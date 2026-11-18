use ragu_core::{
    maybe::Maybe,
    pasta::{Ep, EpAffine, Fp, Fq},
};
use ragu_testing::patcher::{Event, Recorder, constraints_hold, repair};
use udon::curve::Affine;

use super::*;
use crate::{Simulator, decompose};

fn allocate<'dr, D: Driver<'dr>, const N: usize>(
    dr: &mut D,
    bits: [bool; N],
) -> Result<FixedVec<Boolean<'dr, D>, ConstLen<N>>> {
    FixedVec::try_from_fn(|i| Boolean::alloc(dr, &mut (), D::just(|| bits[i])))
}

#[test]
fn multiply_decomposed_and_short_scalars() -> Result<()> {
    let base = EpAffine::generator();
    let table = FixedBase::<_, 254>::new(base, Ep::identity())?;
    let short = FixedBase::<_, 4>::new(base, Ep::identity())?;
    // Set both top bits so the two-bit selector's product contributes.
    let scalar = 17;
    let high = Fp::from(3) * Fp::from(2).pow_u64(252);
    let expected = (base * (Fq::from(3) * Fq::from(2).pow_u64(252) + Fq::from(scalar))).to_affine();
    Simulator::simulate(high + Fp::from(scalar), |dr, witness| {
        let element = Element::alloc(dr, &mut (), witness)?;
        let bits = FixedVec::try_from(decompose(dr, &mut (), &element)?)?;
        dr.reset();
        assert_eq!(table.mul(dr, &bits)?.value().take(), expected);
        assert_eq!(dr.num_gates(), 422);

        let bits = allocate(dr, [true, true, false, true])?;
        dr.reset();
        assert_eq!(
            short.mul(dr, &bits)?.value().take(),
            (base * Fq::from(11)).to_affine()
        );
        assert_eq!(dr.num_gates(), 6);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn short_scalars_and_correction() -> Result<()> {
    let base = EpAffine::generator();
    let correction = -(base * Fq::from(5));
    let table = FixedBase::<_, 51>::new(base, correction)?;
    for scalar in [0, 1, (1 << 51) - 1] {
        Simulator::simulate((), |dr, _| {
            let bits = allocate::<_, 51>(dr, array::from_fn(|i| scalar & (1 << i) != 0))?;
            dr.reset();
            let out = table.mul(dr, &bits)?;
            assert_eq!(
                out.value().take(),
                (base * Fq::from(scalar) + correction).to_affine()
            );
            assert_eq!(dr.num_gates(), 83);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn full_width_scalars() -> Result<()> {
    let base = EpAffine::generator();
    let table = FixedBase::<_, 255>::new(base, Ep::identity())?;
    for scalar_bits in [array::from_fn(|i| i % 5 < 2), [true; 255]] {
        Simulator::simulate((), |dr, _| {
            let bits = allocate(dr, scalar_bits)?;
            let expected_scalar = scalar_bits.iter().rev().fold(Fq::ZERO, |acc, &bit| {
                acc.double() + Fq::from(u64::from(bit))
            });
            let expected = (base * expected_scalar).to_affine();
            dr.reset();
            assert_eq!(table.mul(dr, &bits)?.value().take(), expected);
            assert_eq!(dr.num_gates(), 423);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn zero_scalar_can_join_an_addend() -> Result<()> {
    let base = EpAffine::generator();
    let table = FixedBase::<_, 6>::new(base, Ep::identity())?;
    assert!(matches!(
        Simulator::<Fp>::simulate((), |dr, _| {
            let bits = allocate(dr, [false; 6])?;
            table.mul(dr, &bits)?;
            Ok(())
        }),
        Err(Error::InvalidWitness(_))
    ));
    Simulator::simulate((), |dr, _| {
        let bits = allocate(dr, [false; 6])?;
        let addend = (base * Fq::from(9)).to_affine();
        let onto = Point::alloc(dr, Simulator::<Fp>::just(|| addend))?;
        dr.reset();
        assert_eq!(table.mul_and_add(dr, &bits, &onto)?.value().take(), addend);
        assert_eq!(dr.num_gates(), 12);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn rejects_invalid_tables() {
    let base = EpAffine::generator();
    for (base, correction) in [
        (EpAffine::identity(), Ep::identity()),
        (base, base * Fq::from(2)), // Top digit zero selects the identity.
        (base, -(base * Fq::from(26))), // Top digits d and 7 - d have equal x, so x[7] = 0.
    ] {
        assert!(matches!(
            FixedBase::<_, 6>::new(base, correction),
            Err(Error::Initialization(_))
        ));
    }
}

#[test]
fn final_nonzero_check_rejects_a_forged_doubling() -> Result<()> {
    let table = FixedBase::<_, 6>::new(EpAffine::generator(), Ep::identity())?;
    for checked in [false, true] {
        let mut dr = Recorder::<Fp>::new();
        let bits = allocate(&mut dr, [true, false, false, false, false, false])?;
        if checked {
            table.mul(&mut dr, &bits)?;
        } else {
            let (prefix, top) = table.prefix_and_top(&mut dr, &bits)?;
            prefix.add_incomplete(&mut dr, &top, &mut NonzeroBank::new_unchecked())?;
        }
        assert!(constraints_hold(&dr.events, &dr.values));

        // Replace 1 by 12 so prefix and top are both [6]B; pin `add_incomplete`'s
        // slope (third gate from the end) to 0 in the 0/0 division gate.
        let slope = dr
            .events
            .iter()
            .rev()
            .filter_map(|event| match event {
                Event::Gate { a, .. } => Some(*a),
                _ => None,
            })
            .nth(2)
            .unwrap();
        let mut fixed: Vec<_> = bits.iter().map(|bit| *bit.wire()).collect();
        for (i, &wire) in fixed.iter().enumerate() {
            dr.values[wire] = Fp::from(u64::from(12 & (1 << i) != 0));
        }
        dr.values[slope] = Fp::ZERO;
        fixed.push(slope);
        repair(&dr.events, &mut dr.values, &fixed);
        assert_eq!(constraints_hold(&dr.events, &dr.values), !checked);
    }
    Ok(())
}
