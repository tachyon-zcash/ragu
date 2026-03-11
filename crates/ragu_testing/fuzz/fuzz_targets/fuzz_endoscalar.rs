//! Fuzz endoscalar extract, lift, group_scale, and point operations.
//!
//! Invariants:
//! - `extract_endoscalar` never panics for any valid field element.
//! - `lift_endoscalar(extract_endoscalar(r))` is deterministic.
//! - In-circuit lift agrees with native `lift_endoscalar`.
//! - `group_scale(p)` agrees with `p * lift_endoscalar::<Fq>(endo)`.
//! - Point endo/negate/conditional ops agree with native curve arithmetic.
//! - Edge scalars (0, 1, -1, roots of unity) don't cause panics.

#![no_main]

use arbitrary::Arbitrary;
use ff::Field;
use ff::PrimeField;
use ff::WithSmallOrderMulGroup;
use group::{Curve, Group};
use group::prime::PrimeCurveAffine;
use pasta_curves::arithmetic::CurveAffine;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_core::maybe::Maybe;
use ragu_pasta::{EpAffine, Fq};
use ragu_primitives::{
    Boolean, Element, Endoscalar, Point, Simulator, extract_endoscalar, lift_endoscalar,
};

/// Edge-case field elements that trigger boundary conditions.
fn special_scalar(idx: u8) -> Fp {
    match idx % 10 {
        0 => Fp::ZERO,
        1 => Fp::ONE,
        2 => -Fp::ONE,                     // p - 1
        3 => Fp::TWO_INV,                  // (p + 1) / 2
        4 => Fp::ROOT_OF_UNITY,            // 2-adic root of unity
        5 => Fp::MULTIPLICATIVE_GENERATOR,
        6 => Fp::ZETA,                     // cube root of unity (endomorphism scalar)
        7 => -Fp::ZETA,
        8 => Fp::ROOT_OF_UNITY.square(),
        _ => Fp::from(u64::MAX),
    }
}

/// Get a non-trivial curve point by multiplying generator by a scalar.
fn point_from_seed(seed: u64) -> EpAffine {
    if seed == 0 {
        // Use generator directly (seed=0 would give identity)
        EpAffine::generator()
    } else {
        (EpAffine::generator() * Fq::from(seed)).to_affine()
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum PointOp {
    Endo,
    Negate,
    Double,
    ConditionalEndo(bool),
    ConditionalNegate(bool),
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// Raw scalar seed for extract_endoscalar.
    scalar_seed: u64,
    /// If set, use a special edge-case scalar instead.
    use_special: Option<u8>,
    /// Seed for the curve point.
    point_seed: u64,
    /// Second point seed for add_incomplete.
    point_seed2: u64,
    /// Point operations to apply after group_scale.
    point_ops: Vec<PointOp>,
}

fuzz_target!(|input: Input| {
    if input.point_ops.len() > 16 {
        return;
    }

    // Choose the scalar: either from seed or special value
    let r = match input.use_special {
        Some(idx) => special_scalar(idx),
        None => Fp::from(input.scalar_seed),
    };

    // Native extract/lift
    let extracted = extract_endoscalar::<Fp>(r);
    let lifted_native: Fp = lift_endoscalar(extracted);

    // Determinism
    let extracted2 = extract_endoscalar::<Fp>(r);
    assert_eq!(extracted, extracted2, "extract is not deterministic");
    assert_eq!(
        lifted_native,
        lift_endoscalar::<Fp>(extracted2),
        "lift is not deterministic"
    );

    // Native point operations for oracle
    let p = point_from_seed(input.point_seed);
    let expected_scalar: Fq = lift_endoscalar(extracted);
    let expected_scaled: EpAffine = (p * expected_scalar).to_affine();

    // Compute expected results for point ops natively
    let p2 = point_from_seed(input.point_seed2);

    // Collect booleans needed for conditional ops
    let cond_bools: Vec<bool> = input
        .point_ops
        .iter()
        .filter_map(|op| match op {
            PointOp::ConditionalEndo(c) | PointOp::ConditionalNegate(c) => Some(*c),
            _ => None,
        })
        .collect();

    let result = Simulator::<Fp>::simulate((r, extracted, p, p2, cond_bools.clone()), |dr, witness| {
        let (r_val, _endo_val, p_val, p2_val, bool_vals) = witness.cast();
        let r_elem = Element::alloc(dr, r_val)?;
        let endo = Endoscalar::extract(dr, r_elem)?;

        // Circuit lift must match native lift
        let lifted_circuit = endo.lift(dr)?;
        assert_eq!(
            *lifted_circuit.value().take(),
            lifted_native,
            "circuit lift != native lift"
        );

        // Circuit group_scale must match native
        let point = Point::alloc(dr, p_val)?;
        let scaled = endo.group_scale(dr, &point)?;
        assert_eq!(
            scaled.value().take(),
            expected_scaled,
            "circuit group_scale != native scaling"
        );

        // --- Point operation tests ---
        let mut current = Point::<'_, _, EpAffine>::constant(dr, p)?;
        let mut current_native = p;
        let mut bool_idx = 0;

        for op in &input.point_ops {
            match op {
                PointOp::Endo => {
                    current = current.endo(dr);
                    let coords = current_native.coordinates().unwrap();
                    let new_x = *coords.x() * Fp::ZETA;
                    current_native = EpAffine::from_xy(new_x, *coords.y()).unwrap();
                }
                PointOp::Negate => {
                    current = current.negate(dr);
                    current_native = (-current_native.to_curve()).to_affine();
                }
                PointOp::Double => {
                    match current.double(dr) {
                        Ok(doubled) => {
                            current = doubled;
                            current_native = current_native.to_curve().double().to_affine();
                        }
                        Err(_) => break,
                    }
                }
                PointOp::ConditionalEndo(cond) => {
                    let b = Boolean::alloc(dr, bool_vals.as_ref().map(|v| v[bool_idx]))?;
                    bool_idx += 1;
                    match current.conditional_endo(dr, &b) {
                        Ok(result) => {
                            current = result;
                            if *cond {
                                let coords = current_native.coordinates().unwrap();
                                let new_x = *coords.x() * Fp::ZETA;
                                current_native =
                                    EpAffine::from_xy(new_x, *coords.y()).unwrap();
                            }
                        }
                        Err(_) => break,
                    }
                }
                PointOp::ConditionalNegate(cond) => {
                    let b = Boolean::alloc(dr, bool_vals.as_ref().map(|v| v[bool_idx]))?;
                    bool_idx += 1;
                    match current.conditional_negate(dr, &b) {
                        Ok(result) => {
                            current = result;
                            if *cond {
                                current_native =
                                    (-current_native.to_curve()).to_affine();
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        // After all ops, circuit point must match native
        let circuit_point = current.value().take();
        assert_eq!(
            circuit_point, current_native,
            "point ops: circuit != native after {:?}",
            input.point_ops
        );

        // --- add_incomplete test (distinct points) ---
        let q = Point::<'_, _, EpAffine>::alloc(dr, p2_val)?;
        let p_coords = p.coordinates().unwrap();
        let p2_coords = p2.coordinates().unwrap();
        if p_coords.x() != p2_coords.x() {
            let p_again = Point::<'_, _, EpAffine>::constant(dr, p)?;
            let sum = p_again.add_incomplete(dr, &q, None)?;
            let expected_sum: EpAffine = (p.to_curve() + p2.to_curve()).to_affine();
            assert_eq!(
                sum.value().take(),
                expected_sum,
                "add_incomplete != native addition"
            );
        }

        Ok(())
    });

    assert!(
        result.is_ok(),
        "endoscalar circuit failed: {:?}",
        result.err()
    );
});
