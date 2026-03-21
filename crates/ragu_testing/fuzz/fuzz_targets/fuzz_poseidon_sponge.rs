//! Fuzz Poseidon sponge absorb/squeeze mode transitions.
//!
//! Invariants:
//! - No panics on any absorb/squeeze/save/resume interleaving.
//! - Determinism: identical input sequences produce identical squeeze output.
//! - Save/resume equivalence: absorb → save → resume → squeeze == absorb → squeeze.

#![no_main]

use arbitrary::Arbitrary;
use core::cell::Cell;
use ff::{Field, PrimeField};
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::Cycle;
use ragu_core::maybe::Maybe;
use ragu_pasta::Pasta;
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Element, Simulator};

fn special_value(idx: u8) -> Fp {
    match idx % 8 {
        0 => Fp::ZERO,
        1 => Fp::ONE,
        2 => -Fp::ONE,
        3 => Fp::TWO_INV,
        4 => Fp::ROOT_OF_UNITY,
        5 => Fp::MULTIPLICATIVE_GENERATOR,
        6 => Fp::ROOT_OF_UNITY.square(),
        _ => Fp::from(u64::MAX),
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Op {
    Absorb(u64),
    AbsorbLarge([u64; 4]),
    AbsorbSpecial(u8),
    Squeeze,
}

#[derive(Arbitrary, Debug)]
struct Input {
    ops: Vec<Op>,
    test_save_resume: bool,
}

fn absorb_values(ops: &[Op]) -> Vec<Fp> {
    ops.iter()
        .filter_map(|op| match op {
            Op::Absorb(v) => Some(Fp::from(*v)),
            Op::AbsorbLarge(limbs) => {
                let val = Fp::from(limbs[0])
                    + Fp::from(limbs[1]) * Fp::from(1u64 << 32)
                    + Fp::from(limbs[2]) * Fp::from(1u64 << 48)
                    + Fp::from(limbs[3]) * Fp::from(1u64 << 56);
                Some(val)
            }
            Op::AbsorbSpecial(idx) => Some(special_value(*idx)),
            Op::Squeeze => None,
        })
        .collect()
}

fn run_sponge(ops: &[Op], values: &[Fp]) -> Fp {
    let output = Cell::new(Fp::ZERO);
    let got_output = Cell::new(false);

    let result = Simulator::<Fp>::simulate(values.to_vec(), |dr, witness| {
        let params = Pasta::baked();
        let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
            dr,
            Pasta::circuit_poseidon(params),
        );

        let elems: Vec<Element<'_, _>> = (0..values.len())
            .map(|i| Element::alloc(dr, witness.as_ref().map(|v| v[i])))
            .collect::<Result<_, _>>()?;

        let mut absorb_idx = 0;
        for op in ops {
            match op {
                Op::Absorb(_) | Op::AbsorbLarge(_) | Op::AbsorbSpecial(_) => {
                    sponge.absorb(dr, &elems[absorb_idx])?;
                    absorb_idx += 1;
                }
                Op::Squeeze => {
                    let squeezed = sponge.squeeze(dr)?;
                    if !got_output.get() {
                        output.set(*squeezed.value().take());
                        got_output.set(true);
                    }
                }
            }
        }

        if !got_output.get() {
            let squeezed = sponge.squeeze(dr)?;
            output.set(*squeezed.value().take());
        }

        Ok(())
    });

    assert!(result.is_ok(), "sponge failed: {:?}", result.err());
    output.get()
}

fuzz_target!(|input: Input| {
    if input.ops.is_empty() || input.ops.len() > 64 {
        return;
    }

    let has_absorb = input.ops.iter().any(|op| !matches!(op, Op::Squeeze));
    if !has_absorb {
        return;
    }

    let values = absorb_values(&input.ops);

    // Run twice — determinism check
    let out1 = run_sponge(&input.ops, &values);
    let out2 = run_sponge(&input.ops, &values);
    assert_eq!(out1, out2, "Poseidon is not deterministic");

    // Save/resume equivalence: absorb all values, save, resume, squeeze
    // must equal absorb all values then squeeze directly.
    if input.test_save_resume && values.len() >= 1 {
        let direct_output = Cell::new(Fp::ZERO);
        let resume_output = Cell::new(Fp::ZERO);

        let result = Simulator::<Fp>::simulate(values.clone(), |dr, witness| {
            let params = Pasta::baked();
            let elems: Vec<Element<'_, _>> = (0..values.len())
                .map(|i| Element::alloc(dr, witness.as_ref().map(|v| v[i])))
                .collect::<Result<_, _>>()?;

            // Direct path: absorb all → squeeze
            let mut sponge1 = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            for elem in &elems {
                sponge1.absorb(dr, elem)?;
            }
            let squeezed = sponge1.squeeze(dr)?;
            direct_output.set(*squeezed.value().take());

            // Save/resume path: absorb all → save → resume → squeeze
            let mut sponge2 = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
                dr,
                Pasta::circuit_poseidon(params),
            );
            for elem in &elems {
                sponge2.absorb(dr, elem)?;
            }
            let state = sponge2.save_state(dr).expect("save should succeed after absorb");
            let mut resumed = Sponge::resume(state, Pasta::circuit_poseidon(params));
            let squeezed = resumed.squeeze(dr)?;
            resume_output.set(*squeezed.value().take());

            Ok(())
        });

        assert!(result.is_ok(), "save/resume failed: {:?}", result.err());
        assert_eq!(
            direct_output.get(),
            resume_output.get(),
            "save/resume produced different output than direct squeeze"
        );
    }
});
