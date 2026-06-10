//! Fuzz Poseidon sponge absorb/squeeze mode transitions.
//!
//! Invariants:
//! - No panics on any absorb/squeeze/save/resume interleaving.
//! - Determinism: identical input sequences produce identical squeeze output.
//! - Save/resume equivalence: absorb → save → resume → squeeze == absorb → squeeze.

#![no_main]

use arbitrary::Arbitrary;
use ff::{Field, PrimeField};
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::Cycle;
use ragu_core::maybe::Maybe;
use ragu_pasta::Pasta;
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Element, Simulator, allocator::Standard};

fn special_value(idx: u8) -> Fp {
    match idx % 16 {
        0 => Fp::ZERO,
        1 => Fp::ONE,
        2 => -Fp::ONE,
        3 => -Fp::from(2),
        4 => Fp::TWO_INV,
        5 => Fp::from(2),
        6 => Fp::from(3),
        7 => Fp::from(7),
        8 => Fp::ROOT_OF_UNITY,
        9 => Fp::ROOT_OF_UNITY.square(),
        10 => Fp::ROOT_OF_UNITY.pow_vartime([4u64]),
        11 => Fp::MULTIPLICATIVE_GENERATOR,
        12 => Fp::MULTIPLICATIVE_GENERATOR.square(),
        13 => Fp::from(1u64 << 32),
        14 => Fp::from(1u64 << 48),
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
    let mut output = Fp::ZERO;
    let mut got_output = false;
    // Pasta::baked() returns a &'static, but recomputing the address each
    // call is wasteful; hoist outside the closure so we touch the static
    // exactly once per run_sponge.
    let params = Pasta::baked();

    let result = Simulator::<Fp>::simulate(values.to_vec(), |dr, witness| {
        let allocator = &mut Standard::new();
        let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
            dr,
            Pasta::circuit_poseidon(params),
        );

        let elems: Vec<Element<'_, _>> = (0..values.len())
            .map(|i| Element::alloc(dr, allocator, witness.as_ref().map(|v| v[i])))
            .collect::<Result<_, _>>()?;

        let mut absorb_idx = 0;
        for op in ops {
            match op {
                Op::Absorb(_) | Op::AbsorbLarge(_) | Op::AbsorbSpecial(_) => {
                    sponge.absorb(dr, &elems[absorb_idx])?;
                    absorb_idx += 1;
                }
                Op::Squeeze => {
                    // Skip squeeze ops scheduled before any absorb. The Sponge
                    // API rejects squeeze-from-empty as a precondition error,
                    // and Arbitrary input ordering can't enforce absorb-first.
                    if absorb_idx == 0 {
                        continue;
                    }
                    let squeezed = sponge.squeeze(dr)?;
                    if !got_output {
                        output = *squeezed.value().take();
                        got_output = true;
                    }
                }
            }
        }

        if !got_output {
            let squeezed = sponge.squeeze(dr)?;
            output = *squeezed.value().take();
        }

        Ok(())
    });

    assert!(result.is_ok(), "sponge failed: {:?}", result.err());
    output
}

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
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
        let mut direct_output = Fp::ZERO;
        let mut resume_output = Fp::ZERO;
        let params = Pasta::baked();

        let result = Simulator::<Fp>::simulate(values.clone(), |dr, witness| {
            let allocator = &mut Standard::new();
            let elems: Vec<Element<'_, _>> = (0..values.len())
                .map(|i| Element::alloc(dr, allocator, witness.as_ref().map(|v| v[i])))
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
            direct_output = *squeezed.value().take();

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
            resume_output = *squeezed.value().take();

            Ok(())
        });

        assert!(result.is_ok(), "save/resume failed: {:?}", result.err());
        assert_eq!(
            direct_output,
            resume_output,
            "save/resume produced different output than direct squeeze"
        );
    }
});
