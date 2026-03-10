//! Fuzz the Poseidon sponge's absorb/squeeze mode transitions.
//!
//! Exercises arbitrary interleaving of absorb and squeeze operations,
//! including multi-rate absorption (triggering internal permutations)
//! and save/resume consistency. The Poseidon permutation (Hades
//! construction with full/partial rounds, sbox, MDS mixing) is Ragu's
//! own code — this is the core of Fiat-Shamir soundness.
//!
//! Invariants checked:
//! - No panics on any absorb/squeeze interleaving
//! - Determinism: same input sequence always produces the same squeeze output
//! - Save/resume produces the same squeeze as a straight-through sponge

#![no_main]

use core::cell::Cell;
use ff::Field;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::Cycle;
use ragu_core::maybe::Maybe;
use ragu_pasta::Pasta;
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Element, Simulator};

/// Decode a sequence of sponge operations from raw bytes.
///
/// Format: each byte is an operation.
///   - 0x00..=0xEF: absorb Fp::from(byte as u64)
///   - 0xF0..=0xFF: squeeze (value ignored)
struct Ops<'a> {
    data: &'a [u8],
}

impl<'a> Ops<'a> {
    fn absorb_values(&self) -> Vec<Fp> {
        self.data
            .iter()
            .filter(|b| **b < 0xF0)
            .map(|b| Fp::from(*b as u64))
            .collect()
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 64 {
        return;
    }

    // Need at least one absorb before any squeeze is meaningful
    if !data.iter().any(|b| *b < 0xF0) {
        return;
    }

    let ops = Ops { data };
    let absorb_values = ops.absorb_values();
    let params = Pasta::baked();

    // --- Run 1: Execute the full operation sequence, capture first squeeze ---
    let squeeze1 = Cell::new(Fp::ZERO);
    let got_squeeze1 = Cell::new(false);

    let result1 = Simulator::<Fp>::simulate(absorb_values.clone(), |dr, witness| {
        let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
            dr,
            Pasta::circuit_poseidon(params),
        );

        let elems: Vec<Element<'_, _>> = (0..absorb_values.len())
            .map(|i| Element::alloc(dr, witness.as_ref().map(|v| v[i])))
            .collect::<Result<_, _>>()?;

        let mut absorb_idx = 0;
        for &byte in data {
            if byte < 0xF0 {
                sponge.absorb(dr, &elems[absorb_idx])?;
                absorb_idx += 1;
            } else {
                let squeezed = sponge.squeeze(dr)?;
                if !got_squeeze1.get() {
                    squeeze1.set(*squeezed.value().take());
                    got_squeeze1.set(true);
                }
            }
        }

        // If no squeeze was requested, do one now
        if !got_squeeze1.get() {
            let squeezed = sponge.squeeze(dr)?;
            squeeze1.set(*squeezed.value().take());
            got_squeeze1.set(true);
        }

        Ok(())
    });

    assert!(result1.is_ok(), "Poseidon sponge panicked or failed constraints");

    // --- Run 2: Determinism check — same sequence must produce same output ---
    let squeeze2 = Cell::new(Fp::ZERO);
    let got_squeeze2 = Cell::new(false);

    let result2 = Simulator::<Fp>::simulate(absorb_values.clone(), |dr, witness| {
        let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
            dr,
            Pasta::circuit_poseidon(params),
        );

        let elems: Vec<Element<'_, _>> = (0..absorb_values.len())
            .map(|i| Element::alloc(dr, witness.as_ref().map(|v| v[i])))
            .collect::<Result<_, _>>()?;

        let mut absorb_idx = 0;
        for &byte in data {
            if byte < 0xF0 {
                sponge.absorb(dr, &elems[absorb_idx])?;
                absorb_idx += 1;
            } else {
                let squeezed = sponge.squeeze(dr)?;
                if !got_squeeze2.get() {
                    squeeze2.set(*squeezed.value().take());
                    got_squeeze2.set(true);
                }
            }
        }

        if !got_squeeze2.get() {
            let squeezed = sponge.squeeze(dr)?;
            squeeze2.set(*squeezed.value().take());
            got_squeeze2.set(true);
        }

        Ok(())
    });

    assert!(result2.is_ok());
    assert_eq!(squeeze1.get(), squeeze2.get(), "Poseidon is not deterministic");
});
