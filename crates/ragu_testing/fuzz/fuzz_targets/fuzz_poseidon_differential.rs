//! Differential fuzzing of Poseidon sponge against a native reference.
//!
//! Implements a pure-field-arithmetic sponge (no Simulator/Element/Driver) and
//! compares its output against the circuit sponge. Catches bugs in absorb
//! buffering, rate boundary handling, and squeeze ordering (`get_rate().rev()`).
//!
//! Invariant: `circuit_sponge(ops) == native_sponge(ops)` for all operation
//! sequences.

#![no_main]

use arbitrary::Arbitrary;
use core::cell::Cell;
use ff::{Field, PrimeField};
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::{Cycle, PoseidonPermutation};
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

struct NativeSponge<'a, P> {
    state: Vec<Fp>,
    buf: Vec<Fp>,
    squeezable: Vec<Fp>,
    absorbing: bool,
    params: &'a P,
}

impl<'a, P: PoseidonPermutation<Fp>> NativeSponge<'a, P> {
    fn new(params: &'a P) -> Self {
        NativeSponge {
            state: vec![Fp::ZERO; P::T],
            buf: Vec::new(),
            squeezable: Vec::new(),
            absorbing: true,
            params,
        }
    }

    fn permute(&mut self) {
        let rcs = self.params.round_constants();
        let t = P::T;

        for (round_idx, rc) in rcs.enumerate() {
            // Add round constants
            for (s, c) in self.state.iter_mut().zip(rc.iter()) {
                *s += c;
            }

            // Sbox
            let sbox_count = if round_idx < P::FULL_ROUNDS / 2
                || round_idx >= P::FULL_ROUNDS / 2 + P::PARTIAL_ROUNDS
            {
                t
            } else {
                1
            };
            for s in self.state[..sbox_count].iter_mut() {
                let s2 = *s * *s;
                let s4 = s2 * s2;
                *s = s4 * *s; // s^5
            }

            // MDS
            let mut new_state = vec![Fp::ZERO; t];
            for (row_idx, row) in self.params.mds_matrix().enumerate() {
                for (col_idx, coeff) in row.iter().enumerate() {
                    new_state[row_idx] += *coeff * self.state[col_idx];
                }
            }
            self.state = new_state;
        }
    }

    fn absorb(&mut self, value: Fp) {
        if !self.absorbing {
            // Switch to absorb mode
            self.absorbing = true;
            self.buf.clear();
            self.squeezable.clear();
        }

        if self.buf.len() == P::RATE {
            // Buffer full — add to state and permute
            for (s, v) in self.state.iter_mut().zip(self.buf.iter()) {
                *s += v;
            }
            self.buf.clear();
            self.permute();
        }

        self.buf.push(value);
    }

    fn squeeze(&mut self) -> Fp {
        if self.absorbing {
            if self.buf.is_empty() {
                // Nothing absorbed — switch to squeeze, get rate from current state
                self.absorbing = false;
                // Mirror get_rate: take first RATE elements, reverse
                self.squeezable = self.state[..P::RATE].iter().copied().rev().collect();
            } else {
                // Pending absorbs — add to state, permute, then squeeze
                for (s, v) in self.state.iter_mut().zip(self.buf.iter()) {
                    *s += v;
                }
                self.buf.clear();
                self.permute();
                self.absorbing = false;
                self.squeezable = self.state[..P::RATE].iter().copied().rev().collect();
            }
        }

        if self.squeezable.is_empty() {
            // Need another permutation
            self.permute();
            self.squeezable = self.state[..P::RATE].iter().copied().rev().collect();
        }

        self.squeezable.pop().expect("squeezable not empty after permute")
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
}

fn op_value(op: &Op) -> Option<Fp> {
    match op {
        Op::Absorb(v) => Some(Fp::from(*v)),
        Op::AbsorbLarge(limbs) => Some(
            Fp::from(limbs[0])
                + Fp::from(limbs[1]) * Fp::from(1u64 << 32)
                + Fp::from(limbs[2]) * Fp::from(1u64 << 48)
                + Fp::from(limbs[3]) * Fp::from(1u64 << 56),
        ),
        Op::AbsorbSpecial(idx) => Some(special_value(*idx)),
        Op::Squeeze => None,
    }
}

fuzz_target!(|input: Input| {
    if input.ops.is_empty() || input.ops.len() > 64 {
        return;
    }

    let has_absorb = input.ops.iter().any(|op| !matches!(op, Op::Squeeze));
    if !has_absorb {
        return;
    }

    let params = Pasta::baked();

    // --- Native reference ---
    let mut native = NativeSponge::new(Pasta::circuit_poseidon(params));
    let mut native_squeezes = Vec::new();

    for op in &input.ops {
        match op_value(op) {
            Some(v) => native.absorb(v),
            None => native_squeezes.push(native.squeeze()),
        }
    }
    // Always squeeze at least once
    if native_squeezes.is_empty() {
        native_squeezes.push(native.squeeze());
    }

    // --- Circuit sponge via Simulator ---
    let absorb_values: Vec<Fp> = input.ops.iter().filter_map(op_value).collect();
    let circuit_squeezes: Vec<Cell<Fp>> = (0..native_squeezes.len())
        .map(|_| Cell::new(Fp::ZERO))
        .collect();

    let result = Simulator::<Fp>::simulate(absorb_values.clone(), |dr, witness| {
        let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
            dr,
            Pasta::circuit_poseidon(params),
        );

        let elems: Vec<Element<'_, _>> = (0..absorb_values.len())
            .map(|i| Element::alloc(dr, witness.as_ref().map(|v| v[i])))
            .collect::<Result<_, _>>()?;

        let mut absorb_idx = 0;
        let mut squeeze_idx = 0;
        for op in &input.ops {
            match op {
                Op::Absorb(_) | Op::AbsorbLarge(_) | Op::AbsorbSpecial(_) => {
                    sponge.absorb(dr, &elems[absorb_idx])?;
                    absorb_idx += 1;
                }
                Op::Squeeze => {
                    let squeezed = sponge.squeeze(dr)?;
                    circuit_squeezes[squeeze_idx].set(*squeezed.value().take());
                    squeeze_idx += 1;
                }
            }
        }

        if squeeze_idx == 0 {
            let squeezed = sponge.squeeze(dr)?;
            circuit_squeezes[0].set(*squeezed.value().take());
        }

        Ok(())
    });

    assert!(result.is_ok(), "circuit sponge failed: {:?}", result.err());

    for (i, (native_val, circuit_cell)) in
        native_squeezes.iter().zip(circuit_squeezes.iter()).enumerate()
    {
        assert_eq!(
            *native_val,
            circuit_cell.get(),
            "squeeze {i} mismatch: native vs circuit"
        );
    }
});
