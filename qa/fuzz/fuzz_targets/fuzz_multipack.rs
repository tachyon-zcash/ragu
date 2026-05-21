//! Multipack bit-packing fuzz target.
//!
//! `Boolean::multipack(bits)` packs a slice of `Boolean`s into a `Vec<Element>`,
//! one element per `F::CAPACITY` bits (LSB-first within each chunk). This
//! target generates random boolean vectors, computes the expected packed
//! value via plain Rust arithmetic, runs `multipack` through `Simulator`,
//! and asserts the gadget produces the same per-chunk values.
//!
//! # Identity
//!
//! For bits `b_0, b_1, ..., b_{n-1}` packed into chunks of size
//! `CAPACITY` (LSB-first within each chunk):
//!
//!     element_j = sum_{i=0}^{min(CAPACITY, n - j*CAPACITY) - 1}
//!                 b_{j*CAPACITY + i} * 2^i
//!
//! Mismatch means the gadget's witness assignment diverges from its
//! claimed semantics.

#![no_main]

use arbitrary::Arbitrary;
use ff::{Field, PrimeField};
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_core::maybe::Maybe;
use ragu_primitives::{Boolean, Simulator, allocator::Standard, multipack};

#[derive(Arbitrary, Debug)]
struct Input {
    /// Up to 512 bits to pack (enough for at least two chunks at Pasta's
    /// capacity of 254 bits each).
    bits: Vec<bool>,
}

/// Compute the expected packed Fp values for a slice of bits, LSB-first
/// within each chunk of `capacity` bits.
fn expected_chunks(bits: &[bool], capacity: usize) -> Vec<Fp> {
    bits.chunks(capacity)
        .map(|chunk| {
            let mut value = Fp::ZERO;
            let mut gain = Fp::ONE;
            for &bit in chunk {
                if bit {
                    value += gain;
                }
                gain = gain.double();
            }
            value
        })
        .collect()
}

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    // Bound bit-vector length so iterations stay fast and we don't blow
    // through libFuzzer's `-max_len` budget.
    if input.bits.len() > 512 {
        return;
    }

    let capacity = Fp::CAPACITY as usize;
    let expected = expected_chunks(&input.bits, capacity);

    let bits_owned: Vec<bool> = input.bits.clone();

    let _ = Simulator::<Fp>::simulate(bits_owned, |dr, witness| {
        let allocator = &mut Standard::new();

        // Allocate each input bit as a Boolean.
        let bool_elems: Vec<Boolean<'_, _>> = (0..input.bits.len())
            .map(|i| Boolean::alloc(dr, allocator, witness.as_ref().map(|v| v[i])))
            .collect::<Result<_, _>>()?;

        // Pack them via the gadget under test.
        let packed = multipack(dr, &bool_elems)?;

        // Compare the gadget's witness values to our hand-computed expectation.
        assert_eq!(
            packed.len(),
            expected.len(),
            "multipack returned {} chunks but expected {} (bits.len()={}, capacity={})",
            packed.len(),
            expected.len(),
            input.bits.len(),
            capacity,
        );
        for (i, (got_elem, want_val)) in packed.iter().zip(&expected).enumerate() {
            assert_eq!(
                *got_elem.value().take(),
                *want_val,
                "multipack chunk {} mismatch: bits.len()={}",
                i,
                input.bits.len(),
            );
        }

        Ok(())
    });
});
