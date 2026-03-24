//! Transcript abstraction for Fiat-Shamir transforms.
//!
//! Wraps a Poseidon [`Sponge`] to provide domain-separated challenge generation
//! for the PCD protocol. Domain separation is mandatory at construction.
//!
//! ### Usage
//!
//! ```rust,ignore
//! // Initialize transcript with mandatory domain separation
//! let mut transcript = Transcript::new(dr, params, b"ragu-pcd-v1")?;
//!
//! // Absorb a single field element via Buffer trait
//! value.write(dr, &mut transcript)?;
//!
//! // Squeeze a single field element challenge
//! let w = transcript.challenge(dr)?;
//!
//! // Save/resume for multi-circuit protocols
//! let state = transcript.save_state(dr)?;
//! let mut resumed = Transcript::resume_from_state(state, params);
//! let challenge = resumed.challenge(dr)?; // must squeeze first
//! let mut transcript = resumed.into_transcript(); // then can absorb again
//! ```
//!
//! ### Safety
//!
//! The underlying [`Sponge`] uses additive absorption: absorbing a zero field
//! element is identical to not absorbing it, so `absorb([v])` and
//! `absorb([v, 0])` produce the same sponge state. General-purpose transcript
//! libraries (e.g. Merlin) defend against this by length-prefixing every
//! absorbed message. This transcript does not for efficiency reasons.
//!
//! In our PCD protocol, the message sequence between prover and verifier is
//! fixed by the circuit code, so a prover cannot inject extra zero elements
//! into the transcript without being rejected by the verifier.
//! Transcripts of protocols with different interaction sequences are
//! domain-separated by protocol tags during construction [`Transcript::new`].

use ff::PrimeField;
use ragu_arithmetic::PoseidonPermutation;
use ragu_core::{Result, drivers::Driver};

use ragu_primitives::{
    Element,
    io::Buffer,
    poseidon::{SaveError, Sponge, SpongeState},
};

/// Transcript wrapper around Poseidon [`Sponge`] for Fiat-Shamir transforms.
pub struct Transcript<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> {
    sponge: Sponge<'dr, D, P>,
    params: &'dr P,
}

impl<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> Clone for Transcript<'dr, D, P> {
    fn clone(&self) -> Self {
        Transcript {
            sponge: self.sponge.clone(),
            params: self.params,
        }
    }
}

/// Type alias for saved transcript state.
///
/// This is a gadget that can be passed between circuits, with the state
/// constraint-checked during multi-circuit protocols.
pub type TranscriptState<'dr, D, P> = SpongeState<'dr, D, P>;

impl<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> Transcript<'dr, D, P> {
    /// Creates a new transcript with mandatory domain separation.
    ///
    /// The `tag` is absorbed as field elements (length-prefixed, 16 bytes per
    /// element via u128 conversion) to bind the transcript to a protocol context.
    ///
    /// # Field size constraint
    ///
    /// Assumes the field modulus exceeds 128 bits so that each 16-byte chunk
    /// maps to a unique field element. See [#51] and [#1] for the broader
    /// effort to decouple Ragu from Pasta-specific field assumptions.
    ///
    /// [#51]: https://github.com/tachyon-zcash/ragu/issues/51
    /// [#1]: https://github.com/tachyon-zcash/ragu/issues/1
    pub fn new(dr: &mut D, params: &'dr P, tag: &[u8]) -> Result<Self>
    where
        D::F: PrimeField,
    {
        let mut sponge = Sponge::new(dr, params);

        // prefix with the tag length
        let len_elem = Element::constant(dr, D::F::from(tag.len() as u64));
        sponge.absorb(dr, &len_elem)?;

        // Then absorb the tag content in 16-byte chunks as u128
        for chunk in tag.chunks(16) {
            let bytes: [u8; 16] = core::array::from_fn(|i| chunk.get(i).copied().unwrap_or(0));
            let elem = Element::constant(dr, D::F::from_u128(u128::from_le_bytes(bytes)));
            sponge.absorb(dr, &elem)?;
        }

        Ok(Transcript { sponge, params })
    }

    /// Squeezes a single field element challenge from the transcript.
    pub fn challenge(&mut self, dr: &mut D) -> Result<Element<'dr, D>> {
        self.sponge.squeeze(dr)
    }

    /// Saves the transcript state (analogous to flush).
    ///
    /// This consumes the transcript and applies a permutation to transition
    /// into squeeze mode. The returned state can be passed to another circuit
    /// for resumption via [`Self::resume_from_state`].
    pub fn save_state(
        self,
        dr: &mut D,
    ) -> core::result::Result<TranscriptState<'dr, D, P>, SaveError> {
        self.sponge.save_state(dr)
    }

    /// Resumes a transcript from saved state in squeeze-only mode.
    ///
    /// Returns a [`ResumedTranscript`] that only permits squeezing challenges.
    /// Call [`ResumedTranscript::into_transcript`] to transition back to a full
    /// transcript that supports absorbing.
    pub fn resume_from_state(
        state: TranscriptState<'dr, D, P>,
        params: &'dr P,
    ) -> ResumedTranscript<'dr, D, P> {
        let sponge = Sponge::resume(state, params);
        ResumedTranscript {
            sponge,
            params,
            squeezed: false,
        }
    }
}

/// A resumed transcript restricted to squeeze-only mode.
///
/// Created by [`Transcript::resume_from_state`]. The saved state has buffered
/// rate values ready to be squeezed; exposing only [`challenge`][Self::challenge]
/// prevents the caller from accidentally absorbing (which would silently discard
/// those values). Call [`into_transcript`][Self::into_transcript] to transition
/// back to a full [`Transcript`] that supports absorbing.
pub struct ResumedTranscript<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> {
    sponge: Sponge<'dr, D, P>,
    params: &'dr P,
    squeezed: bool,
}

impl<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> ResumedTranscript<'dr, D, P> {
    /// Squeezes a single field element challenge.
    pub fn challenge(&mut self, dr: &mut D) -> Result<Element<'dr, D>> {
        self.squeezed = true;
        self.sponge.squeeze(dr)
    }

    /// Transitions back to a full transcript that supports absorbing.
    ///
    /// # Panics
    ///
    /// Panics if no challenges have been squeezed since resuming. Calling
    /// `into_transcript` without squeezing would silently discard the buffered
    /// rate values from the saved state.
    pub fn into_transcript(self) -> Transcript<'dr, D, P> {
        assert!(
            self.squeezed,
            "must squeeze at least once before transitioning back to absorb mode"
        );
        Transcript {
            sponge: self.sponge,
            params: self.params,
        }
    }
}

impl<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> Buffer<'dr, D> for Transcript<'dr, D, P> {
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        self.sponge.absorb(dr, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use ff::Field;
    use proptest::prelude::*;
    use ragu_arithmetic::Cycle;
    use ragu_core::maybe::Maybe;
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::{GadgetExt, Simulator};

    type Sim = Simulator<Fp>;

    fn arb_field() -> impl Strategy<Value = Fp> {
        any::<u64>().prop_map(Fp::from)
    }

    fn arb_tag() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..=32)
    }

    fn arb_values(n: impl Into<prop::collection::SizeRange>) -> impl Strategy<Value = Vec<Fp>> {
        prop::collection::vec(arb_field(), n)
    }

    #[derive(Debug, Clone)]
    enum Op {
        Absorb(Fp),
        Squeeze,
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![arb_field().prop_map(Op::Absorb), Just(Op::Squeeze),]
    }

    fn apply_ops<P: PoseidonPermutation<Fp>>(
        dr: &mut Sim,
        t: &mut Transcript<'_, Sim, P>,
        ops: &[Op],
    ) -> Vec<Fp> {
        ops.iter()
            .filter_map(|op| match op {
                Op::Absorb(v) => {
                    let e = Element::constant(dr, *v);
                    e.write(dr, t).unwrap();
                    None
                }
                Op::Squeeze => Some(*t.challenge(dr).unwrap().value().take()),
            })
            .collect()
    }

    proptest! {
        #[test]
        fn proptest_domain_separation(v in arb_field(), t1 in arb_tag(), t2 in arb_tag()) {
            prop_assume!(t1 != t2);
            let params = Pasta::baked();
            let mut dr = Sim::new();
            let poseidon = Pasta::circuit_poseidon(params);

            let mut tr1 = Transcript::new(&mut dr, poseidon, &t1).unwrap();
            let mut tr2 = Transcript::new(&mut dr, poseidon, &t2).unwrap();

            let elem = Element::constant(&mut dr, v);
            elem.write(&mut dr, &mut tr1).unwrap();
            elem.write(&mut dr, &mut tr2).unwrap();

            let c1 = *tr1.challenge(&mut dr).unwrap().value().take();
            let c2 = *tr2.challenge(&mut dr).unwrap().value().take();
            prop_assert_ne!(c1, c2);
        }

        #[test]
        fn proptest_determinism(vs in arb_values(1..=8)) {
            let params = Pasta::baked();
            let poseidon = Pasta::circuit_poseidon(params);

            let squeeze = |vs: &[Fp]| {
                let mut dr = Sim::new();
                let mut t = Transcript::new(&mut dr, poseidon, b"determinism").unwrap();
                for &v in vs {
                    let e = Element::constant(&mut dr, v);
                    e.write(&mut dr, &mut t).unwrap();
                }
                *t.challenge(&mut dr).unwrap().value().take()
            };

            prop_assert_eq!(squeeze(&vs), squeeze(&vs));
        }

        #[test]
        fn proptest_squeezes_distinct(v in arb_field()) {
            let params = Pasta::baked();
            let mut dr = Sim::new();

            let mut t = Transcript::new(&mut dr, Pasta::circuit_poseidon(params), b"distinct").unwrap();
            let e = Element::constant(&mut dr, v);
            e.write(&mut dr, &mut t).unwrap();

            let c0 = *t.challenge(&mut dr).unwrap().value().take();
            let c1 = *t.challenge(&mut dr).unwrap().value().take();
            let c2 = *t.challenge(&mut dr).unwrap().value().take();
            let c3 = *t.challenge(&mut dr).unwrap().value().take();

            for c in [c0, c1, c2, c3] {
                prop_assert_ne!(c, Fp::ZERO);
            }
            prop_assert_ne!(c0, c1);
            prop_assert_ne!(c1, c2);
            prop_assert_ne!(c2, c3);
        }

        /// Tests that save/resume is transparent: the full squeeze-output
        /// sequence is identical whether or not a save/resume occurs at the
        /// cutoff. The cutoff falls after an arbitrary mix of absorbs and
        /// squeezes.
        ///
        /// Two invariants are enforced by construction:
        /// - `before_ops` ends with a guaranteed `Absorb` so `save_state` is
        ///   called while the sponge is in absorb mode.
        /// - `after_ops` starts with a guaranteed `Squeeze` so
        ///   `into_transcript` can be called legally after resuming.
        #[test]
        fn proptest_save_resume_continuity(
            before_prefix in prop::collection::vec(arb_op(), 0..=5),
            before_final  in arb_field(),
            after_rest    in prop::collection::vec(arb_op(), 0..=4),
        ) {
            let params = Pasta::baked();
            let poseidon = Pasta::circuit_poseidon(params);

            let before_ops: Vec<Op> = before_prefix
                .into_iter()
                .chain(core::iter::once(Op::Absorb(before_final)))
                .collect();
            let after_ops: Vec<Op> = core::iter::once(Op::Squeeze)
                .chain(after_rest)
                .collect();

            // Straight-through reference.
            let expected: Vec<Fp> = {
                let mut dr = Sim::new();
                let mut t = Transcript::new(&mut dr, poseidon, b"continuity").unwrap();
                let mut out = apply_ops(&mut dr, &mut t, &before_ops);
                out.extend(apply_ops(&mut dr, &mut t, &after_ops));
                out
            };

            // Save/resume path: identical ops, with a state save at the cutoff.
            let actual: Vec<Fp> = {
                let mut dr = Sim::new();
                let mut t = Transcript::new(&mut dr, poseidon, b"continuity").unwrap();
                let mut out = apply_ops(&mut dr, &mut t, &before_ops);

                let state = t.save_state(&mut dr).expect("save_state should succeed");
                let mut resumed = Transcript::resume_from_state(state, poseidon);

                // after_ops[0] is guaranteed Squeeze; squeeze it on ResumedTranscript.
                out.push(*resumed.challenge(&mut dr).unwrap().value().take());
                let mut t = resumed.into_transcript();
                out.extend(apply_ops(&mut dr, &mut t, &after_ops[1..]));
                out
            };

            prop_assert_eq!(expected, actual);
        }
    }

    #[test]
    #[should_panic]
    fn test_skip_squeeze_after_resume() {
        let params = Pasta::baked();
        let mut dr = Sim::new();

        let mut t =
            Transcript::new(&mut dr, Pasta::circuit_poseidon(params), b"skip-squeeze").unwrap();
        let e = Element::constant(&mut dr, Fp::from(42u64));
        e.write(&mut dr, &mut t).unwrap();

        let state = t.save_state(&mut dr).expect("save_state should succeed");
        let resumed = Transcript::resume_from_state(state, Pasta::circuit_poseidon(params));

        // should panic because no squeeze was called
        let _ = resumed.into_transcript();
    }
}
