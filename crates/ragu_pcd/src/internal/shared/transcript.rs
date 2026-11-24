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
//! // Squeeze a challenge, tagged with its role in the fuse's schedule
//! let w = transcript.challenge::<ChallengeW>(dr)?;
//!
//! // Save/resume for multi-circuit protocols
//! let state = transcript.save_state(dr)?;
//! let mut resumed = Transcript::resume_from_state(state, params);
//! let mu = resumed.challenge::<ChallengeMu>(dr)?; // must squeeze first
//! let mut transcript = resumed.into_transcript(); // then can absorb again
//! ```
//!
//! ### Typed challenges
//!
//! A squeeze returns a [`Challenge`] tagged with a zero-sized marker naming
//! the challenge it is in the fuse's schedule, [`ChallengeW`] through
//! [`ChallengePreBeta`]. Distinct markers make distinct types, so a function
//! or field that takes one challenge refuses another at compile time. The
//! tag names the role only: it places no restriction on the value, which can
//! be zero like any squeeze.
//!
//! Name the tag at the squeeze. A tag left to inference takes whatever the
//! challenge's first use expects, so two squeezes passed in the wrong order
//! would still compile. A squeeze that names no challenge of the schedule,
//! such as the compression's transcript, whose challenges its own protocols
//! name, uses the `()` tag.
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

use core::{marker::PhantomData, ops::Deref};

use ragu_core::{PoseidonPermutation, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{
    Element,
    io::Buffer,
    poseidon::{SaveError, Sponge, SpongeState},
};
use udon::field::Field;

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
    pub fn new(dr: &mut D, params: &'dr P, tag: &[u8]) -> Result<Self> {
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

    /// Squeezes the challenge `T` from the transcript.
    pub fn challenge<T>(&mut self, dr: &mut D) -> Result<Challenge<Element<'dr, D>, T>> {
        Ok(Challenge::new(self.sponge.squeeze(dr)?))
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
    /// Squeezes the challenge `T`.
    pub fn challenge<T>(&mut self, dr: &mut D) -> Result<Challenge<Element<'dr, D>, T>> {
        self.squeezed = true;
        Ok(Challenge::new(self.sponge.squeeze(dr)?))
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

/// A Fiat–Shamir challenge, tagged with the marker `T` naming which challenge
/// of the fuse's schedule it is.
///
/// The tag is a phantom type, so a challenge costs what its value does.
/// [`Deref`] reads the value for arithmetic, and
/// [`into_inner`](Self::into_inner) discards the tag where the value leaves
/// the typed boundary, such as a circuit's wires.
pub struct Challenge<F, T> {
    value: F,
    _marker: PhantomData<T>,
}

impl<F, T> Challenge<F, T> {
    /// Tags `value` as the challenge `T`.
    ///
    /// The transcript's squeezes tag their own output. Use this where a
    /// challenge was derived some other way: read back from a proof, or
    /// squeezed by the compression, which replays the fuse's schedule over
    /// its own transcript.
    pub fn new(value: F) -> Self {
        Challenge {
            value,
            _marker: PhantomData,
        }
    }

    /// Unwraps the challenge, discarding its tag.
    pub fn into_inner(self) -> F {
        self.value
    }
}

impl<F, T> Deref for Challenge<F, T> {
    type Target = F;

    fn deref(&self) -> &F {
        &self.value
    }
}

impl<F: Clone, T> Clone for Challenge<F, T> {
    fn clone(&self) -> Self {
        Challenge::new(self.value.clone())
    }
}

impl<F: Copy, T> Copy for Challenge<F, T> {}

impl<'dr, D: Driver<'dr>, T> Challenge<Element<'dr, D>, T> {
    /// The challenge's value, still tagged. Like [`Maybe::take`], this is
    /// for a driver that holds witness values, such as the prover's emulator,
    /// and fails to compile on one that does not.
    pub fn take(&self) -> Challenge<D::F, T> {
        Challenge::new(*self.value().take())
    }
}

/// Marks $w$, squeezed after the `preamble` bridge: the registry's $W$ point
/// and the application step's $\zeta$.
pub struct ChallengeW;

/// Marks $y$, the first challenge squeezed after the `s_prime` bridge.
pub struct ChallengeY;

/// Marks $z$, the second challenge squeezed after the `s_prime` bridge.
pub struct ChallengeZ;

/// Marks $\mu$, the first folding layer's challenge, squeezed after the
/// `inner_error` bridge.
pub struct ChallengeMu;

/// Marks $\mu'$, the second folding layer's challenge, squeezed after the
/// `outer_error` bridge.
pub struct ChallengeMuPrime;

/// Marks $x$, squeezed after the `ab` bridge.
pub struct ChallengeX;

/// Marks $\alpha$, squeezed after the `query` bridge.
pub struct ChallengeAlpha;

/// Marks $u$, squeezed after the `f` bridge: the point the batch opens at.
pub struct ChallengeU;

/// Marks `pre_beta`, squeezed after the `eval` bridge, whose endoscalar is
/// $\beta$.
pub struct ChallengePreBeta;

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use proptest::prelude::*;
    use ragu_core::{
        Cycle,
        maybe::Maybe,
        pasta::{Fp, Pasta},
    };
    use ragu_primitives::{GadgetExt, Simulator};
    use ragu_testing::strategies;

    use super::*;

    type Sim = Simulator<Fp>;

    fn arb_tag() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..=32)
    }

    fn arb_values(n: impl Into<prop::collection::SizeRange>) -> impl Strategy<Value = Vec<Fp>> {
        prop::collection::vec(strategies::prime_field_element::<Fp>(), n)
    }

    #[derive(Debug, Clone)]
    enum Op {
        Absorb(Fp),
        Squeeze,
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            strategies::prime_field_element::<Fp>().prop_map(Op::Absorb),
            Just(Op::Squeeze),
        ]
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
                Op::Squeeze => Some(*t.challenge::<()>(dr).unwrap().value().take()),
            })
            .collect()
    }

    proptest! {
        #[test]
        fn proptest_domain_separation(v in strategies::prime_field_element::<Fp>(), t1 in arb_tag(), t2 in arb_tag()) {
            prop_assume!(t1 != t2);
            let params = crate::pasta::baked();
            let mut dr = Sim::new();
            let poseidon = Pasta::circuit_poseidon(params);

            let mut tr1 = Transcript::new(&mut dr, poseidon, &t1).unwrap();
            let mut tr2 = Transcript::new(&mut dr, poseidon, &t2).unwrap();

            let elem = Element::constant(&mut dr, v);
            elem.write(&mut dr, &mut tr1).unwrap();
            elem.write(&mut dr, &mut tr2).unwrap();

            let c1 = *tr1.challenge::<()>(&mut dr).unwrap().value().take();
            let c2 = *tr2.challenge::<()>(&mut dr).unwrap().value().take();
            prop_assert_ne!(c1, c2);
        }

        #[test]
        fn proptest_determinism(vs in arb_values(1..=8)) {
            let params = crate::pasta::baked();
            let poseidon = Pasta::circuit_poseidon(params);

            let squeeze = |vs: &[Fp]| {
                let mut dr = Sim::new();
                let mut t = Transcript::new(&mut dr, poseidon, b"determinism").unwrap();
                for &v in vs {
                    let e = Element::constant(&mut dr, v);
                    e.write(&mut dr, &mut t).unwrap();
                }
                *t.challenge::<()>(&mut dr).unwrap().value().take()
            };

            prop_assert_eq!(squeeze(&vs), squeeze(&vs));
        }

        #[test]
        fn proptest_squeezes_distinct(v in strategies::prime_field_element::<Fp>()) {
            let params = crate::pasta::baked();
            let mut dr = Sim::new();

            let mut t = Transcript::new(&mut dr, Pasta::circuit_poseidon(params), b"distinct").unwrap();
            let e = Element::constant(&mut dr, v);
            e.write(&mut dr, &mut t).unwrap();

            let c0 = *t.challenge::<()>(&mut dr).unwrap().value().take();
            let c1 = *t.challenge::<()>(&mut dr).unwrap().value().take();
            let c2 = *t.challenge::<()>(&mut dr).unwrap().value().take();
            let c3 = *t.challenge::<()>(&mut dr).unwrap().value().take();

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
        /// Two properties are enforced by construction:
        /// - `before_ops` ends with a guaranteed `Absorb` so `save_state` is
        ///   called while the sponge is in absorb mode.
        /// - `after_ops` starts with a guaranteed `Squeeze` so
        ///   `into_transcript` can be called legally after resuming.
        #[test]
        fn proptest_save_resume_continuity(
            before_prefix in prop::collection::vec(arb_op(), 0..=5),
            before_final  in strategies::prime_field_element::<Fp>(),
            after_rest    in prop::collection::vec(arb_op(), 0..=4),
        ) {
            let params = crate::pasta::baked();
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
                out.push(*resumed.challenge::<()>(&mut dr).unwrap().value().take());
                let mut t = resumed.into_transcript();
                out.extend(apply_ops(&mut dr, &mut t, &after_ops[1..]));
                out
            };

            prop_assert_eq!(expected, actual);
        }
    }

    #[test]
    #[should_panic(
        expected = "must squeeze at least once before transitioning back to absorb mode"
    )]
    fn test_skip_squeeze_after_resume() {
        let params = crate::pasta::baked();
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

    #[test]
    fn challenge_costs_its_value() {
        use core::mem::{align_of, size_of};

        assert_eq!(size_of::<Challenge<Fp, ChallengeW>>(), size_of::<Fp>());
        assert_eq!(align_of::<Challenge<Fp, ChallengeW>>(), align_of::<Fp>());
        assert_eq!(
            size_of::<Challenge<Element<'static, Sim>, ChallengeX>>(),
            size_of::<Element<'static, Sim>>()
        );
    }

    /// The tag is a type only: it is not absorbed, so the same transcript
    /// squeezes the same value under any tag.
    #[test]
    fn tag_leaves_the_squeeze_unchanged() {
        let params = crate::pasta::baked();
        let mut dr = Sim::new();

        let mut t = Transcript::new(&mut dr, Pasta::circuit_poseidon(params), b"tags").unwrap();
        let e = Element::constant(&mut dr, Fp::from(7u64));
        e.write(&mut dr, &mut t).unwrap();
        let mut untagged = t.clone();

        let w = t.challenge::<ChallengeW>(&mut dr).unwrap();
        let raw = untagged.challenge::<()>(&mut dr).unwrap();
        assert_eq!(*w.value().take(), *raw.value().take());
    }
}
