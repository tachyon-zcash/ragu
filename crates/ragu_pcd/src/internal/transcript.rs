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
//! // Squeeze a typed challenge
//! let w = transcript.challenge::<ChallengeW>(dr)?;
//!
//! // Save/resume for multi-circuit protocols
//! let state = transcript.save_state(dr)?;
//! let mut resumed = Transcript::resume_from_state(state, params);
//! let mu = resumed.challenge::<ChallengeMu>(dr)?; // must squeeze first
//! let mut transcript = resumed.into_transcript(); // then can absorb again
//! ```

use ff::PrimeField;
use ragu_arithmetic::PoseidonPermutation;
use ragu_core::{Result, drivers::Driver};

use ragu_primitives::{
    Element,
    io::Buffer,
    poseidon::{SaveError, Sponge, SpongeState},
};

use crate::proof::Challenge;

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

    /// Squeezes a typed challenge from the transcript.
    ///
    /// The phantom tag `T` is inferred from the binding site.
    pub(crate) fn challenge<T>(&mut self, dr: &mut D) -> Result<Challenge<Element<'dr, D>, T>> {
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
    /// Squeezes a typed challenge from the resumed transcript.
    ///
    /// The phantom tag `T` is inferred from the binding site.
    pub(crate) fn challenge<T>(&mut self, dr: &mut D) -> Result<Challenge<Element<'dr, D>, T>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use ragu_arithmetic::Cycle;
    use ragu_core::maybe::Maybe;
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::{GadgetExt, Simulator};

    type Sim = Simulator<Fp>;

    #[test]
    fn test_domain_separation() -> Result<()> {
        let params = Pasta::baked();
        let mut dr = Sim::new();

        // Create two transcripts with different domain tags
        let mut transcript1 =
            Transcript::new(&mut dr, Pasta::circuit_poseidon(params), b"domain-1")?;
        let mut transcript2 =
            Transcript::new(&mut dr, Pasta::circuit_poseidon(params), b"domain-2")?;

        // Absorb the same value into both
        let value = Element::constant(&mut dr, Fp::from(42));
        value.write(&mut dr, &mut transcript1)?;
        value.write(&mut dr, &mut transcript2)?;

        // Different domains should produce different challenges
        let challenge1 = transcript1.challenge::<()>(&mut dr)?;
        let challenge2 = transcript2.challenge::<()>(&mut dr)?;

        assert_ne!(*challenge1.value().take(), *challenge2.value().take());

        Ok(())
    }

    #[test]
    fn test_save_resume_consistency() -> Result<()> {
        let params = Pasta::baked();
        let mut dr = Sim::new();

        // Normal flow: absorb then squeeze directly
        let mut transcript1 =
            Transcript::new(&mut dr, Pasta::circuit_poseidon(params), b"test-protocol")?;
        let value1 = Element::constant(&mut dr, Fp::from(123));
        value1.write(&mut dr, &mut transcript1)?;
        let challenge1 = transcript1.challenge::<()>(&mut dr)?;

        // Save/resume flow: absorb, save state, resume, then squeeze
        let mut transcript2 =
            Transcript::new(&mut dr, Pasta::circuit_poseidon(params), b"test-protocol")?;
        value1.write(&mut dr, &mut transcript2)?;

        let state = transcript2
            .save_state(&mut dr)
            .expect("save_state should succeed");

        let mut resumed = Transcript::resume_from_state(state, Pasta::circuit_poseidon(params));
        let challenge2 = resumed.challenge::<()>(&mut dr)?;

        // Both flows should produce the same challenge
        assert_eq!(*challenge1.value().take(), *challenge2.value().take());

        Ok(())
    }

    #[test]
    fn test_challenge_determinism() -> Result<()> {
        let params = Pasta::baked();
        let mut dr = Sim::new();
        let value1 = Element::constant(&mut dr, Fp::from(999));
        let value2 = Element::constant(&mut dr, Fp::from(500));

        // Run the same sequence twice with identical inputs
        let mut transcript1 = Transcript::new(
            &mut dr,
            Pasta::circuit_poseidon(params),
            b"determinism-test",
        )?;
        value1.write(&mut dr, &mut transcript1)?;
        value2.write(&mut dr, &mut transcript1)?;

        let mut transcript2 = Transcript::new(
            &mut dr,
            Pasta::circuit_poseidon(params),
            b"determinism-test",
        )?;
        value1.write(&mut dr, &mut transcript2)?;
        value2.write(&mut dr, &mut transcript2)?;

        let challenge1 = transcript1.challenge::<()>(&mut dr)?;
        let challenge2 = transcript2.challenge::<()>(&mut dr)?;
        assert_eq!(*challenge1.value().take(), *challenge2.value().take());

        Ok(())
    }

    #[test]
    fn test_challenge_multiple_squeezes() -> Result<()> {
        let params = Pasta::baked();
        let mut dr = Sim::new();

        let mut transcript = Transcript::new(&mut dr, Pasta::circuit_poseidon(params), b"test")?;
        let value = Element::constant(&mut dr, Fp::from(123));
        value.write(&mut dr, &mut transcript)?;

        let c0 = *transcript.challenge::<()>(&mut dr)?.value().take();
        let c1 = *transcript.challenge::<()>(&mut dr)?.value().take();
        let c2 = *transcript.challenge::<()>(&mut dr)?.value().take();
        let c3 = *transcript.challenge::<()>(&mut dr)?.value().take();

        // Each squeeze must produce a non-zero, distinct value.
        for c in [c0, c1, c2, c3] {
            assert_ne!(c, Fp::ZERO);
        }
        assert_ne!(c0, c1);
        assert_ne!(c1, c2);
        assert_ne!(c2, c3);

        Ok(())
    }

    /// Verifies that splitting a transcript across a save/resume boundary
    /// produces the same challenges as a straight-through transcript.
    #[test]
    fn test_resume_squeeze_absorb_squeeze() -> Result<()> {
        let params = Pasta::baked();
        let poseidon = Pasta::circuit_poseidon(params);
        let mut dr = Sim::new();

        let v1 = Element::constant(&mut dr, Fp::from(42));
        let v2 = Element::constant(&mut dr, Fp::from(99));

        let mut t = Transcript::new(&mut dr, poseidon, b"resume-test")?;
        v1.write(&mut dr, &mut t)?;
        let expected_c1 = *t.challenge::<()>(&mut dr)?.value().take();
        v2.write(&mut dr, &mut t)?;
        let expected_c2 = *t.challenge::<()>(&mut dr)?.value().take();

        let mut t = Transcript::new(&mut dr, poseidon, b"resume-test")?;
        v1.write(&mut dr, &mut t)?;
        let state = t.save_state(&mut dr).expect("save_state should succeed");
        let mut resumed = Transcript::resume_from_state(state, poseidon);
        let c1 = *resumed.challenge::<()>(&mut dr)?.value().take();
        let mut t = resumed.into_transcript();
        v2.write(&mut dr, &mut t)?;
        let c2 = *t.challenge::<()>(&mut dr)?.value().take();

        assert_eq!(c1, expected_c1);
        assert_eq!(c2, expected_c2);

        Ok(())
    }
}
