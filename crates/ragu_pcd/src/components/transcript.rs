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
//! let mut transcript = Transcript::resume_from_state(dr, state, params);
//! ```

use arithmetic::PoseidonPermutation;
use ff::PrimeField;
use ragu_core::{Result, drivers::Driver};

use ragu_primitives::{
    Element,
    io::Buffer,
    poseidon::{SaveError, Sponge, SpongeState},
};

/// Transcript wrapper around Poseidon [`Sponge`] for Fiat-Shamir transforms.
pub(crate) struct Transcript<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> {
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
pub(crate) type TranscriptState<'dr, D, P> = SpongeState<'dr, D, P>;

impl<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> Transcript<'dr, D, P> {
    /// Creates a new transcript with mandatory domain separation.
    ///
    /// The `tag` is absorbed as field elements (length-prefixed, 16 bytes per
    /// element via u128 conversion) to bind the transcript to a protocol context.
    pub(crate) fn new(dr: &mut D, params: &'dr P, tag: &[u8]) -> Result<Self>
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
    pub(crate) fn challenge(&mut self, dr: &mut D) -> Result<Element<'dr, D>> {
        self.sponge.squeeze(dr)
    }

    /// Saves the transcript state (analogous to flush).
    ///
    /// This consumes the transcript and applies a permutation to transition
    /// into squeeze mode. The returned state can be passed to another circuit
    /// for resumption via [`Self::resume_from_state`].
    pub(crate) fn save_state(
        self,
        dr: &mut D,
    ) -> core::result::Result<TranscriptState<'dr, D, P>, SaveError> {
        self.sponge.save_state(dr)
    }

    /// Resumes transcript from saved state.
    ///
    /// The resumed transcript is in **squeeze mode**, ready to output challenges
    /// via [`Self::challenge`]. You can either:
    /// - Squeeze challenges from previously-absorbed data first, then absorb new messages
    /// - Absorb additional messages immediately (transitions back to absorb mode)
    ///
    /// Note: Calling `write()` before `challenge()` transitions back to absorb mode.
    /// Any remaining squeeze capacity from the saved state becomes inaccessible.
    pub(crate) fn resume_from_state(
        dr: &mut D,
        state: TranscriptState<'dr, D, P>,
        params: &'dr P,
    ) -> Self {
        let sponge = Sponge::resume(dr, state, params);
        Transcript { sponge, params }
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
    use arithmetic::Cycle;
    use ff::Field;
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
        let challenge1 = transcript1.challenge(&mut dr)?;
        let challenge2 = transcript2.challenge(&mut dr)?;

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
        let challenge1 = transcript1.challenge(&mut dr)?;

        // Save/resume flow: absorb, save state, resume, then squeeze
        let mut transcript2 =
            Transcript::new(&mut dr, Pasta::circuit_poseidon(params), b"test-protocol")?;
        value1.write(&mut dr, &mut transcript2)?;

        let state = transcript2
            .save_state(&mut dr)
            .expect("save_state should succeed");

        let mut transcript2 =
            Transcript::resume_from_state(&mut dr, state, Pasta::circuit_poseidon(params));
        let challenge2 = transcript2.challenge(&mut dr)?;

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

        let challenge1 = transcript1.challenge(&mut dr)?;
        let challenge2 = transcript2.challenge(&mut dr)?;
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

        let challenge = transcript.challenge(&mut dr)?;
        assert_ne!(*challenge.value().take(), Fp::ZERO);

        let c1 = transcript.challenge(&mut dr)?;
        let c2 = transcript.challenge(&mut dr)?;
        let c3 = transcript.challenge(&mut dr)?;
        assert_ne!(*c1.value().take(), Fp::ZERO);
        assert_ne!(*c2.value().take(), Fp::ZERO);
        assert_ne!(*c3.value().take(), Fp::ZERO);

        Ok(())
    }
}
