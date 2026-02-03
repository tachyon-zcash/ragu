//! Transcript abstraction for Fiat-Shamir transforms.
//!
//! This module provides a [`TranscriptProtocol`] trait defining Fiat-Shamir
//! operations, along with a concrete [`Transcript`] implementation that wraps
//! around the Poseidon [`Sponge`].
//!
//! ## Usage
//!
//! ```rust
//! use ragu_primitives::{Transcript, TranscriptProtocol, GadgetExt, Element, vec::{FixedVec, ConstLen}};
//! # use arithmetic::Cycle;
//! # use ragu_pasta::{Fp, Pasta};
//! # type Simulator = ragu_primitives::Simulator<Fp>;
//! # let params = Pasta::baked();
//! # let mut dr = Simulator::new();
//!
//! // Initialize transcript with domain separation
//! let mut transcript = Transcript::new(&mut dr, Pasta::circuit_poseidon(params));
//! transcript.domain_sep(&mut dr, b"my-protocol").unwrap();
//!
//! // Absorb a single field element via Buffer trait
//! let a = Element::constant(&mut dr, Fp::from(42));
//! a.write(&mut dr, &mut transcript).unwrap();
//!
//! // Squeeze a single field element challenge
//! let challenge: Element<'_, _> = transcript.challenge(&mut dr).unwrap();
//!
//! // Absorb multiple elements via FixedVec
//! let values = FixedVec::<Element<'_, _>, ConstLen<3>>::from_fn(|i| {
//!     Element::constant(&mut dr, Fp::from((i + 1) as u64))
//! });
//! values.write(&mut dr, &mut transcript).unwrap();
//!
//! // Squeeze an array of 4 challenges
//! let challenges: [Element<'_, _>; 4] = transcript.challenge(&mut dr).unwrap();
//! ```
//!
//! ## Save/Resume for Multi-Circuit Transcripts
//!
//! The transcript supports multi-circuit protocols via [`save_state`](TranscriptExt::save_state)
//! and [`resume_from`](TranscriptExt::resume_from), allowing state to be passed
//! between circuits with constraint-checked continuity.

use arithmetic::PoseidonPermutation;
use ff::PrimeField;
use ragu_core::{Result, drivers::Driver};

use crate::{
    Element,
    io::{Buffer, FromElements},
    poseidon::{SaveError, Sponge, SpongeState},
};

/// Protocol-level transcript operations extending writeable [`Buffer`].
///
/// This trait provides domain separation, prover message absorption
/// (via [`write`]), and challenge generation.
///
/// [`write`]: Buffer::write
pub trait TranscriptProtocol<'dr, D: Driver<'dr>>: Buffer<'dr, D> {
    /// Apply domain separation.
    ///
    /// This should be called once at initialization to bind the transcript to a
    /// protocol context. The tag is absorbed as field elements (8 bytes per
    /// element via u64 conversion).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut transcript = Transcript::new(dr, params);
    /// transcript.domain_sep(dr, b"ragu-pcd-v1")?;
    /// ```
    fn domain_sep(&mut self, dr: &mut D, tag: &[u8]) -> Result<()>
    where
        D::F: PrimeField;

    /// Squeeze a challenge from the transcript.
    ///
    /// The challenge type is determined by type inference or explicit type
    /// annotation. The transcript squeezes `N` field elements and constructs
    /// the challenge using [`FromElements`].
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let w: Element<'dr, D> = transcript.challenge(dr)?;
    /// // Type inference for Point (2 field elements)
    /// let p: Point<'dr, D, C> = transcript.challenge(dr)?;
    /// let q: FixedVec<Element<'dr, D>, ConstLen<N>> = transcript.challenge(dr)?;
    /// ```
    fn challenge<T, const N: usize>(&mut self, dr: &mut D) -> Result<T>
    where
        T: FromElements<'dr, D, N>;
}

impl<'dr, D, P> TranscriptProtocol<'dr, D> for Transcript<'dr, D, P>
where
    D: Driver<'dr>,
    P: PoseidonPermutation<D::F>,
    D::F: PrimeField,
{
    fn domain_sep(&mut self, dr: &mut D, tag: &[u8]) -> Result<()> {
        // Absorb protocol tag as field elements
        // Pack bytes into u64 chunks (8 bytes each)
        for chunk in tag.chunks(8) {
            let bytes: [u8; 8] = core::array::from_fn(|i| chunk.get(i).copied().unwrap_or(0));
            let elem = Element::constant(dr, D::F::from(u64::from_le_bytes(bytes)));

            self.sponge.absorb(dr, &elem)?;
        }
        Ok(())
    }

    fn challenge<T, const N: usize>(&mut self, dr: &mut D) -> Result<T>
    where
        T: FromElements<'dr, D, N>,
    {
        // TODO: (alex) use try_map once stabilized:
        // `core::array::from_fn(|_| self.sponge.squeeze(dr)).try_map(|e| e)?;`
        let mut elements = core::array::from_fn(|_| Element::one());
        for e in &mut elements {
            *e = self.sponge.squeeze(dr)?;
        }

        T::from_elements(dr, elements)
    }
}

/// Extended transcript operations for save/resume.
///
/// This trait provides state management operations for multi-circuit protocols.
/// It is implemented for [`Transcript`] and enables the save/resume pattern.
pub trait TranscriptExt<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>>:
    TranscriptProtocol<'dr, D> + Sized
{
    /// Save the transcript state (analogous to flush).
    ///
    /// This consumes the transcript and applies a permutation to transition
    /// into squeeze mode. The returned state can be passed to another circuit
    /// for resumption via [`Self::resume_from`].
    ///
    /// # Usage
    ///
    /// ```rust,ignore
    /// let state = transcript.save_state(dr)?;
    /// // Pass `state` to another circuit...
    /// let mut transcript = Transcript::resume_from(dr, state, params)?;
    /// let c: Element<'dr, D> = transcript.challenge(dr)?;
    /// ```
    fn save_state(self, dr: &mut D) -> core::result::Result<TranscriptState<'dr, D, P>, SaveError>;

    /// Resume transcript from saved state.
    ///
    /// After resuming, call [`TranscriptProtocol::challenge`] to squeeze
    /// challenges.
    fn resume_from(dr: &mut D, state: TranscriptState<'dr, D, P>, params: &'dr P) -> Result<Self>;
}

/// Transcript wrapper around Poseidon [`Sponge`] for Fiat-Shamir transforms.
///
/// See the [module-level documentation] for design details.
///
/// [module-level documentation]: self
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
    /// Create a new transcript.
    ///
    /// After creation, call [`TranscriptProtocol::domain_sep`] to bind the
    /// transcript to a protocol context.
    pub fn new(dr: &mut D, params: &'dr P) -> Self {
        Transcript {
            sponge: Sponge::new(dr, params),
            params,
        }
    }

    /// Explicitly clone the transcript for save_state pattern.
    pub fn clone_for_save(&self) -> Self {
        self.clone()
    }
}

impl<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>> Buffer<'dr, D> for Transcript<'dr, D, P> {
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        self.sponge.absorb(dr, value)
    }
}

impl<'dr, D, P> TranscriptExt<'dr, D, P> for Transcript<'dr, D, P>
where
    D: Driver<'dr>,
    P: PoseidonPermutation<D::F>,
    D::F: PrimeField,
{
    fn save_state(self, dr: &mut D) -> core::result::Result<TranscriptState<'dr, D, P>, SaveError> {
        self.sponge.save_state(dr)
    }

    fn resume_from(dr: &mut D, state: TranscriptState<'dr, D, P>, params: &'dr P) -> Result<Self> {
        let sponge = Sponge::resume(dr, state, params);
        Ok(Transcript { sponge, params })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arithmetic::Cycle;
    use ff::Field;
    use ragu_core::maybe::Maybe;
    use ragu_pasta::{Fp, Pasta};

    use crate::GadgetExt;

    type Simulator = crate::Simulator<Fp>;

    #[test]
    fn test_domain_separation() -> Result<()> {
        let params = Pasta::baked();
        let mut dr = Simulator::new();

        // Create two transcripts with different domain tags
        let mut transcript1 = Transcript::new(&mut dr, Pasta::circuit_poseidon(params));
        transcript1.domain_sep(&mut dr, b"domain-1")?;

        let mut transcript2 = Transcript::new(&mut dr, Pasta::circuit_poseidon(params));
        transcript2.domain_sep(&mut dr, b"domain-2")?;

        // Absorb the same value into both
        let value = Element::constant(&mut dr, Fp::from(42));
        value.write(&mut dr, &mut transcript1)?;
        value.write(&mut dr, &mut transcript2)?;

        // Different domains should produce different challenges
        let challenge1: Element<'_, _> = transcript1.challenge(&mut dr)?;
        let challenge2: Element<'_, _> = transcript2.challenge(&mut dr)?;

        assert_ne!(*challenge1.value().take(), *challenge2.value().take());

        Ok(())
    }

    #[test]
    fn test_save_resume_consistency() -> Result<()> {
        let params = Pasta::baked();
        let mut dr = Simulator::new();

        // Normal flow: absorb then squeeze directly
        let mut transcript1 = Transcript::new(&mut dr, Pasta::circuit_poseidon(params));
        transcript1.domain_sep(&mut dr, b"test-protocol")?;
        let value1 = Element::constant(&mut dr, Fp::from(123));
        value1.write(&mut dr, &mut transcript1)?;
        let challenge1: Element<'_, _> = transcript1.challenge(&mut dr)?;

        // Save/resume flow: absorb, save state, resume, then squeeze
        let mut transcript2 = Transcript::new(&mut dr, Pasta::circuit_poseidon(params));
        transcript2.domain_sep(&mut dr, b"test-protocol")?;
        value1.write(&mut dr, &mut transcript2)?;

        let state = transcript2
            .save_state(&mut dr)
            .expect("save_state should succeed");

        let mut transcript2 =
            Transcript::resume_from(&mut dr, state, Pasta::circuit_poseidon(params))?;
        let challenge2: Element<'_, _> = transcript2.challenge(&mut dr)?;

        // Both flows should produce the same challenge
        assert_eq!(*challenge1.value().take(), *challenge2.value().take());

        Ok(())
    }

    #[test]
    fn test_challenge_determinism() -> Result<()> {
        let params = Pasta::baked();
        let mut dr = Simulator::new();
        let value1 = Element::constant(&mut dr, Fp::from(999));
        let value2 = Element::constant(&mut dr, Fp::from(500));

        // Run the same sequence twice with identical inputs
        let mut transcript1 = Transcript::new(&mut dr, Pasta::circuit_poseidon(params));
        transcript1.domain_sep(&mut dr, b"determinism-test")?;
        value1.write(&mut dr, &mut transcript1)?;
        value2.write(&mut dr, &mut transcript1)?;

        let mut transcript2 = Transcript::new(&mut dr, Pasta::circuit_poseidon(params));
        transcript2.domain_sep(&mut dr, b"determinism-test")?;
        value1.write(&mut dr, &mut transcript2)?;
        value2.write(&mut dr, &mut transcript2)?;

        let challenge1: Element<'_, _> = transcript1.challenge(&mut dr)?;
        let challenge2: Element<'_, _> = transcript2.challenge(&mut dr)?;
        assert_eq!(*challenge1.value().take(), *challenge2.value().take());

        Ok(())
    }

    #[test]
    fn test_challenge_type_inference() -> Result<()> {
        let params = Pasta::baked();
        let mut dr = Simulator::new();

        let mut transcript = Transcript::new(&mut dr, Pasta::circuit_poseidon(params));
        let value = Element::constant(&mut dr, Fp::from(123));
        value.write(&mut dr, &mut transcript)?;

        let challenge: Element<'_, _> = transcript.challenge(&mut dr)?;
        assert_ne!(*challenge.value().take(), Fp::ZERO);

        let array: [Element<'_, _>; 3] = transcript.challenge(&mut dr)?;
        assert_eq!(array.len(), 3);

        Ok(())
    }
}
