use alloc::vec::Vec;

use blake2b_simd::{Params, State};
use ragu_core::Result;
use udon::{curve::Affine, field::Field};

use crate::ipa::IpaTranscript;

#[derive(Clone)]
pub(super) struct Transcript(State);

impl Transcript {
    pub(super) fn new(domain: &[u8]) -> Self {
        let mut transcript = Self(Params::new().personal(b"RaguHidingExp-v1").to_state());
        transcript.bytes(domain);
        transcript
    }

    pub(super) fn bytes(&mut self, bytes: &[u8]) {
        self.0.update(&(bytes.len() as u64).to_le_bytes());
        self.0.update(bytes);
    }

    pub(super) fn point<C: Affine>(&mut self, point: C) {
        self.bytes(point.to_bytes().as_ref());
    }

    pub(super) fn scalar<F: Field>(&mut self, scalar: F) {
        self.bytes(scalar.to_bytes().as_ref());
    }

    pub(super) fn challenge<F: Field>(&mut self, label: &[u8]) -> F {
        self.bytes(label);
        let hash = self.0.finalize();
        self.bytes(hash.as_bytes());
        F::from_uniform_bytes(hash.as_array())
    }
}

/// The batch's three squeezes follow the prefix, quotient, and full
/// evaluation vector respectively. Only hiding commitments reach the hash.
pub(super) struct BatchTranscript<'a, C: Affine> {
    pub inner: Transcript,
    pub bases: super::Bases<C>,
    pub blinds: &'a [C::Scalar],
    pub quotient: Option<super::HiddenPoint<C>>,
    pub evaluations: Vec<C>,
    pub draws: usize,
}

pub(super) const BATCH_DRAWS: [&[u8]; 3] = [b"alpha", b"u", b"beta"];

impl<C: Affine> IpaTranscript<C> for BatchTranscript<'_, C> {
    fn write_point(&mut self, point: C) -> Result<()> {
        assert!(self.draws == 1 && self.quotient.is_none());
        let masked = self.bases.hide_point(point, self.blinds[0]);
        masked.absorb(&mut self.inner);
        self.quotient = Some(masked);
        Ok(())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<()> {
        assert_eq!(self.draws, 2);
        let commitment = self
            .bases
            .commit(scalar, self.blinds[1 + self.evaluations.len()]);
        self.inner.point(commitment);
        self.evaluations.push(commitment);
        Ok(())
    }

    fn squeeze_challenge(&mut self) -> Result<C::Scalar> {
        let result = self.inner.challenge(BATCH_DRAWS[self.draws]);
        self.draws += 1;
        Ok(result)
    }
}

/// Scoped to this fixed-zero IPA. Canonical byte encodings handle identities
/// and scalar zero on both curves without a nonidentity bridge.
impl<C: Affine> IpaTranscript<C> for Transcript {
    fn write_point(&mut self, point: C) -> Result<()> {
        self.point(point);
        Ok(())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<()> {
        self.scalar(scalar);
        Ok(())
    }

    fn squeeze_challenge(&mut self) -> Result<C::Scalar> {
        Ok(self.challenge(b"ipa-challenge"))
    }
}
