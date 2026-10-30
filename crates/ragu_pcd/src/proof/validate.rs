//! Structural preflight shared by minimal and expanded proof boundaries.

use alloc::vec::Vec;
use ragu_circuits::polynomials::Rank;
use ragu_core::{Error, Result};
use udon::{curve::Affine, field::Field};

use super::{Cached, CachedPoint, MinimalProof, Proof, format::Header};
use crate::{
    Application, SelectableBackend,
    internal::nested,
    profile::ProfiledCycle,
    wire::{self, Validate},
};

impl<G: Affine> Validate<CachedPoint> for Cached<G> {
    fn valid(&self) -> bool {
        <G as Validate<wire::Point>>::valid(&self.0)
    }
}
impl<F: Field, const H: usize> Validate<Header<H>> for Vec<F> {
    fn valid(&self) -> bool {
        self.len() == H
    }
}

impl<C: ProfiledCycle, R: Rank, const H: usize, B: SelectableBackend> Application<'_, C, R, H, B> {
    // The proof's circuit_id selects which wiring polynomial the verifier
    // checks against, and every domain point carries one, so an in-domain id
    // is always well defined. It need not name a circuit: the domain also
    // holds registered bonding polynomials and, at unassigned points, the
    // zero polynomial, which is itself a bonding polynomial. Letting the
    // prover choose freely among them is safe because this check expects a
    // circuit and so fixes k_0 = 1, which no bonding polynomial (s(X, 0) =
    // 0) can satisfy. Rejecting out-of-domain ids keeps the selection inside
    // that argument, rather than an evaluation of the registry interpolation
    // at an arbitrary point.
    // (Internal circuit IDs are constants and don't need this check.)
    pub(crate) fn preflight_minimal(&self, proof: &MinimalProof<C, R, H>) -> Result<()> {
        if !proof.well_formed() || !self.native_registry.circuit_in_domain(proof.circuit_id) {
            return Err(Error::InvalidWitness("malformed minimal proof".into()));
        }
        Ok(())
    }

    pub(crate) fn preflight_proof(
        &self,
        proof: &Proof<C, R>,
    ) -> Result<[C::ScalarField; nested::stages::challenges::NUM + 1]> {
        if !proof.well_formed::<H>() || !self.native_registry.circuit_in_domain(proof.circuit_id) {
            return Err(Error::InvalidWitness("malformed proof".into()));
        }
        // Expanded proofs may be constructed in memory. Reject unusable cached
        // challenges before any consumer reconstructs stages from their lifts.
        proof.challenges().lifts::<C>()
    }
}
