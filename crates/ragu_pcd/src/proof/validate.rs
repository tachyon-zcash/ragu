//! The boundary where an application takes a proof: structural checks, and
//! the derivation of what a deserialized proof's encoding omits.

use alloc::borrow::Cow;

use ragu_circuits::polynomials::Rank;
use ragu_core::{Cycle, Error, Result};
use udon::curve::Affine;

use super::{Cached, CachedPoint, Pcd, Proof};
use crate::{
    Application, SelectableBackend,
    header::Header,
    internal::nested,
    profile::ProfiledCycle,
    wire::{self, Dimensions, Validate},
};

impl<G: Affine> Validate<CachedPoint> for Cached<G> {
    fn valid(&self, dims: Dimensions) -> bool {
        <G as Validate<wire::Point>>::valid(&self.0, dims)
    }
}

/// The lifts of a proof's challenges, in challenge-stage order, with
/// `pre_beta`'s last.
type Lifts<C> = [<C as Cycle>::ScalarField; nested::stages::challenges::NUM + 1];

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
    fn check(&self, proof: &Proof<C, R>) -> Result<()> {
        if !proof.well_formed::<H>() || !self.native_registry.circuit_in_domain(proof.circuit_id) {
            return Err(Error::InvalidWitness("malformed proof".into()));
        }
        Ok(())
    }

    /// Checks a proof one of this application's methods takes, and derives
    /// the values a deserialized proof's encoding omits. Returns the proof
    /// with every field set, borrowed when it already was, and the lifts of
    /// its challenges.
    ///
    /// Checks shapes, nonidentity point slots and the circuit domain before
    /// reading any field. An in-memory proof's challenges are its own;
    /// unusable ones are rejected here, before any consumer reconstructs
    /// stages from their lifts.
    pub(crate) fn prepare<'p>(
        &self,
        proof: &'p Proof<C, R>,
    ) -> Result<(Cow<'p, Proof<C, R>>, Lifts<C>)> {
        self.check(proof)?;
        let proof = if proof.complete {
            Cow::Borrowed(proof)
        } else {
            let mut proof = proof.clone();
            self.derive(&mut proof)?;
            Cow::Owned(proof)
        };
        let lifts = proof.challenges().lifts::<C>()?;
        Ok((proof, lifts))
    }

    /// [`prepare`](Self::prepare) for proof-carrying data the caller gives
    /// up, deriving in place rather than in a copy.
    pub(crate) fn prepare_owned<Hd: Header<C::CircuitField>>(
        &self,
        pcd: Pcd<C, R, Hd>,
    ) -> Result<Pcd<C, R, Hd>> {
        let Pcd { mut proof, data } = pcd;
        self.check(&proof)?;
        if !proof.complete {
            self.derive(&mut proof)?;
        }
        proof.challenges().lifts::<C>()?;
        Ok(Pcd { proof, data })
    }
}
