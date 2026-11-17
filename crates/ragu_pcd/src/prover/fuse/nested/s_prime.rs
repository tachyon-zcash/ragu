//! Nested s-prime prover phase.
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::RegistryAt,
};
use ragu_core::{Cycle, Result};
use udon::curve::Affine;

use crate::{Application, Proof, profile::ProfiledCycle, protocol::nested};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn compute_nested_s_prime(
        &self,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<NestedSPrime<C, R>> {
        let x0 = nested::challenge::<C>(left.x())?;
        let x1 = nested::challenge::<C>(right.x())?;

        let registry_wx0_poly = B::registry_at_x(nested_registry, x0);
        let registry_wx1_poly = B::registry_at_x(nested_registry, x1);
        let nested_gen = C::nested_generators(self.params);
        let mut commitments = [<C::NestedCurve as Affine>::identity(); 2];
        <C::NestedCurve as Affine>::batch_to_affine(
            &B::sparse_commit_batch([&registry_wx0_poly, &registry_wx1_poly], nested_gen),
            &mut commitments,
        );
        let [registry_wx0_commitment, registry_wx1_commitment] = commitments;

        Ok(NestedSPrime {
            registry_wx0_poly,
            registry_wx0_commitment,
            registry_wx1_poly,
            registry_wx1_commitment,
        })
    }
}

/// Ephemeral nested-field data for the $m_n(w_n, x_{i,n}, Y)$ restrictions,
/// used only during the fuse step.
pub(in crate::prover::fuse) struct NestedSPrime<C: Cycle, R: Rank> {
    pub(in crate::prover::fuse) registry_wx0_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(in crate::prover::fuse) registry_wx0_commitment: C::NestedCurve,
    pub(in crate::prover::fuse) registry_wx1_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(in crate::prover::fuse) registry_wx1_commitment: C::NestedCurve,
}
