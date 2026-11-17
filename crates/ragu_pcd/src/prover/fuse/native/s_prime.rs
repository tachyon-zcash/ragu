//! Native s-prime prover phase.
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::RegistryAt,
};
use ragu_core::{Cycle, Result};
use udon::curve::Affine;

use crate::{Application, Proof, profile::ProfiledCycle};

/// Ephemeral native-field data for $s'(X)$, used only during the fuse step.
pub(in crate::prover::fuse) struct NativeSPrime<C: Cycle, R: Rank> {
    pub(in crate::prover::fuse) registry_wx0_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(in crate::prover::fuse) registry_wx0_commitment: C::HostCurve,
    pub(in crate::prover::fuse) registry_wx1_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(in crate::prover::fuse) registry_wx1_commitment: C::HostCurve,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn compute_native_s_prime(
        &self,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<NativeSPrime<C, R>> {
        let x0 = left.x();
        let x1 = right.x();

        let registry_wx0_poly = B::registry_at_x(native_registry, x0);
        let registry_wx1_poly = B::registry_at_x(native_registry, x1);
        let host_gen = C::host_generators(self.params);
        let mut commitments = [<C::HostCurve as Affine>::identity(); 2];
        <C::HostCurve as Affine>::batch_to_affine(
            &B::sparse_commit_batch([&registry_wx0_poly, &registry_wx1_poly], host_gen),
            &mut commitments,
        );
        let [registry_wx0_commitment, registry_wx1_commitment] = commitments;

        Ok(NativeSPrime {
            registry_wx0_poly,
            registry_wx0_commitment,
            registry_wx1_poly,
            registry_wx1_commitment,
        })
    }
}
