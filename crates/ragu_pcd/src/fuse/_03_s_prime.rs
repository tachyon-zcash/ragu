//! Commit to $m(w, x_i, Y)$ polynomials for the child proofs.
//!
//! This sets the s-prime fields on the [`ProofBuilder`], which commits to the
//! $m(w, x_i, Y)$ polynomials for the $i$th child proof's $x$ challenge.
//!
//! The nested registry's restrictions $m_n(w_n, x_{i,n}, Y)$ are computed
//! here as well, at the nested counterparts of the same challenges. Their
//! nested-curve commitments are committed in the native points stage the
//! endoscaling walk reads them from, whose commitment the `s_prime` bridge
//! carries, so they are fixed before $y$ is squeezed.

use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::{Cycle, Result};
use rand::CryptoRng;
use udon::{curve::Affine, field::Field};

use super::{NativeSPrime, NestedSPrime};
use crate::{Application, Proof, internal::nested, proof::ProofBuilder};

impl<
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    J: crate::framework_hooks::HookConfig,
    B: crate::SelectableBackend,
> Application<'_, C, R, HEADER_SIZE, J, B>
{
    pub(super) fn compute_s_prime<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        nested_registry: &RegistryAt<'_, C::ScalarField, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, J, B>,
    ) -> Result<(NativeSPrime<C, R>, NestedSPrime<C, R>)> {
        let native = self.compute_native_s_prime(native_registry, left, right)?;
        let nested = self.compute_nested_s_prime(nested_registry, left, right)?;
        self.commit_native_points_registry_wx(
            rng,
            nested.registry_wx0_commitment,
            nested.registry_wx1_commitment,
            builder,
        )?;
        self.compute_bridge_s_prime(rng, &native, builder)?;
        Ok((native, nested))
    }

    fn compute_bridge_s_prime<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native: &NativeSPrime<C, R>,
        builder: &mut ProofBuilder<'_, C, R, J, B>,
    ) -> Result<()> {
        let bridge_rx = nested::stages::s_prime::Stage::<C::HostCurve, R, J::PolyWitnesses>::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &nested::stages::s_prime::Witness {
                registry_wx0: native.registry_wx0_commitment,
                registry_wx1: native.registry_wx1_commitment,
                native_points_registry_wx: builder.native_points_registry_wx_commitment(),
            },
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_s_prime_rx(bridge_rx, bridge_commitment);
        Ok(())
    }

    fn compute_native_s_prime(
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
            &[
                B::sparse_commit(&registry_wx0_poly, host_gen),
                B::sparse_commit(&registry_wx1_poly, host_gen),
            ],
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

    fn compute_nested_s_prime(
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
            &[
                B::sparse_commit(&registry_wx0_poly, nested_gen),
                B::sparse_commit(&registry_wx1_poly, nested_gen),
            ],
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
