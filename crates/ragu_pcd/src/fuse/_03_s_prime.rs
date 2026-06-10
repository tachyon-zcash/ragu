//! Commit to $m(w, x_i, Y)$ polynomials for the child proofs.
//!
//! This sets the s-prime fields on the [`ProofBuilder`], which commits to the
//! $m(w, x_i, Y)$ polynomials for the $i$th child proof's $x$ challenge.

use ragu_arithmetic::{CryptoRngCore, Cycle, ff::Field};
use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::Result;

use super::NativeSPrime;
use crate::{Application, Proof, internal::nested, proof::ProofBuilder};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_s_prime<RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<NativeSPrime<C, R>> {
        let native = self.compute_native_s_prime(native_registry, left, right)?;
        self.compute_bridge_s_prime(rng, &native, builder)?;
        Ok(native)
    }

    fn compute_bridge_s_prime<RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        native: &NativeSPrime<C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<()> {
        let bridge_rx = nested::stages::s_prime::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::random(&mut *rng),
            &nested::stages::s_prime::Witness {
                registry_wx0: native.registry_wx0_commitment,
                registry_wx1: native.registry_wx1_commitment,
                stashed_preamble: builder.native_preamble_commitment(),
            },
        )?;
        let bridge_commitment = bridge_rx.commit_to_affine(C::nested_generators(self.params));
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

        let registry_wx0_poly = native_registry.x(x0);
        let registry_wx1_poly = native_registry.x(x1);
        let host_gen = C::host_generators(self.params);
        let [registry_wx0_commitment, registry_wx1_commitment] =
            ragu_arithmetic::batch_to_affine([
                registry_wx0_poly.commit(host_gen),
                registry_wx1_poly.commit(host_gen),
            ]);

        Ok(NativeSPrime {
            registry_wx0_poly,
            registry_wx0_commitment,
            registry_wx1_poly,
            registry_wx1_commitment,
        })
    }
}
