//! Commit to $m(w, x_i, Y)$ polynomials for the child proofs.
//!
//! This creates the [`proof::SPrime`] component of the proof, which commits to
//! the $m(w, x_i, Y)$ polynomials for the $i$th child proof's $x$ challenge.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::Result;
use rand::CryptoRng;

use crate::{Application, Proof, internal::nested, proof};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_s_prime<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<proof::SPrime<C, R>> {
        let native = self.compute_native_s_prime(native_registry, left, right)?;

        let bridge = proof::Bridge::commit(
            self.params,
            nested::stages::s_prime::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::random(&mut *rng),
                &nested::stages::s_prime::Witness {
                    registry_wx0: native.registry_wx0_commitment,
                    registry_wx1: native.registry_wx1_commitment,
                },
            )?,
        );

        Ok(proof::SPrime { native, bridge })
    }

    fn compute_native_s_prime(
        &self,
        native_registry: &RegistryAt<'_, C::CircuitField, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<proof::NativeSPrime<C, R>> {
        let x0 = left.challenges.x;
        let x1 = right.challenges.x;

        let registry_wx0_poly = native_registry.x(x0);
        let registry_wx1_poly = native_registry.x(x1);
        let host_gen = C::host_generators(self.params);
        let [registry_wx0_commitment, registry_wx1_commitment] =
            ragu_arithmetic::batch_to_affine([
                registry_wx0_poly.commit(host_gen),
                registry_wx1_poly.commit(host_gen),
            ]);

        Ok(proof::NativeSPrime {
            registry_wx0_poly,
            registry_wx0_commitment,
            registry_wx1_poly,
            registry_wx1_commitment,
        })
    }
}
