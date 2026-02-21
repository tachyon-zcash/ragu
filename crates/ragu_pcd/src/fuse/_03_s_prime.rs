//! Commit to $m(w, x_i, Y)$ polynomials for the child proofs.
//!
//! This creates the [`proof::SPrime`] component of the proof, which commits to
//! the $m(w, x_i, Y)$ polynomials for the $i$th child proof's $x$ challenge.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, registry::RegistryAt, staging::StageExt};
use ragu_core::Result;
use rand::CryptoRng;

use crate::{Application, Proof, circuits::nested, proof};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_s_prime<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_at_w: &RegistryAt<'_, C::CircuitField, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<proof::SPrime<C, R>> {
        let x0 = left.challenges.x;
        let x1 = right.challenges.x;

        let native_registry_wx0_poly = registry_at_w.wx(x0);
        let native_registry_wx0_blind = C::CircuitField::random(&mut *rng);
        let native_registry_wx0_commitment = native_registry_wx0_poly
            .commit(C::host_generators(self.params), native_registry_wx0_blind);
        let native_registry_wx1_poly = registry_at_w.wx(x1);
        let native_registry_wx1_blind = C::CircuitField::random(&mut *rng);
        let native_registry_wx1_commitment = native_registry_wx1_poly
            .commit(C::host_generators(self.params), native_registry_wx1_blind);

        let nested_s_prime_witness = nested::stages::s_prime::Witness {
            registry_wx0: native_registry_wx0_commitment,
            registry_wx1: native_registry_wx1_commitment,
        };
        let nested_s_prime_rx =
            nested::stages::s_prime::Stage::<C::HostCurve, R>::rx(&nested_s_prime_witness)?;
        let nested_s_prime_blind = C::ScalarField::random(&mut *rng);
        let nested_s_prime_commitment =
            nested_s_prime_rx.commit(C::nested_generators(self.params), nested_s_prime_blind);

        Ok(proof::SPrime {
            registry_wx0_poly: native_registry_wx0_poly,
            registry_wx0_blind: native_registry_wx0_blind,
            registry_wx0_commitment: native_registry_wx0_commitment,
            registry_wx1_poly: native_registry_wx1_poly,
            registry_wx1_blind: native_registry_wx1_blind,
            registry_wx1_commitment: native_registry_wx1_commitment,
            nested_s_prime_rx,
            nested_s_prime_blind,
            nested_s_prime_commitment,
        })
    }
}
