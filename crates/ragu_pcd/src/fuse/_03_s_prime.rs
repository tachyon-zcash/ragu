//! Commit to $m(w, x_i, Y)$ polynomials for the child proofs.
//!
//! This creates the [`proof::SPrime`] component of the proof, which commits to
//! the $m(w, x_i, Y)$ polynomials for the $i$th child proof's $x$ challenge.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Committable, Rank},
    registry::RegistryAt,
    staging::StageExt,
};
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

        let registry_wx0 = registry_at_w
            .wx(x0)
            .commit(C::host_generators(self.params), rng);
        let registry_wx1 = registry_at_w
            .wx(x1)
            .commit(C::host_generators(self.params), rng);

        let nested_s_prime_witness = nested::stages::s_prime::Witness {
            registry_wx0: registry_wx0.commitment(),
            registry_wx1: registry_wx1.commitment(),
        };
        let nested_s_prime_rx =
            nested::stages::s_prime::Stage::<C::HostCurve, R>::rx(&nested_s_prime_witness)?
                .commit(C::nested_generators(self.params), rng);

        Ok(proof::SPrime {
            registry_wx0,
            registry_wx1,
            nested_s_prime_rx,
        })
    }
}
