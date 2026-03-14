//! Commit to $m(w, x_i, Y)$ polynomials for the child proofs.
//!
//! This creates the [`proof::SPrime`] component of the proof, which commits to
//! the $m(w, x_i, Y)$ polynomials for the $i$th child proof's $x$ challenge.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{CommittedPolynomial, Rank},
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

        let wx0_poly = registry_at_w.wx(x0);
        let wx1_poly = registry_at_w.wx(x1);
        let generators = C::host_generators(self.params);
        let blind_0 = C::CircuitField::random(rng);
        let blind_1 = C::CircuitField::random(rng);
        let [commit_0, commit_1] = ragu_arithmetic::batch_to_affine([
            wx0_poly.commit(generators, blind_0),
            wx1_poly.commit(generators, blind_1),
        ]);
        let registry_wx0 = CommittedPolynomial::from_parts(wx0_poly, blind_0, commit_0);
        let registry_wx1 = CommittedPolynomial::from_parts(wx1_poly, blind_1, commit_1);

        let nested_s_prime_witness = nested::stages::s_prime::Witness {
            registry_wx0: registry_wx0.commitment(),
            registry_wx1: registry_wx1.commitment(),
        };
        let nested_s_prime_poly =
            nested::stages::s_prime::Stage::<C::HostCurve, R>::rx(&nested_s_prime_witness)?;
        let blind = C::ScalarField::random(rng);
        let commitment =
            nested_s_prime_poly.commit_to_affine(C::nested_generators(self.params), blind);
        let nested_s_prime_rx =
            CommittedPolynomial::from_parts(nested_s_prime_poly, blind, commitment);

        Ok(proof::SPrime {
            registry_wx0,
            registry_wx1,
            nested_s_prime_rx,
        })
    }
}
