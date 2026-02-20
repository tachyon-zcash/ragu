//! This module provides the [`Application::verify`] method implementation.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, structured},
    registry::CircuitIndex,
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;

use core::iter::once;

use crate::{
    Application, Pcd, Proof, circuits::native::stages::preamble::ProofInputs, components::claims,
    header::Header,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Verifies some [`Pcd`] for the provided [`Header`].
    pub fn verify<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<'_, C, R, H>,
        mut rng: RNG,
    ) -> Result<bool> {
        // Sample verification challenges w, y, and z.
        let w = C::CircuitField::random(&mut rng);
        let y = C::CircuitField::random(&mut rng);
        let z = C::CircuitField::random(&mut rng);

        // Validate that the application circuit_id is within the registry domain.
        // (Internal circuit IDs are constants and don't need this check.)
        if !self
            .native_registry
            .circuit_in_domain(pcd.proof.application.circuit_id)
        {
            return Ok(false);
        }

        // Validate that the `left_header` and `right_header` lengths match
        // `HEADER_SIZE`. Alternatively, the `Proof` structure could be
        // parameterized on the `HEADER_SIZE`, but this appeared to be simpler.
        if pcd.proof.application.left_header.len() != HEADER_SIZE
            || pcd.proof.application.right_header.len() != HEADER_SIZE
        {
            return Ok(false);
        }

        // Compute unified k(y), unified_bridge k(y), and application k(y).
        let (unified_ky, unified_bridge_ky, application_ky) =
            Emulator::emulate_wireless((&pcd.proof, pcd.data.clone(), y), |dr, witness| {
                let (proof, data, y) = witness.cast();
                let y = Element::alloc(dr, y)?;
                let proof_inputs =
                    ProofInputs::<_, C, HEADER_SIZE>::alloc_for_verify::<R, H>(dr, proof, data)?;

                let (unified_ky, unified_bridge_ky) = proof_inputs.unified_ky_values(dr, &y)?;
                let unified_ky = *unified_ky.value().take();
                let unified_bridge_ky = *unified_bridge_ky.value().take();
                let application_ky = *proof_inputs.application_ky(dr, &y)?.value().take();

                Ok((unified_ky, unified_bridge_ky, application_ky))
            })?;

        // Build a and b polynomials for each revdot claim.
        let source = native::SingleProofSource { proof: &pcd.proof };
        let mut builder = claims::Builder::new(&self.native_registry, y, z);
        claims::native::build(&source, &mut builder)?;

        // Check all native revdot claims.
        let native_revdot_claims = {
            let ky_source = native::SingleProofKySource {
                raw_c: pcd.proof.ab.c,
                application_ky,
                unified_bridge_ky,
                unified_ky,
            };

            native::ky_values(&ky_source)
                .zip(builder.a.iter().zip(builder.b.iter()))
                .all(|(ky, (a, b))| a.revdot(b) == ky)
        };

        // Check all nested revdot claims.
        let nested_revdot_claims = {
            let nested_source = nested::SingleProofSource { proof: &pcd.proof };
            let y_nested = C::ScalarField::random(&mut rng);
            let z_nested = C::ScalarField::random(&mut rng);
            let mut nested_builder =
                claims::Builder::new(&self.nested_registry, y_nested, z_nested);
            claims::nested::build(&nested_source, &mut nested_builder)?;

            let ky_source = nested::SingleProofKySource::<C::ScalarField>::new();
            nested::ky_values(&ky_source)
                .zip(nested_builder.a.iter().zip(nested_builder.b.iter()))
                .all(|(ky, (a, b))| a.revdot(b) == ky)
        };

        // Check polynomial evaluation claim.
        let p_eval_claim = pcd.proof.p.poly.eval(pcd.proof.challenges.u) == pcd.proof.p.v;

        // Check P commitment corresponds to polynomial and blind.
        let p_commitment_claim = pcd
            .proof
            .p
            .poly
            .commit(C::host_generators(self.params), pcd.proof.p.blind)
            == pcd.proof.p.commitment;

        // Check A/B commitments correspond to polynomials and blinds.
        let ab_commitment_claim = {
            let a_ok = pcd
                .proof
                .ab
                .a_poly
                .commit(C::host_generators(self.params), pcd.proof.ab.a_blind)
                == pcd.proof.ab.a_commitment;
            let b_ok = pcd
                .proof
                .ab
                .b_poly
                .commit(C::host_generators(self.params), pcd.proof.ab.b_blind)
                == pcd.proof.ab.b_commitment;
            a_ok && b_ok
        };

        // Check F commitment corresponds to polynomial and blind.
        let f_commitment_claim = pcd
            .proof
            .f
            .poly
            .commit(C::host_generators(self.params), pcd.proof.f.blind)
            == pcd.proof.f.commitment;

        // Check registry_xy polynomial evaluation at the sampled w.
        // registry_xy_poly is m(W, x, y) - the registry evaluated at current x, y, free in W.
        let registry_xy_claim = {
            let x = pcd.proof.challenges.x;
            let y = pcd.proof.challenges.y;
            let poly_eval = pcd.proof.query.registry_xy_poly.eval(w);
            let expected = self.native_registry.wxy(w, x, y);
            poly_eval == expected
        };

        // TODO: Add checks for registry_wx0_poly, registry_wx1_poly, and registry_wy_poly.
        // - registry_wx0/wx1: need child proof x challenges (x₀, x₁) which "disappear" in preamble
        // - registry_wy: interstitial value that will be elided later

        Ok(native_revdot_claims
            && nested_revdot_claims
            && p_eval_claim
            && p_commitment_claim
            && ab_commitment_claim
            && f_commitment_claim
            && registry_xy_claim)
    }
}

mod native {
    use super::*;
    use crate::components::claims::{
        Source,
        native::{KySource, RxComponent},
    };

    pub use crate::components::claims::native::ky_values;

    pub struct SingleProofSource<'rx, C: Cycle, R: Rank> {
        pub proof: &'rx Proof<C, R>,
    }

    impl<'rx, C: Cycle, R: Rank> Source for SingleProofSource<'rx, C, R> {
        type RxComponent = RxComponent;
        type Rx = &'rx structured::Polynomial<C::CircuitField, R>;
        type AppCircuitId = CircuitIndex;

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            use RxComponent::*;
            let poly = match component {
                AbA => &self.proof.ab.a_poly,
                AbB => &self.proof.ab.b_poly,
                Application => &self.proof.application.rx,
                Hashes1 => &self.proof.circuits.hashes_1_rx,
                Hashes2 => &self.proof.circuits.hashes_2_rx,
                PartialCollapse => &self.proof.circuits.partial_collapse_rx,
                FullCollapse => &self.proof.circuits.full_collapse_rx,
                ComputeV => &self.proof.circuits.compute_v_rx,
                Preamble => &self.proof.preamble.native_rx,
                ErrorM => &self.proof.error_m.native_rx,
                ErrorN => &self.proof.error_n.native_rx,
                Query => &self.proof.query.native_rx,
                Eval => &self.proof.eval.native_rx,
            };
            core::iter::once(poly)
        }

        fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
            core::iter::once(self.proof.application.circuit_id)
        }
    }

    /// Source for k(y) values for single-proof verification.
    pub struct SingleProofKySource<F> {
        pub raw_c: F,
        pub application_ky: F,
        pub unified_bridge_ky: F,
        pub unified_ky: F,
    }

    impl<F: Field> KySource for SingleProofKySource<F> {
        type Ky = F;

        fn raw_c(&self) -> impl Iterator<Item = F> {
            once(self.raw_c)
        }

        fn application_ky(&self) -> impl Iterator<Item = F> {
            once(self.application_ky)
        }

        fn unified_bridge_ky(&self) -> impl Iterator<Item = F> {
            once(self.unified_bridge_ky)
        }

        fn unified_ky(&self) -> impl Iterator<Item = F> + Clone {
            once(self.unified_ky)
        }

        fn zero(&self) -> F {
            F::ZERO
        }
    }
}

mod nested {
    use super::*;
    use crate::components::claims::{
        Source,
        nested::{KySource, RxComponent},
    };

    pub use crate::components::claims::nested::ky_values;

    /// Source for nested field rx polynomials for single-proof verification.
    pub struct SingleProofSource<'rx, C: Cycle, R: Rank> {
        pub proof: &'rx Proof<C, R>,
    }

    impl<'rx, C: Cycle, R: Rank> Source for SingleProofSource<'rx, C, R> {
        type RxComponent = RxComponent;
        type Rx = &'rx structured::Polynomial<C::ScalarField, R>;
        type AppCircuitId = ();

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            use RxComponent::*;
            let poly = match component {
                EndoscalarStage => &self.proof.p.endoscalar_rx,
                PointsStage => &self.proof.p.points_rx,
                EndoscalingStep(step) => &self.proof.p.step_rxs[step as usize], // TODO: bounds
            };
            core::iter::once(poly)
        }

        fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
            core::iter::empty()
        }
    }

    /// Source for k(y) values for nested single-proof verification.
    pub struct SingleProofKySource<F>(core::marker::PhantomData<F>);

    impl<F> SingleProofKySource<F> {
        pub fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<F: Field> KySource for SingleProofKySource<F> {
        type Ky = F;

        fn one(&self) -> F {
            F::ONE
        }

        fn zero(&self) -> F {
            F::ZERO
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApplicationBuilder;
    use crate::step::internal::trivial::Trivial;
    use ff::Field;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_circuits::{polynomials::ProductionRank, registry::CircuitIndex};
    use ragu_pasta::Pasta;
    use ragu_primitives::{GadgetExt, Point, poseidon::Sponge};
    use rand::{SeedableRng, rngs::StdRng};

    type TestR = ProductionRank;
    const HEADER_SIZE: usize = 4;

    type CF = <Pasta as Cycle>::CircuitField;
    type SF = <Pasta as Cycle>::ScalarField;
    type NestedCurve = <Pasta as Cycle>::NestedCurve;

    fn create_test_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
        let pasta = Pasta::baked();
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .finalize(pasta)
            .expect("failed to create test application")
    }

    fn create_seeded_proof(
        app: &crate::Application<'_, Pasta, TestR, HEADER_SIZE>,
    ) -> crate::Proof<Pasta, TestR> {
        let mut rng = StdRng::seed_from_u64(42);
        let (proof, _) = app
            .seed(&mut rng, Trivial::new(), ())
            .expect("seed should not fail");
        proof
    }

    fn replay_fiat_shamir_challenges(
        app: &crate::Application<'_, Pasta, TestR, HEADER_SIZE>,
        proof: &crate::Proof<Pasta, TestR>,
    ) -> Result<crate::proof::Challenges<Pasta>> {
        let mut dr = Emulator::execute();
        let mut transcript = Sponge::new(&mut dr, Pasta::circuit_poseidon(app.params));

        Point::constant(&mut dr, proof.preamble.nested_commitment)?
            .write(&mut dr, &mut transcript)?;
        let w = transcript.squeeze(&mut dr)?;

        Point::constant(&mut dr, proof.s_prime.nested_s_prime_commitment)?
            .write(&mut dr, &mut transcript)?;
        let y = transcript.squeeze(&mut dr)?;
        let z = transcript.squeeze(&mut dr)?;

        Point::constant(&mut dr, proof.error_m.nested_commitment)?
            .write(&mut dr, &mut transcript)?;
        let mu = transcript.squeeze(&mut dr)?;
        let nu = transcript.squeeze(&mut dr)?;

        Point::constant(&mut dr, proof.error_n.nested_commitment)?
            .write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.squeeze(&mut dr)?;
        let nu_prime = transcript.squeeze(&mut dr)?;

        Point::constant(&mut dr, proof.ab.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let x = transcript.squeeze(&mut dr)?;

        Point::constant(&mut dr, proof.query.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let alpha = transcript.squeeze(&mut dr)?;

        Point::constant(&mut dr, proof.f.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let u = transcript.squeeze(&mut dr)?;

        Point::constant(&mut dr, proof.eval.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let pre_beta = transcript.squeeze(&mut dr)?;

        Ok(crate::proof::Challenges {
            w: *w.value().take(),
            y: *y.value().take(),
            z: *z.value().take(),
            mu: *mu.value().take(),
            nu: *nu.value().take(),
            mu_prime: *mu_prime.value().take(),
            nu_prime: *nu_prime.value().take(),
            x: *x.value().take(),
            alpha: *alpha.value().take(),
            u: *u.value().take(),
            pre_beta: *pre_beta.value().take(),
        })
    }

    fn assert_seeded_rejects(corrupt: impl FnOnce(&mut crate::Proof<Pasta, TestR>)) {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);
        let mut proof = create_seeded_proof(&app);
        corrupt(&mut proof);
        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(!result);
    }

    macro_rules! seeded_rejects {
        ($name:ident, |$proof:ident| $corruption:expr) => {
            #[test]
            fn $name() {
                assert_seeded_rejects(|$proof| {
                    $corruption;
                });
            }
        };
    }

    #[test]
    fn seeded_proof_verifies_without_corruption() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);
        let proof = create_seeded_proof(&app);
        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(result, "seeded proof should verify without corruption");
    }

    #[test]
    fn seeded_transcript_replay_matches_stored_challenges() {
        let app = create_test_app();
        let proof = create_seeded_proof(&app);
        let replayed =
            replay_fiat_shamir_challenges(&app, &proof).expect("challenge replay should succeed");

        assert_eq!(proof.challenges.w, replayed.w);
        assert_eq!(proof.challenges.y, replayed.y);
        assert_eq!(proof.challenges.z, replayed.z);
        assert_eq!(proof.challenges.mu, replayed.mu);
        assert_eq!(proof.challenges.nu, replayed.nu);
        assert_eq!(proof.challenges.mu_prime, replayed.mu_prime);
        assert_eq!(proof.challenges.nu_prime, replayed.nu_prime);
        assert_eq!(proof.challenges.x, replayed.x);
        assert_eq!(proof.challenges.alpha, replayed.alpha);
        assert_eq!(proof.challenges.u, replayed.u);
        assert_eq!(proof.challenges.pre_beta, replayed.pre_beta);
    }

    #[test]
    fn seeded_transcript_replay_detects_corrupted_absorbed_commitment() {
        let app = create_test_app();
        let mut proof = create_seeded_proof(&app);
        proof.query.nested_commitment = NestedCurve::generator();

        let replayed =
            replay_fiat_shamir_challenges(&app, &proof).expect("challenge replay should succeed");
        assert!(
            proof.challenges.alpha != replayed.alpha
                || proof.challenges.u != replayed.u
                || proof.challenges.pre_beta != replayed.pre_beta
        );
    }

    seeded_rejects!(seeded_rejects_invalid_circuit_id, |proof| {
        proof.application.circuit_id = CircuitIndex::new(u32::MAX as usize)
    });
    seeded_rejects!(seeded_rejects_wrong_left_header_size, |proof| {
        proof.application.left_header = alloc::vec![CF::ZERO; HEADER_SIZE + 1]
    });
    seeded_rejects!(seeded_rejects_wrong_right_header_size, |proof| {
        proof.application.right_header = alloc::vec![CF::ZERO; HEADER_SIZE - 1]
    });

    // Fiat-Shamir challenge corruptions

    seeded_rejects!(seeded_rejects_corrupted_challenge_w, |proof| {
        proof.challenges.w = CF::from(777u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_challenge_y, |proof| {
        proof.challenges.y = CF::from(777u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_challenge_z, |proof| {
        proof.challenges.z = CF::from(777u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_challenge_mu, |proof| {
        proof.challenges.mu = CF::from(777u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_challenge_nu, |proof| {
        proof.challenges.nu = CF::from(777u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_challenge_mu_prime, |proof| {
        proof.challenges.mu_prime = CF::from(777u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_challenge_nu_prime, |proof| {
        proof.challenges.nu_prime = CF::from(777u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_challenge_x, |proof| {
        proof.challenges.x = CF::from(777u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_challenge_alpha, |proof| {
        proof.challenges.alpha = CF::from(777u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_challenge_u, |proof| {
        proof.challenges.u = CF::from(777u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_challenge_pre_beta, |proof| {
        proof.challenges.pre_beta = CF::from(777u64)
    });

    // Nested commitment corruptions

    seeded_rejects!(
        seeded_rejects_corrupted_preamble_nested_commitment,
        |proof| { proof.preamble.nested_commitment = NestedCurve::generator() }
    );
    seeded_rejects!(
        seeded_rejects_corrupted_s_prime_nested_commitment,
        |proof| { proof.s_prime.nested_s_prime_commitment = NestedCurve::generator() }
    );
    seeded_rejects!(
        seeded_rejects_corrupted_error_n_nested_commitment,
        |proof| { proof.error_n.nested_commitment = NestedCurve::generator() }
    );
    seeded_rejects!(
        seeded_rejects_corrupted_error_m_nested_commitment,
        |proof| { proof.error_m.nested_commitment = NestedCurve::generator() }
    );
    seeded_rejects!(seeded_rejects_corrupted_ab_nested_commitment, |proof| {
        proof.ab.nested_commitment = NestedCurve::generator()
    });
    seeded_rejects!(seeded_rejects_corrupted_query_nested_commitment, |proof| {
        proof.query.nested_commitment = NestedCurve::generator()
    });
    seeded_rejects!(seeded_rejects_corrupted_f_nested_commitment, |proof| {
        proof.f.nested_commitment = NestedCurve::generator()
    });
    seeded_rejects!(seeded_rejects_corrupted_eval_nested_commitment, |proof| {
        proof.eval.nested_commitment = NestedCurve::generator()
    });

    // Scalar corruptions

    seeded_rejects!(seeded_rejects_corrupted_p_blind, |proof| {
        proof.p.blind = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_p_v, |proof| {
        proof.p.v = CF::from(12345u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_ab_c, |proof| {
        proof.ab.c = CF::from(99999u64)
    });

    // Native rx polynomial corruptions

    seeded_rejects!(seeded_rejects_corrupted_ab_a_poly_rx, |proof| {
        *proof.ab.a_poly.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_ab_b_poly_rx, |proof| {
        *proof.ab.b_poly.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_application_rx, |proof| {
        *proof.application.rx.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_hashes_1_rx, |proof| {
        *proof.circuits.hashes_1_rx.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_hashes_2_rx, |proof| {
        *proof.circuits.hashes_2_rx.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_partial_collapse_rx, |proof| {
        *proof.circuits.partial_collapse_rx.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_full_collapse_rx, |proof| {
        *proof.circuits.full_collapse_rx.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_compute_v_rx, |proof| {
        *proof.circuits.compute_v_rx.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_preamble_native_rx, |proof| {
        *proof.preamble.native_rx.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_error_m_native_rx, |proof| {
        *proof.error_m.native_rx.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_error_n_native_rx, |proof| {
        *proof.error_n.native_rx.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_query_native_rx, |proof| {
        *proof.query.native_rx.constant_term() = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_eval_native_rx, |proof| {
        *proof.eval.native_rx.constant_term() = CF::from(999u64)
    });

    // Nested rx polynomial corruptions

    seeded_rejects!(seeded_rejects_corrupted_p_endoscalar_rx, |proof| {
        *proof.p.endoscalar_rx.constant_term() = SF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_p_points_rx, |proof| {
        *proof.p.points_rx.constant_term() = SF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_p_step_rx_0, |proof| {
        *proof.p.step_rxs[0].constant_term() = SF::from(999u64)
    });

    // Unstructured polynomial corruptions

    seeded_rejects!(seeded_rejects_corrupted_p_poly, |proof| {
        proof.p.poly[0] = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_f_poly, |proof| {
        proof.f.poly[0] = CF::from(999u64)
    });
    seeded_rejects!(seeded_rejects_corrupted_query_registry_xy_poly, |proof| {
        proof.query.registry_xy_poly[0] = CF::from(999u64)
    });
}
