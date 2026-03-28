//! This module provides the [`Application::verify`] method implementation.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;

use core::iter::once;

use crate::{
    Application, Pcd, Proof,
    header::Header,
    internal::claims,
    internal::native::stages::preamble::ProofInputs,
    internal::{native::claims as native_claims, nested::claims as nested_claims},
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Verifies some [`Pcd`] for the provided [`Header`].
    ///
    /// Returns `Ok(true)` if all verification checks pass, `Ok(false)` if
    /// any check fails (e.g., invalid circuit ID, header size mismatch,
    /// corrupted commitments or evaluations), or `Err` if an internal
    /// computation error occurs.
    pub fn verify<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<C, R, H>,
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
            .circuit_in_domain(pcd.proof().application.circuit_id)
        {
            return Ok(false);
        }

        // Validate that the `left_header` and `right_header` lengths match
        // `HEADER_SIZE`. Alternatively, the `Proof` structure could be
        // parameterized on the `HEADER_SIZE`, but this appeared to be simpler.
        if pcd.proof().application.left_header.len() != HEADER_SIZE
            || pcd.proof().application.right_header.len() != HEADER_SIZE
        {
            return Ok(false);
        }

        // Compute unified k(y), unified_bridge k(y), and application k(y).
        let (unified_ky, unified_bridge_ky, application_ky) =
            Emulator::emulate_wireless((pcd.proof(), pcd.data().clone(), y), |dr, witness| {
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
        let source = native::SingleProofSource { proof: pcd.proof() };
        let mut builder = claims::Builder::new(&self.native_registry, y, z);
        native_claims::build(&source, &mut builder)?;

        // Check all native revdot claims.
        let native_revdot_claims = {
            let ky_source = native::SingleProofKySource {
                raw_c: pcd.proof().ab.native.c,
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
            let nested_source = nested::SingleProofSource { proof: pcd.proof() };
            let y_nested = C::ScalarField::random(&mut rng);
            let z_nested = C::ScalarField::random(&mut rng);
            let mut nested_builder =
                claims::Builder::new(&self.nested_registry, y_nested, z_nested);
            nested_claims::build(&nested_source, &mut nested_builder)?;

            let ky_source = nested::SingleProofKySource::<C::ScalarField>::new();
            nested::ky_values(&ky_source)
                .zip(nested_builder.a.iter().zip(nested_builder.b.iter()))
                .all(|(ky, (a, b))| a.revdot(b) == ky)
        };

        // Check polynomial evaluation claim.
        let p_eval_claim =
            pcd.proof().p.native.poly.eval(pcd.proof().challenges.u) == pcd.proof().p.native.v;

        // Check P commitment corresponds to polynomial and blind.
        let p_commitment_claim = pcd
            .proof()
            .p
            .native
            .poly
            .commit_to_affine(C::host_generators(self.params), pcd.proof().p.native.blind)
            == pcd.proof().p.native.commitment;

        // Check registry_xy polynomial evaluation at the sampled w.
        // registry_xy_poly is m(W, x, y) - the registry evaluated at current x, y, free in W.
        let registry_xy_claim = {
            let x = pcd.proof().challenges.x;
            let y = pcd.proof().challenges.y;
            let poly_eval = pcd.proof().query.native.registry_xy_poly.eval(w);
            let expected = self.native_registry.wxy(w, x, y);
            poly_eval == expected
        };

        // Check ab.a and ab.b commitment binding.
        let ab_commitment_claim = {
            let generators = C::host_generators(self.params);
            let a_ok = pcd
                .proof()
                .ab
                .native
                .a_poly
                .commit_to_affine(generators, pcd.proof().ab.native.a_blind)
                == pcd.proof().ab.native.a_commitment;
            let b_ok = pcd
                .proof()
                .ab
                .native
                .b_poly
                .commit_to_affine(generators, pcd.proof().ab.native.b_blind)
                == pcd.proof().ab.native.b_commitment;
            a_ok && b_ok
        };

        // Check f commitment binding.
        let f_commitment_claim = pcd
            .proof()
            .f
            .native
            .poly
            .commit_to_affine(C::host_generators(self.params), pcd.proof().f.native.blind)
            == pcd.proof().f.native.commitment;

        // TODO: Add checks for registry_wx0_poly, registry_wx1_poly, and registry_wy_poly.
        // - registry_wx0/wx1: need child proof x challenges (x₀, x₁) which "disappear" in preamble
        // - registry_wy: interstitial value that will be elided later

        Ok(native_revdot_claims
            && nested_revdot_claims
            && p_eval_claim
            && p_commitment_claim
            && registry_xy_claim
            && ab_commitment_claim
            && f_commitment_claim)
    }
}

mod native {
    use super::*;
    use crate::internal::claims::Source;
    use crate::internal::native::{RxComponent, claims::KySource};

    pub use crate::internal::native::claims::ky_values;

    pub struct SingleProofSource<'rx, C: Cycle, R: Rank> {
        pub proof: &'rx Proof<C, R>,
    }

    impl<'rx, C: Cycle, R: Rank> Source for SingleProofSource<'rx, C, R> {
        type RxComponent = RxComponent;
        type Rx = &'rx sparse::Polynomial<C::CircuitField, R>;
        type AppCircuitId = CircuitIndex;

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            core::iter::once(self.proof.native_rx(component))
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
    use crate::internal::claims::Source;
    use crate::internal::nested::{RxIndex, claims::KySource};

    pub use crate::internal::nested::claims::ky_values;

    /// Source for nested field rx polynomials for single-proof verification.
    pub struct SingleProofSource<'rx, C: Cycle, R: Rank> {
        pub proof: &'rx Proof<C, R>,
    }

    impl<'rx, C: Cycle, R: Rank> Source for SingleProofSource<'rx, C, R> {
        type RxComponent = RxIndex;
        type Rx = &'rx sparse::Polynomial<C::ScalarField, R>;
        type AppCircuitId = ();

        fn rx(&self, component: RxIndex) -> impl Iterator<Item = Self::Rx> {
            core::iter::once(&self.proof[component])
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
    use ragu_arithmetic::FixedGenerators;
    use ragu_circuits::polynomials::ProductionRank;
    use ragu_pasta::Pasta;
    use ragu_primitives::{GadgetExt, Point};
    use rand::{SeedableRng, rngs::StdRng};

    type CF = <Pasta as ragu_arithmetic::Cycle>::CircuitField;
    type HostCurve = <Pasta as ragu_arithmetic::Cycle>::HostCurve;
    type NestedCurve = <Pasta as ragu_arithmetic::Cycle>::NestedCurve;
    type TestR = ProductionRank;
    const HEADER_SIZE: usize = 4;

    fn fake_nested_point() -> NestedCurve {
        *Pasta::nested_generators(Pasta::baked()).h()
    }

    fn fake_host_point() -> HostCurve {
        *Pasta::host_generators(Pasta::baked()).h()
    }

    fn create_test_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
        let pasta = Pasta::baked();
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .finalize(pasta)
            .expect("failed to create test application")
    }

    fn create_seeded_proof(
        seed: u64,
    ) -> (
        crate::Application<'static, Pasta, TestR, HEADER_SIZE>,
        crate::proof::Proof<Pasta, TestR>,
    ) {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(seed);
        let (pcd, _aux) = app
            .seed(&mut rng, Trivial::new(), ())
            .expect("seeded proof should not fail");
        let (proof, _data) = pcd.into_parts();
        (app, proof)
    }

    #[test]
    fn verify_accepts_seeded_proof() {
        let (app, proof) = create_seeded_proof(42);
        let mut rng = StdRng::seed_from_u64(9999);
        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(result, "a freshly seeded proof must be accepted");
    }

    #[test]
    fn verify_transcript_replay_challenges_match() {
        let pasta = Pasta::baked();
        let (_app, proof) = create_seeded_proof(7);

        let challenges = &proof.challenges;

        let dr = &mut ragu_core::drivers::emulator::Emulator::execute();
        let poseidon = Pasta::circuit_poseidon(pasta);
        let mut t = crate::internal::transcript::Transcript::new(dr, poseidon, crate::RAGU_TAG)
            .expect("transcript init should not fail");

        let preamble_commit =
            Point::<_, NestedCurve>::constant(dr, proof.preamble.bridge.commitment)
                .expect("point constant should not fail");
        preamble_commit
            .write(dr, &mut t)
            .expect("write should not fail");
        let w = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();

        let s_prime_commit = Point::<_, NestedCurve>::constant(dr, proof.s_prime.bridge.commitment)
            .expect("point constant should not fail");
        s_prime_commit
            .write(dr, &mut t)
            .expect("write should not fail");
        let y = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();
        let z = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();

        let inner_error_commit =
            Point::<_, NestedCurve>::constant(dr, proof.inner_error.bridge.commitment)
                .expect("point constant should not fail");
        inner_error_commit
            .write(dr, &mut t)
            .expect("write should not fail");
        let mu = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();
        let nu = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();

        let outer_error_commit =
            Point::<_, NestedCurve>::constant(dr, proof.outer_error.bridge.commitment)
                .expect("point constant should not fail");
        outer_error_commit
            .write(dr, &mut t)
            .expect("write should not fail");
        let mu_prime = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();
        let nu_prime = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();

        let ab_commit = Point::<_, NestedCurve>::constant(dr, proof.ab.bridge.commitment)
            .expect("point constant should not fail");
        ab_commit.write(dr, &mut t).expect("write should not fail");
        let x = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();

        let query_commit = Point::<_, NestedCurve>::constant(dr, proof.query.bridge.commitment)
            .expect("point constant should not fail");
        query_commit
            .write(dr, &mut t)
            .expect("write should not fail");
        let alpha = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();

        let f_commit = Point::<_, NestedCurve>::constant(dr, proof.f.bridge.commitment)
            .expect("point constant should not fail");
        f_commit.write(dr, &mut t).expect("write should not fail");
        let u = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();

        let eval_commit = Point::<_, NestedCurve>::constant(dr, proof.eval.bridge.commitment)
            .expect("point constant should not fail");
        eval_commit
            .write(dr, &mut t)
            .expect("write should not fail");
        let pre_beta = *t
            .challenge(dr)
            .expect("challenge should not fail")
            .value()
            .take();

        assert_eq!(w, challenges.w, "w mismatch");
        assert_eq!(y, challenges.y, "y mismatch");
        assert_eq!(z, challenges.z, "z mismatch");
        assert_eq!(mu, challenges.mu, "mu mismatch");
        assert_eq!(nu, challenges.nu, "nu mismatch");
        assert_eq!(mu_prime, challenges.mu_prime, "mu_prime mismatch");
        assert_eq!(nu_prime, challenges.nu_prime, "nu_prime mismatch");
        assert_eq!(x, challenges.x, "x mismatch");
        assert_eq!(alpha, challenges.alpha, "alpha mismatch");
        assert_eq!(u, challenges.u, "u mismatch");
        assert_eq!(pre_beta, challenges.pre_beta, "pre_beta mismatch");
    }

    macro_rules! seeded_rejects {
        ($test_name:ident, $seed:expr, |$proof:ident| $corrupt:expr) => {
            #[test]
            fn $test_name() {
                let (app, mut $proof) = create_seeded_proof($seed);
                $corrupt;
                let mut rng = StdRng::seed_from_u64(99999);
                let pcd = $proof.carry::<()>(());
                let result = app.verify(&pcd, &mut rng).expect("verify should not error");
                assert!(
                    !result,
                    concat!(stringify!($test_name), ": verifier must reject")
                );
            }
        };
    }

    seeded_rejects!(rejects_corrupt_w_challenge, 1, |proof| {
        proof.challenges.w = CF::random(&mut StdRng::seed_from_u64(777))
    });

    seeded_rejects!(rejects_corrupt_y_challenge, 2, |proof| {
        proof.challenges.y = CF::random(&mut StdRng::seed_from_u64(778))
    });

    seeded_rejects!(rejects_corrupt_z_challenge, 3, |proof| {
        proof.challenges.z = CF::random(&mut StdRng::seed_from_u64(779))
    });

    seeded_rejects!(rejects_corrupt_mu_challenge, 4, |proof| {
        proof.challenges.mu = CF::random(&mut StdRng::seed_from_u64(780))
    });

    seeded_rejects!(rejects_corrupt_nu_challenge, 5, |proof| {
        proof.challenges.nu = CF::random(&mut StdRng::seed_from_u64(781))
    });

    seeded_rejects!(rejects_corrupt_mu_prime_challenge, 6, |proof| {
        proof.challenges.mu_prime = CF::random(&mut StdRng::seed_from_u64(782))
    });

    seeded_rejects!(rejects_corrupt_nu_prime_challenge, 7, |proof| {
        proof.challenges.nu_prime = CF::random(&mut StdRng::seed_from_u64(783))
    });

    seeded_rejects!(rejects_corrupt_x_challenge, 8, |proof| {
        proof.challenges.x = CF::random(&mut StdRng::seed_from_u64(784))
    });

    seeded_rejects!(rejects_corrupt_alpha_challenge, 9, |proof| {
        proof.challenges.alpha = CF::random(&mut StdRng::seed_from_u64(785))
    });

    seeded_rejects!(rejects_corrupt_u_challenge, 10, |proof| {
        proof.challenges.u = CF::random(&mut StdRng::seed_from_u64(786))
    });

    seeded_rejects!(rejects_corrupt_pre_beta_challenge, 11, |proof| {
        proof.challenges.pre_beta = CF::random(&mut StdRng::seed_from_u64(787))
    });

    seeded_rejects!(rejects_corrupt_p_blind, 12, |proof| {
        proof.p.native.blind = CF::from(999u64)
    });

    seeded_rejects!(rejects_corrupt_p_eval, 13, |proof| {
        proof.p.native.v = CF::from(12345u64)
    });

    seeded_rejects!(rejects_corrupt_ab_c, 14, |proof| {
        proof.ab.native.c = CF::from(99999u64)
    });

    seeded_rejects!(rejects_corrupt_ab_a_blind, 15, |proof| {
        proof.ab.native.a_blind = CF::from(11111u64)
    });

    seeded_rejects!(rejects_corrupt_ab_b_blind, 16, |proof| {
        proof.ab.native.b_blind = CF::from(22222u64)
    });

    seeded_rejects!(rejects_corrupt_ab_a_commitment, 17, |proof| {
        proof.ab.native.a_commitment = fake_host_point()
    });

    seeded_rejects!(rejects_corrupt_ab_b_commitment, 18, |proof| {
        proof.ab.native.b_commitment = fake_host_point()
    });

    seeded_rejects!(rejects_corrupt_f_blind, 19, |proof| {
        proof.f.native.blind = CF::from(33333u64)
    });

    seeded_rejects!(rejects_corrupt_f_commitment, 20, |proof| {
        proof.f.native.commitment = fake_host_point()
    });

    seeded_rejects!(rejects_corrupt_preamble_bridge_commitment, 21, |proof| {
        proof.preamble.bridge.commitment = fake_nested_point()
    });

    seeded_rejects!(rejects_corrupt_s_prime_bridge_commitment, 22, |proof| {
        proof.s_prime.bridge.commitment = fake_nested_point()
    });

    seeded_rejects!(rejects_corrupt_inner_error_bridge_commitment, 23, |proof| {
        proof.inner_error.bridge.commitment = fake_nested_point()
    });

    seeded_rejects!(rejects_corrupt_outer_error_bridge_commitment, 24, |proof| {
        proof.outer_error.bridge.commitment = fake_nested_point()
    });

    seeded_rejects!(rejects_corrupt_ab_bridge_commitment, 25, |proof| {
        proof.ab.bridge.commitment = fake_nested_point()
    });

    seeded_rejects!(rejects_corrupt_query_bridge_commitment, 26, |proof| {
        proof.query.bridge.commitment = fake_nested_point()
    });

    seeded_rejects!(rejects_corrupt_f_bridge_commitment, 27, |proof| {
        proof.f.bridge.commitment = fake_nested_point()
    });

    seeded_rejects!(rejects_corrupt_eval_bridge_commitment, 28, |proof| {
        proof.eval.bridge.commitment = fake_nested_point()
    });

    seeded_rejects!(rejects_corrupt_preamble_native_rx, 29, |proof| {
        proof.preamble.native.rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_inner_error_native_rx, 30, |proof| {
        proof.inner_error.native.rx_triple.rx =
            ragu_circuits::polynomials::structured::Polynomial::random(&mut StdRng::seed_from_u64(
                8888,
            ))
    });

    seeded_rejects!(rejects_corrupt_outer_error_native_rx, 31, |proof| {
        proof.outer_error.native.rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_query_native_rx, 32, |proof| {
        proof.query.native.rx_triple.rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_eval_native_rx, 33, |proof| {
        proof.eval.native.rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_application_rx, 34, |proof| {
        proof.application.rx_triple.rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_hashes_1_rx, 35, |proof| {
        proof.circuits.hashes_1.rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_hashes_2_rx, 36, |proof| {
        proof.circuits.hashes_2.rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_inner_collapse_rx, 37, |proof| {
        proof.circuits.inner_collapse.rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_outer_collapse_rx, 38, |proof| {
        proof.circuits.outer_collapse.rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_compute_v_rx, 39, |proof| {
        proof.circuits.compute_v.rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_registry_xy_poly, 40, |proof| {
        proof.query.native.registry_xy_poly =
            ragu_circuits::polynomials::unstructured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_p_poly, 41, |proof| {
        proof.p.native.poly = ragu_circuits::polynomials::unstructured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_nested_endoscalar_rx, 42, |proof| {
        proof.p.nested.endoscalar_rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });

    seeded_rejects!(rejects_corrupt_nested_points_rx, 43, |proof| {
        proof.p.nested.points_rx = ragu_circuits::polynomials::structured::Polynomial::new()
    });
}
