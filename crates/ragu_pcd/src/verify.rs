//! This module provides the [`Application::verify`] method implementation.

use core::iter::once;

use ragu_arithmetic::{Cycle, ff::Field, rand::CryptoRng};
use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::StageExt,
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::Element;

use crate::{
    Application, Pcd, Proof, SelectableBackend,
    header::Header,
    internal::{
        claims,
        native::{RxComponent, claims as native_claims, stages::preamble::ProofInputs},
        nested::{
            RxComponent as NestedRxComponent, challenge as nested_challenge,
            claims as nested_claims,
            stages::{beta as nested_beta, challenges as nested_challenges},
            unified as nested_unified,
        },
    },
};

/// The backend whose kernels [`Application::verify`] consults for the selected
/// backend `B`. Every computational call in this module goes through this
/// alias, never through `B` directly, so which code path decides acceptance is
/// fixed by the sealed [`SelectableBackend::Verifier`] mapping.
type Verifier<B> = <B as SelectableBackend>::Verifier;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Verifies some [`Pcd`] for the provided [`Header`].
    ///
    /// Returns `Ok(true)` if all verification checks pass, `Ok(false)` if
    /// any check fails (e.g., invalid circuit ID, header size mismatch,
    /// corrupted commitments or evaluations), or `Err` if an internal
    /// computation error occurs.
    ///
    /// The computational kernels used here are those of the sealed
    /// [`SelectableBackend::Verifier`] of the selected backend: the reference
    /// kernels for `ReferenceBackend` and `AcceleratedProver`, the accelerated
    /// ones for `AcceleratedBackend`. Applications choose between them but
    /// cannot supply the implementation that controls the acceptance decision.
    pub fn verify<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<C, R, H>,
        mut rng: RNG,
    ) -> Result<bool> {
        // Sample verification challenges w, y, and z.
        let w = C::CircuitField::random(&mut rng);
        let y = C::CircuitField::random(&mut rng);
        let z = C::CircuitField::random(&mut rng);

        // The proof's circuit_id selects which wiring polynomial the verifier
        // checks against, and every domain point carries one, so an in-domain id
        // is always well defined. It need not name a circuit: the domain also
        // holds registered bonding polynomials and, at unassigned points, the
        // zero polynomial, which is itself a bonding polynomial. Letting the
        // prover choose freely among them is safe because this check expects a
        // circuit and so fixes k_0 = 1, which no bonding polynomial (s(X, 0) =
        // 0) can satisfy. Rejecting out-of-domain ids keeps the selection inside
        // that argument, rather than an evaluation of the registry interpolation
        // at an arbitrary point.
        // (Internal circuit IDs are constants and don't need this check.)
        if !self
            .native_registry
            .circuit_in_domain(pcd.proof().circuit_id())
        {
            return Ok(false);
        }

        // Validate that the `left_header` and `right_header` lengths match
        // `HEADER_SIZE`. Alternatively, the `Proof` structure could be
        // parameterized on the `HEADER_SIZE`, but this appeared to be simpler.
        if pcd.proof().left_header().len() != HEADER_SIZE
            || pcd.proof().right_header().len() != HEADER_SIZE
        {
            return Ok(false);
        }

        // Compute unified k(y), unified_bridge k(y), and application k(y).
        let (unified_ky, unified_bridge_ky, application_ky) =
            Emulator::emulate_wireless((pcd.proof(), pcd.data().clone(), y), |dr, witness| {
                let (proof, data, y) = witness.cast();
                let y = Element::alloc(dr, &mut (), y)?;
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
        let mut builder =
            claims::Builder::<_, C::CircuitField, R, Verifier<B>>::new(&self.native_registry, y, z);
        native_claims::build(&source, &mut builder)?;

        // Check all native revdot claims.
        let native_revdot_claims = {
            let ky_source = native::SingleProofKySource {
                // NOTE: `raw_c` is now computed as `revdot(a, b)` rather
                // than stored in the proof, so this claim is tautological
                // in the verifier. It remains meaningful inside the circuit
                // where `c` is an independently allocated witness element.
                raw_c: Verifier::<B>::sparse_revdot(
                    &pcd.proof()[RxComponent::AbA],
                    &pcd.proof()[RxComponent::AbB],
                ),
                application_ky,
                unified_bridge_ky,
                unified_ky,
            };

            native::ky_values(&ky_source)
                .zip(builder.a.iter().zip(builder.b.iter()))
                .all(|(ky, (a, b))| Verifier::<B>::sparse_revdot(a, b) == ky)
        };

        // Check all nested revdot claims.
        let nested_revdot_claims = {
            let nested_source = nested::SingleProofSource { proof: pcd.proof() };
            let y_nested = C::ScalarField::random(&mut rng);
            let z_nested = C::ScalarField::random(&mut rng);
            let mut nested_builder = claims::Builder::<_, C::ScalarField, R, Verifier<B>>::new(
                &self.nested_registry,
                y_nested,
                z_nested,
            );
            nested_claims::build(&nested_source, &mut nested_builder)?;

            // The nested unified instance's k(y), at the sampled nested y,
            // for the instance circuits' claims: the instance is read off
            // the proof (c_n and v_n derived from its polynomials), and the
            // claims bind it to those circuits' traces.
            let unified_ky = Emulator::emulate_wireless(
                (pcd.proof().nested_instance()?, y_nested),
                |dr, witness| {
                    let (instance, y) = witness.cast();
                    let y = Element::alloc(dr, &mut (), y)?;
                    let output = nested_unified::Output::<_, C::HostCurve>::alloc(
                        dr,
                        &mut (),
                        instance.as_ref(),
                    )?;
                    Ok(*output.ky(dr, &y)?.value().take())
                },
            )?;
            let ky_source = nested::SingleProofKySource {
                // As with the native `raw_c` above, the nested accumulator's
                // claim is tautological here: its k(y) is derived from the
                // very polynomials the claim checks. It remains meaningful
                // inside the collapse circuit, where c_n is an instance
                // wire the fold is checked against.
                raw_c: Verifier::<B>::sparse_revdot(
                    &pcd.proof()[NestedRxComponent::AbA],
                    &pcd.proof()[NestedRxComponent::AbB],
                ),
                unified_ky,
            };
            nested::ky_values(&ky_source)
                .zip(nested_builder.a.iter().zip(nested_builder.b.iter()))
                .all(|(ky, (a, b))| Verifier::<B>::sparse_revdot(a, b) == ky)
        };

        // Check registry_xy polynomial evaluation at the sampled w.
        // registry_xy_poly is m(W, x, y) - the registry evaluated at current x, y, free in W.
        let registry_xy_claim = {
            let x = pcd.proof().x();
            let y = pcd.proof().y();
            let poly_eval = Verifier::<B>::sparse_eval(pcd.proof().native_registry_xy_poly(), w);
            let expected = Verifier::<B>::registry_wxy(&self.native_registry, w, x, y);
            poly_eval == expected
        };

        // The nested counterpart: the proof's nested registry_xy polynomial is
        // m_n(W, x_n, y_n) at the nested counterparts of its x and y, checked
        // at a sampled w.
        let nested_registry_xy_claim = {
            let w = C::ScalarField::random(&mut rng);
            let x = nested_challenge::<C>(pcd.proof().x())?;
            let y = nested_challenge::<C>(pcd.proof().y())?;
            let poly_eval = Verifier::<B>::sparse_eval(pcd.proof().nested_registry_xy_poly(), w);
            let expected = Verifier::<B>::registry_wxy(&self.nested_registry, w, x, y);
            poly_eval == expected
        };

        // The nested challenge stage is the unblinded stage of the lifts of
        // this proof's challenges: recompute it and compare. In-circuit, the
        // binding circuits tie its commitment to the transcript challenges.
        let nested_challenges_claim = {
            let lifts = pcd.proof().challenges().lifts::<C>()?;
            let (challenge_lifts, beta_lift) = lifts.split_at(nested_challenges::NUM);
            let expected_challenges = nested_challenges::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ZERO,
                &nested_challenges::Witness::new(
                    challenge_lifts.try_into().expect("NUM challenge lifts"),
                    pcd.proof().is_base_case::<HEADER_SIZE>(),
                ),
            )?;
            let expected_beta = nested_beta::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ZERO,
                nested_beta::Witness { lift: beta_lift[0] },
            )?;
            pcd.proof()
                .nested_challenges_rx()
                .iter_coeffs()
                .eq(expected_challenges.iter_coeffs())
                && pcd
                    .proof()
                    .nested_beta_rx()
                    .iter_coeffs()
                    .eq(expected_beta.iter_coeffs())
        };

        // TODO: Add checks for registry_wx0_poly, registry_wx1_poly, and registry_wy_poly.
        // - registry_wx0/wx1: need child proof x challenges (x₀, x₁) which "disappear" in preamble
        // - registry_wy: interstitial value that will be elided later

        Ok(native_revdot_claims
            && nested_revdot_claims
            && registry_xy_claim
            && nested_registry_xy_claim
            && nested_challenges_claim)
    }
}

mod native {
    use super::*;
    pub use crate::internal::native::claims::ky_values;
    use crate::internal::{
        claims::Source,
        native::{RxComponent, claims::KySource},
    };

    pub struct SingleProofSource<'rx, C: Cycle, R: Rank> {
        pub proof: &'rx Proof<C, R>,
    }

    impl<'rx, C: Cycle, R: Rank> Source for SingleProofSource<'rx, C, R> {
        type RxComponent = RxComponent;
        type Rx = &'rx sparse::Polynomial<C::CircuitField, R>;
        type AppCircuitId = CircuitIndex;

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            core::iter::once(&self.proof[component])
        }

        fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
            core::iter::once(self.proof.circuit_id())
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

        fn ones(&self) -> impl Iterator<Item = F> + Clone {
            once(F::ONE)
        }

        fn zero(&self) -> F {
            F::ZERO
        }
    }
}

mod nested {
    use super::*;
    pub use crate::internal::nested::claims::ky_values;
    use crate::internal::{
        claims::Source,
        nested::{RxComponent, claims::KySource},
    };

    /// Source for nested field polynomials for single-proof verification.
    pub struct SingleProofSource<'rx, C: Cycle, R: Rank> {
        pub proof: &'rx Proof<C, R>,
    }

    impl<'rx, C: Cycle, R: Rank> Source for SingleProofSource<'rx, C, R> {
        type RxComponent = RxComponent;
        type Rx = &'rx sparse::Polynomial<C::ScalarField, R>;
        type AppCircuitId = ();

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            core::iter::once(&self.proof[component])
        }

        fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
            core::iter::empty()
        }
    }

    /// Source for k(y) values for nested single-proof verification.
    pub struct SingleProofKySource<F> {
        pub raw_c: F,
        pub unified_ky: F,
    }

    impl<F: Field> KySource for SingleProofKySource<F> {
        type Ky = F;

        fn raw_c(&self) -> impl Iterator<Item = F> {
            once(self.raw_c)
        }

        fn ones(&self) -> impl Iterator<Item = F> + Clone {
            once(F::ONE)
        }

        fn unified_ky(&self) -> impl Iterator<Item = F> + Clone {
            once(self.unified_ky)
        }

        fn zero(&self) -> F {
            F::ZERO
        }
    }
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::{
        ff::Field,
        rand::{SeedableRng, rngs::StdRng},
    };
    use ragu_circuits::{polynomials::ProductionRank, registry::CircuitIndex};
    use ragu_pasta::Pasta;

    use super::*;
    use crate::ApplicationBuilder;

    type TestR = ProductionRank;
    const HEADER_SIZE: usize = 4;

    fn create_test_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
        let pasta = Pasta::baked();
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .finalize(pasta)
            .expect("failed to create test application")
    }

    #[test]
    fn verify_rejects_invalid_circuit_id() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);

        // Create a valid trivial proof
        let mut proof = app.trivial_proof();

        // Corrupt the circuit_id to be outside the registry domain
        proof.circuit_id = CircuitIndex::new(u32::MAX as usize);

        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(!result, "verify should reject invalid circuit_id");
    }

    #[test]
    fn verify_rejects_wrong_left_header_size() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);

        // Create a valid trivial proof
        let mut proof = app.trivial_proof();

        // Corrupt left_header to have wrong size
        proof.left_header = alloc::vec![<Pasta as Cycle>::CircuitField::ZERO; HEADER_SIZE + 1];

        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(!result, "verify should reject wrong left_header size");
    }

    #[test]
    fn verify_rejects_wrong_right_header_size() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);

        // Create a valid trivial proof
        let mut proof = app.trivial_proof();

        // Corrupt right_header to have wrong size
        proof.right_header = alloc::vec![<Pasta as Cycle>::CircuitField::ZERO; HEADER_SIZE - 1];

        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(!result, "verify should reject wrong right_header size");
    }
}
