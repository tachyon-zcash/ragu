//! This module provides the [`Application::verify`] method implementation.

use core::iter::once;

use ragu_arithmetic::{Cycle, ff::Field, rand::CryptoRng};
use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::Element;

use crate::{
    Application, Pcd, Proof, SelectableBackend,
    header::Header,
    internal::{
        claims,
        native::{RxComponent, claims as native_claims, stages::preamble::ProofInputs},
        nested::claims as nested_claims,
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

            let ky_source = nested::SingleProofKySource::<C::ScalarField>::new();
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

        // TODO: Add checks for registry_wx0_poly, registry_wx1_poly, and registry_wy_poly.
        // - registry_wx0/wx1: need child proof x challenges (x₀, x₁) which "disappear" in preamble
        // - registry_wy: interstitial value that will be elided later

        Ok(native_revdot_claims && nested_revdot_claims && registry_xy_claim)
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
        nested::{RxIndex, claims::KySource},
    };

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
    use ragu_arithmetic::{
        ff::Field,
        rand::{SeedableRng, rngs::StdRng},
    };
    use ragu_circuits::{
        polynomials::{ProductionRank, sparse},
        registry::CircuitIndex,
    };
    use ragu_core::drivers::{Driver, DriverValue};
    use ragu_pasta::Pasta;
    use ragu_primitives::allocator::Standard;

    use super::*;
    use crate::{
        ApplicationBuilder,
        step::{Encoded, Index, Step},
    };

    type TestR = ProductionRank;
    const HEADER_SIZE: usize = 4;

    fn create_test_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
        let pasta = Pasta::baked();
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .finalize(pasta)
            .expect("failed to create test application")
    }

    /// A seed step with no predicate that outputs `()`.
    struct UnitSeed;

    impl Step<Pasta> for UnitSeed {
        const INDEX: Index = Index::new(0);

        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = ();
        type Right = ();
        type Output = ();

        fn witness<
            'dr,
            'source: 'dr,
            D: Driver<'dr, F = <Pasta as Cycle>::CircuitField>,
            const HS: usize,
        >(
            &self,
            _: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
            _: DriverValue<D, ()>,
            _: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, ()>,
            DriverValue<D, ()>,
        )>
        where
            Self: 'dr,
        {
            Ok((
                (
                    Encoded::from_gadget(()),
                    Encoded::from_gadget(()),
                    Encoded::from_gadget(()),
                ),
                D::unit(),
                D::unit(),
            ))
        }
    }

    /// A step with no predicate that fuses two `Pcd<()>` children into `()`.
    struct UnitStep;

    impl Step<Pasta> for UnitStep {
        const INDEX: Index = Index::new(1);

        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = ();
        type Right = ();
        type Output = ();

        fn witness<
            'dr,
            'source: 'dr,
            D: Driver<'dr, F = <Pasta as Cycle>::CircuitField>,
            const HS: usize,
        >(
            &self,
            dr: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
            left: DriverValue<D, ()>,
            right: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, ()>,
            DriverValue<D, ()>,
        )>
        where
            Self: 'dr,
        {
            let allocator = &mut Standard::new();
            Ok((
                (
                    Encoded::new(dr, allocator, left)?,
                    Encoded::new(dr, allocator, right)?,
                    Encoded::from_gadget(()),
                ),
                D::unit(),
                D::unit(),
            ))
        }
    }

    #[test]
    fn verify_rejects_invalid_circuit_id() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);

        // Create a synthesized dummy proof
        let mut proof = app.dummy_proof();

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

        // Create a synthesized dummy proof
        let mut proof = app.dummy_proof();

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

        // Create a synthesized dummy proof
        let mut proof = app.dummy_proof();

        // Corrupt right_header to have wrong size
        proof.right_header = alloc::vec![<Pasta as Cycle>::CircuitField::ZERO; HEADER_SIZE - 1];

        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(!result, "verify should reject wrong right_header size");
    }

    /// Builds an application with a unit seed step to seed and a unit step
    /// fusing two `Pcd<()>` children.
    fn unit_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .register(UnitSeed)
            .expect("register seed step")
            .register(UnitStep)
            .expect("register fuse step")
            .finalize(Pasta::baked())
            .expect("failed to create test application")
    }

    /// Corrupts a proof so that it no longer verifies on its own.
    fn corrupt(pcd: Pcd<Pasta, TestR, ()>) -> Pcd<Pasta, TestR, ()> {
        let (mut proof, ()) = pcd.into_parts();
        proof
            .native_a_poly
            .add_assign(&sparse::Polynomial::from_coeffs(alloc::vec![
                <Pasta as Cycle>::CircuitField::ONE,
            ]));
        proof.carry(())
    }

    #[test]
    fn base_case_confined_to_bootstrap_rejects_invalid_unit_children() {
        // Regression test for the base-case over-broadness closed by confining
        // the base case to the internal `Bootstrap` step (see `is_base_case`).
        //
        // Previously any fuse whose step declared `()` inputs was treated as a
        // base case, so the child revdot claim was skipped and a corrupted
        // `Pcd<()>` slipped through. Now only a step declaring `Dummy`
        // inputs triggers it, so an application step's children always have
        // their claims enforced and the forgery is rejected.
        let app = unit_app();
        let mut rng = StdRng::seed_from_u64(1);

        // Genuine seed still works: it fuses against the bootstrap proof, so an
        // honestly produced unit proof verifies.
        let (valid_unit, ()) = app.seed(&mut rng, UnitSeed, ()).expect("seed");
        assert!(
            app.verify(&valid_unit, StdRng::seed_from_u64(2))
                .expect("valid child verify should not error"),
            "honestly produced unit proof should still verify"
        );

        // Positive control: the same fuse over honest children verifies, so a
        // rejection below is attributable to the children rather than to the
        // step itself.
        let (honest_parent, ()) = app
            .fuse(
                &mut rng,
                UnitStep,
                (),
                valid_unit.clone(),
                valid_unit.clone(),
            )
            .expect("honest fuse");
        assert!(
            app.verify(&honest_parent, StdRng::seed_from_u64(3))
                .expect("honest parent verify should not error"),
            "a parent fused from valid children must verify"
        );

        let invalid_child = corrupt(valid_unit);
        assert!(
            !app.verify(&invalid_child, StdRng::seed_from_u64(4))
                .expect("invalid child verify should not error"),
            "corrupted child proof should not verify on its own"
        );

        // Fusing the corrupted children through a unit step no longer receives
        // base-case treatment: `UnitStep` declares `()` inputs, not `Dummy`,
        // so the revdot claim is enforced. `fuse` does not check that the trace
        // it assembles is satisfiable, so it still succeeds; the forgery is
        // rejected by the verifier.
        let (parent, ()) = app
            .fuse(&mut rng, UnitStep, (), invalid_child.clone(), invalid_child)
            .expect("fuse assembles a proof regardless of satisfiability");
        assert!(
            !app.verify(&parent, StdRng::seed_from_u64(5))
                .expect("parent verify should not error"),
            "a parent fused from invalid children must not verify"
        );
    }

    #[test]
    fn forged_dummy_headers_cannot_trigger_the_base_case() {
        // Base-case detection reads the suffix slot of the headers the current
        // step declared for its children (see `is_dummy_input`). Those headers
        // live in three places that an honest prover keeps equal: the step's
        // application circuit bakes them in as constants, the proof stores
        // them, and the preamble stage witnesses them. A prover who forges any
        // one of the three to the reserved `Dummy` suffix — trying to make the
        // circuit skip the child revdot claim — breaks that agreement, and the
        // consumer's claims pin it:
        //
        // * `hashes_1` publishes the witnessed headers, which the verifier's
        //   `unified_bridge_ky` compares against the proof's stored headers; and
        // * the verifier's `application_ky` pins the stored headers to the
        //   constants the step's application circuit emitted.
        //
        // Forging the stored headers, as here, diverges from both, so the proof
        // must be rejected whether or not its children are valid.
        let app = unit_app();
        let forged = {
            let mut header = alloc::vec![<Pasta as Cycle>::CircuitField::ZERO; HEADER_SIZE];
            header[HEADER_SIZE - 1] =
                <Pasta as Cycle>::CircuitField::from(crate::header::Suffix::internal(2).get());
            header
        };

        let mut rng = StdRng::seed_from_u64(11);
        let (valid_unit, ()) = app.seed(&mut rng, UnitSeed, ()).expect("seed");
        let invalid_unit = corrupt(valid_unit.clone());

        for (child, child_desc) in [(valid_unit, "valid"), (invalid_unit, "corrupted")] {
            let (parent, ()) = app
                .fuse(&mut rng, UnitStep, (), child.clone(), child)
                .expect("fuse assembles a proof regardless of satisfiability");

            let (mut proof, ()) = parent.into_parts();
            proof.left_header.clone_from(&forged);
            proof.right_header.clone_from(&forged);
            let parent = proof.carry::<()>(());

            assert!(
                !app.verify(&parent, StdRng::seed_from_u64(12))
                    .expect("parent verify should not error"),
                "forged dummy suffixes over {child_desc} children must not verify"
            );
        }
    }

    #[test]
    fn rerandomize_unit_proof_still_verifies() {
        // A `Pcd<()>` used to trip the over-broad base case during
        // rerandomization (both fuse inputs carried a `()` output), silently
        // dropping its revdot claim. With the base case confined to `Bootstrap`
        // and `Rerandomize`'s suffix wire constrained away from `Dummy`,
        // an honest rerandomize takes the normal claim-enforcing path — and
        // must still preserve verification.
        let pasta = Pasta::baked();
        let app = ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .register(UnitSeed)
            .expect("register seed step")
            .finalize(pasta)
            .expect("failed to create test application");

        let mut rng = StdRng::seed_from_u64(7);
        let (unit, ()) = app.seed(&mut rng, UnitSeed, ()).expect("seed");
        assert!(
            app.verify(&unit, StdRng::seed_from_u64(8))
                .expect("verify should not error"),
            "seeded unit proof should verify"
        );

        let rerandomized = app.rerandomize(unit, &mut rng).expect("rerandomize");
        assert!(
            app.verify(&rerandomized, StdRng::seed_from_u64(9))
                .expect("verify should not error"),
            "rerandomized unit proof should still verify through the enforced path"
        );
    }

    #[test]
    fn bootstrap_proof_verifies_as_unit() {
        let app = unit_app();
        let t = app.bootstrap_pcd();
        assert!(
            app.verify(&t, StdRng::seed_from_u64(51))
                .expect("verify should not error"),
            "the bootstrap proof must verify as ()"
        );
    }

    #[test]
    fn bootstrap_step_ignores_its_children() {
        // The bootstrap step is the base case: it verifies nothing about its
        // children, so running it over corrupted proofs still yields a valid
        // `()` proof, indistinguishable in power from the real one — any
        // prover can mint one. This is by design (the bootstrap proof attests
        // nothing) and is documented; this test keeps that fact honest.
        use crate::{header::Dummy, step::internal::bootstrap::Bootstrap};

        let app = unit_app();
        let mut rng = StdRng::seed_from_u64(71);
        let (unit, ()) = app.seed(&mut rng, UnitSeed, ()).expect("seed");
        let (bad, ()) = corrupt(unit).into_parts();
        let bad = bad.carry::<Dummy>(());

        let (minted, ()) = app
            .fuse(&mut rng, Bootstrap::new(), (), bad.clone(), bad)
            .expect("fuse");
        assert!(
            app.verify(&minted, StdRng::seed_from_u64(72))
                .expect("verify should not error"),
            "the bootstrap step over corrupted children still yields a verifying unit proof"
        );
        // …and that minted proof works exactly like the real bootstrap proof
        // beneath a seed step, attesting nothing more.
        let (seeded, ()) = app
            .fuse(&mut rng, UnitSeed, (), minted.clone(), minted)
            .expect("fuse");
        assert!(
            app.verify(&seeded, StdRng::seed_from_u64(73))
                .expect("verify should not error"),
            "a seed step over a minted bootstrap proof verifies, like one over the cached one"
        );
    }
}
