use ragu_circuits::{
    polynomials::{ProductionRank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    pasta::Pasta,
};
use ragu_primitives::allocator::Standard;
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::*;
use crate::{
    ApplicationBuilder,
    step::{Encoded, Index, Step},
};

type TestR = ProductionRank;
const HEADER_SIZE: usize = 4;

fn create_test_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
    let pasta = ragu_pcd::pasta::baked();
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .finalize(pasta)
        .expect("failed to create test application")
}

/// The bootstrap proof, checked to verify first, so that the one field a
/// rejection test then corrupts is the only reason it can be rejected.
fn verifying_proof(
    app: &crate::Application<'static, Pasta, TestR, HEADER_SIZE>,
    rng: &mut StdRng,
) -> Proof<Pasta, TestR> {
    let bootstrap = app.bootstrap_pcd();
    assert!(
        app.verify(&bootstrap, &mut *rng)
            .expect("verify should not error"),
        "the uncorrupted bootstrap proof must verify"
    );
    bootstrap.into_parts().0
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

    let mut proof = verifying_proof(&app, &mut rng);

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

    let mut proof = verifying_proof(&app, &mut rng);

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

    let mut proof = verifying_proof(&app, &mut rng);

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
        .finalize(ragu_pcd::pasta::baked())
        .expect("failed to create test application")
}

/// Corrupts a proof so that it no longer verifies on its own. The edited
/// polynomial's commitment cache is left stale, so a parent fused from the
/// result opens a polynomial that its walked commitment does not match.
fn corrupt(pcd: Pcd<Pasta, TestR, ()>) -> Pcd<Pasta, TestR, ()> {
    let (mut proof, ()) = pcd.into_parts();
    proof
        .native_a_poly
        .add_assign(&sparse::Polynomial::from_coeffs(alloc::vec![
            <Pasta as Cycle>::CircuitField::ONE,
        ]));
    proof.carry(())
}

/// Makes a proof's statement false without editing a polynomial: its stored
/// $\mu$ no longer matches the transcript. A parent reads a child's $\mu$
/// only into its copy of the child's instance, and every commitment cache
/// stays consistent, so a parent fused from the result can be rejected only
/// by enforcing its children's claims.
fn invalidate(pcd: Pcd<Pasta, TestR, ()>) -> Pcd<Pasta, TestR, ()> {
    let (mut proof, ()) = pcd.into_parts();
    proof.mu += <Pasta as Cycle>::CircuitField::ONE;
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
    //
    // The children are invalidated without editing a polynomial. An edit
    // leaves that polynomial's commitment cache stale, and the verifier
    // rejects the parent on that mismatch alone, whether or not the child
    // claims are enforced: the test would pass with the base case open.
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

    let invalid_child = invalidate(valid_unit);
    assert!(
        !app.verify(&invalid_child, StdRng::seed_from_u64(4))
            .expect("invalid child verify should not error"),
        "invalidated child proof should not verify on its own"
    );

    // Fusing the invalidated children through a unit step no longer
    // receives base-case treatment: `UnitStep` declares `()` inputs, not
    // `Dummy`, so the revdot claim is enforced. `fuse` does not check that
    // the trace it assembles is satisfiable, so it still succeeds; the
    // forgery is rejected by the verifier.
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
    let pasta = ragu_pcd::pasta::baked();
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
fn bootstrap_exempts_child_claims_with_consistent_commitments() {
    // Bootstrap may consume invalid child statements. Its PCS openings
    // must still match the children's committed polynomials.
    use crate::{header::Dummy, step::internal::bootstrap::Bootstrap};

    let app = unit_app();
    let mut rng = StdRng::seed_from_u64(71);
    let (unit, ()) = app.seed(&mut rng, UnitSeed, ()).expect("seed");
    let (consistent, ()) = unit.clone().into_parts();
    let (mismatched, ()) = corrupt(unit).into_parts();

    for (proof, expected, case) in [
        (consistent, true, "retyped child"),
        (mismatched, false, "mismatched child commitment"),
    ] {
        // A unit proof cannot attest a Dummy output. Retyping it makes
        // the child claim false without changing any polynomial or point.
        let child = proof.carry::<Dummy>(());
        assert!(
            !app.verify(&child, StdRng::seed_from_u64(74))
                .expect("child verify should not error"),
            "{case}: the child claim must be invalid"
        );

        let (minted, ()) = app
            .fuse(&mut rng, Bootstrap::new(), (), child.clone(), child)
            .expect("fuse");
        assert_eq!(
            app.verify(&minted, StdRng::seed_from_u64(72))
                .expect("verify should not error"),
            expected,
            "{case}: bootstrap exempts child claims while enforcing PCS consistency"
        );

        // A valid minted proof works like the cached bootstrap beneath a
        // seed step; a broken PCS check must still be rejected there.
        let (seeded, ()) = app
            .fuse(&mut rng, UnitSeed, (), minted.clone(), minted)
            .expect("fuse");
        assert_eq!(
            app.verify(&seeded, StdRng::seed_from_u64(73))
                .expect("verify should not error"),
            expected,
            "{case}: the seed step must preserve the bootstrap verdict"
        );
    }
}
