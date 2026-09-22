use ragu_arithmetic::{
    ff::Field,
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};

use crate::{Application, ApplicationBuilder, Proof};

const HEADER_SIZE: usize = 4;

fn create_test_app() -> Application<'static, Pasta, ProductionRank, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .finalize(Pasta::baked())
        .expect("failed to create test application")
}

/// Stripping the bootstrap proof exercises every vector-to-array conversion
/// against the constants the builder sizes the vectors from.
#[test]
fn bootstrap_proof_strips() {
    let app = create_test_app();
    let proof = app.bootstrap_pcd().into_parts().0;
    let stripped = proof.strip();
    assert_eq!(stripped.left_header.len(), HEADER_SIZE);
    assert_eq!(stripped.right_header.len(), HEADER_SIZE);
}

/// Expanding a stripped proof must reproduce every field of the original,
/// derived ones included, on both sides of the base case: the bootstrap
/// proof takes it, and the seeded trivial proof, a fuse of two bootstrap
/// proofs, does not.
#[test]
fn expand_restores_stripped_proofs() {
    let app = create_test_app();
    let mut rng = StdRng::seed_from_u64(0);
    let bootstrap = app.bootstrap_pcd().into_parts().0;
    let seeded = app.seeded_trivial_pcd(&mut rng).into_parts().0;
    for (name, proof) in [("bootstrap", bootstrap), ("seeded", seeded)] {
        let expanded: Proof<Pasta, ProductionRank> = app
            .expand(proof.clone().strip())
            .expect("an honest proof expands");
        assert_eq!(
            expanded.test_mismatch(&proof),
            None,
            "the expanded {name} proof differs from the original"
        );
    }
}

fn verify(
    app: &Application<'static, Pasta, ProductionRank, HEADER_SIZE>,
    proof: &Proof<Pasta, ProductionRank>,
    rng: &mut StdRng,
) -> bool {
    app.verify(&proof.clone().carry::<()>(()), &mut *rng)
        .expect("verify must not error")
}

fn strip_and_verify(
    app: &Application<'static, Pasta, ProductionRank, HEADER_SIZE>,
    proof: &Proof<Pasta, ProductionRank>,
    rng: &mut StdRng,
) -> bool {
    app.verify(&proof.clone().strip().carry::<()>(()), &mut *rng)
        .expect("verify must not error")
}

/// The stripped form verifies exactly when the working form does, and a
/// derived field carries nothing: editing one rejects the working form but
/// stripping drops the edit, while a primary edit survives it and both
/// forms reject. A stripped proof of the wrong shape is rejected outright.
#[test]
fn verify_agrees_on_both_forms() {
    let app = create_test_app();
    let mut rng = StdRng::seed_from_u64(2);
    let (proof, ()) = app.bootstrap_pcd().into_parts();
    assert!(verify(&app, &proof, &mut rng));
    assert!(strip_and_verify(&app, &proof, &mut rng));

    let mut challenge_edited = proof.clone();
    challenge_edited.w += Fp::ONE;
    assert!(!verify(&app, &challenge_edited, &mut rng));
    assert!(strip_and_verify(&app, &challenge_edited, &mut rng));

    let mut header_edited = proof.clone();
    header_edited.left_header[0] += Fp::ONE;
    assert!(!verify(&app, &header_edited, &mut rng));
    assert!(!strip_and_verify(&app, &header_edited, &mut rng));

    let mut resized = proof.strip();
    resized.left_header.push(Fp::ZERO);
    assert!(
        !app.verify(&resized.carry::<()>(()), &mut rng)
            .expect("verify must not error")
    );
}
