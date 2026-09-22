use ragu_arithmetic::rand::{SeedableRng, rngs::StdRng};
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::Pasta;

use crate::{Application, ApplicationBuilder, Proof};

const HEADER_SIZE: usize = 4;

fn create_test_app() -> Application<'static, Pasta, ProductionRank, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .finalize(Pasta::baked())
        .expect("failed to create test application")
}

/// Reducing the bootstrap proof exercises every vector-to-array conversion
/// against the constants the builder sizes the vectors from.
#[test]
fn bootstrap_proof_reduces_to_minimal() {
    let app = create_test_app();
    let proof = app.bootstrap_pcd().into_parts().0;
    let minimal = proof.into_minimal();
    assert_eq!(minimal.left_header.len(), HEADER_SIZE);
    assert_eq!(minimal.right_header.len(), HEADER_SIZE);
}

/// Expanding a reduced proof must reproduce every field of the original,
/// derived ones included, on both sides of the base case: the bootstrap
/// proof takes it, and the seeded trivial proof, a fuse of two bootstrap
/// proofs, does not.
#[test]
fn expand_restores_reduced_proofs() {
    let app = create_test_app();
    let mut rng = StdRng::seed_from_u64(0);
    let bootstrap = app.bootstrap_pcd().into_parts().0;
    let seeded = app.seeded_trivial_pcd(&mut rng).into_parts().0;
    for (name, proof) in [("bootstrap", bootstrap), ("seeded", seeded)] {
        let expanded: Proof<Pasta, ProductionRank> = app
            .expand(proof.clone().into_minimal())
            .expect("an honest proof expands");
        assert_eq!(
            expanded.test_mismatch(&proof),
            None,
            "the expanded {name} proof differs from the original"
        );
    }
}
