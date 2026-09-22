use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::Pasta;

use crate::ApplicationBuilder;

const HEADER_SIZE: usize = 4;

/// Reducing the bootstrap proof exercises every vector-to-array conversion
/// against the constants the builder sizes the vectors from.
#[test]
fn bootstrap_proof_reduces_to_minimal() {
    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .finalize(Pasta::baked())
        .expect("failed to create test application");
    let proof = app.bootstrap_pcd().into_parts().0;
    let minimal = proof.into_minimal();
    assert_eq!(minimal.left_header.len(), HEADER_SIZE);
    assert_eq!(minimal.right_header.len(), HEADER_SIZE);
}
