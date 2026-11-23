//! The two proof forms: the uncompressed [`Proof`] a fuse produces, with
//! the [`Pcd`] that carries its data ([`uncompressed`]), and the
//! [`CompressedProof`] compression produces, with its [`CompressedPcd`].

#![allow(dead_code)]

mod compressed;
pub(crate) mod uncompressed;
// These regression suites edit proof fields directly. Keep their sources
// grouped by subject in tests/ and their access confined to the test build.
// Their properties prove tens of wallet-rank proofs each, so they are
// `#[ignore]`d in the platform matrix. Rust CI explicitly replays the
// properties with saved recursion failures, and the scheduled heavy-tests
// run picks up the full suites with `cargo test -- --ignored`.
// The backend, fixture and debug jobs compile a smaller harness for their filters.
#[cfg(test)]
#[path = "../../tests/app_stage.rs"]
mod app_stage_tests;
#[cfg(all(test, not(ragu_pcd_targeted_tests)))]
#[path = "../../tests/base_case_combinations.rs"]
mod base_case_combinations_tests;
#[cfg(all(test, not(ragu_pcd_targeted_tests)))]
#[path = "../../tests/bridge_hash.rs"]
mod bridge_hash_tests;
#[cfg(all(test, not(ragu_pcd_targeted_tests)))]
#[path = "../../tests/compression/blinding.rs"]
mod compress_blinding_tests;
#[cfg(all(test, not(ragu_pcd_targeted_tests)))]
#[path = "../../tests/recursive_bindings.rs"]
mod recursive_binding_tests;
#[cfg(all(test, not(ragu_pcd_targeted_tests)))]
#[path = "../../tests/recursive_boundaries.rs"]
mod recursive_boundary_tests;
#[cfg(test)]
#[path = "../../tests/recursive_propagation.rs"]
pub(crate) mod recursive_propagation_tests;
#[cfg(all(test, not(ragu_pcd_targeted_tests)))]
#[path = "../../tests/rerandomization_hiding.rs"]
mod rerandomization_hiding_tests;

// Keep this beneath `proof` so the shared test helper can inspect private
// `Proof` fields.
#[cfg(test)]
#[path = "../../tests/backend_equivalence/proof.rs"]
mod backend_equivalence;
#[cfg(test)]
#[path = "../../tests/child_commitments.rs"]
mod child_commitment_tests;
// Golden fixtures of the fuse pipeline and the compressed verifier, under
// `tests/fixtures/fuse/`. Mounted here so the digests destructure `Proof`
// exhaustively: a new field fails to compile until the fixture pins it.
#[cfg(test)]
#[path = "../../tests/fuse_fixtures.rs"]
mod fuse_fixture_tests;
#[cfg(all(test, not(ragu_pcd_targeted_tests)))]
#[path = "../../tests/profile_substitution.rs"]
mod profile_substitution_tests;
#[cfg(all(test, not(ragu_pcd_targeted_tests)))]
#[path = "../../tests/proof_shape.rs"]
mod proof_shape_tests;
#[cfg(all(test, not(ragu_pcd_targeted_tests)))]
#[path = "../../tests/verify_rejections.rs"]
mod verify_rejection_tests;

pub use compressed::{CompressedPcd, CompressedProof};
pub use uncompressed::{Pcd, Proof};
pub(crate) use uncompressed::{bridge_alpha_power, builder::ProofBuilder, commitments_match};
