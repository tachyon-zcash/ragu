//! Proofs and proof-carrying data, in both forms.
//!
//! [`Proof`] and [`Pcd`] carry a fuse's polynomials;
//! [`Application::compress`](crate::Application::compress) reduces them to
//! [`CompressedProof`] and [`CompressedPcd`]. Their byte encodings are in
//! [`wire`](crate::wire).

#![allow(dead_code)]

mod compressed;
mod uncompressed;

pub(crate) use compressed::Messages;
pub use compressed::{CompressedPcd, CompressedProof};
pub(crate) use uncompressed::{Cached, bridge_alpha_power, commitments_match};
pub use uncompressed::{Pcd, Proof};

// These regression suites edit proof fields directly. Keep their sources
// grouped by subject in tests/ and their access confined to the test build.
// Their properties prove tens of production-rank proofs each, so they are
// `#[ignore]`d in the platform matrix. Rust CI explicitly replays the
// properties with saved recursion failures, and the scheduled heavy-tests
// run picks up the full suites with `cargo test -- --ignored`.
#[cfg(test)]
#[path = "../../tests/app_stage.rs"]
mod app_stage_tests;
#[cfg(test)]
#[path = "../../tests/base_case_combinations.rs"]
mod base_case_combinations_tests;
#[cfg(test)]
#[path = "../../tests/bridge_hash.rs"]
mod bridge_hash_tests;
#[cfg(test)]
#[path = "../../tests/compress_blinding.rs"]
mod compress_blinding_tests;
#[cfg(test)]
#[path = "../../tests/recursive_bindings.rs"]
mod recursive_binding_tests;
#[cfg(test)]
#[path = "../../tests/recursive_boundaries.rs"]
mod recursive_boundary_tests;
#[cfg(test)]
#[path = "../../tests/recursive_propagation.rs"]
pub(crate) mod recursive_propagation_tests;

// Keep this beneath `proof` so the shared test helper can inspect private
// `Proof` fields.
#[cfg(test)]
#[path = "../../tests/backend_equivalence.rs"]
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
#[cfg(test)]
#[path = "../../tests/profile_substitution.rs"]
mod profile_substitution_tests;
#[cfg(test)]
#[path = "../../tests/proof_shape.rs"]
mod proof_shape_tests;
#[cfg(test)]
#[path = "../../tests/verify_rejections.rs"]
mod verify_rejection_tests;
// Mutable component access for the corruption vocabulary (see
// `crate::fuzzing`). Its source lives with the rest of the fuzzing surface in
// `tests/fuzzing/`, but it is mounted here, as a child of `proof`, so it can
// reach the private `Cached` fields without loosening them. The file gates
// itself behind `unstable-fuzzing` with an inner `#![cfg]`, so no feature
// attribute appears here.
// TODO: Revisit this layout; for now, it keeps the fuzzing surface in one
// directory without loosening `Proof`'s privacy or adding a feature
// attribute here.
#[path = "../../tests/fuzzing/access.rs"]
mod access;
