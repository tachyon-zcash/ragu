//! The wire format: byte round trips of production-rank proofs through the
//! application's envelope, the compressed transport path and the serde
//! adapters.
//!
//! `malformed_proofs.rs` and `validation.rs` beside these edit a proof's
//! private fields, so `proof/codec.rs` mounts them into the crate's own
//! tests instead of this target.

#[allow(dead_code)]
#[path = "../nontrivial_support.rs"]
mod nontrivial_support;

mod compressed;
mod format;
#[cfg(feature = "serde")]
mod serde;

/// The envelope ahead of every payload, under envelope version 3.
const ENVELOPE: usize = 28;

type TestProof = ragu_pcd::Proof<nontrivial_support::C, nontrivial_support::R>;
type TestCompressed = ragu_pcd::CompressedProof<nontrivial_support::C>;
