//! Proof-carrying data framework for Ragu.
//!
//! This crate provides the top-level API for building PCD applications:
//!
//! - [`ApplicationBuilder`] / [`Application`] — configure, build, then
//!   [`seed`](Application::seed), [`fuse`](Application::fuse) and
//!   [`rerandomize`](Application::rerandomize) proofs, and
//!   [`compress`](Application::compress) them to check the result with
//!   [`verify_compressed`](Application::verify_compressed).
//!   `Application::verify_uncompressed` is a test oracle behind the
//!   `test-utils` feature.
//! - [`step::Step`] — the trait that defines computation nodes (transitions).
//! - [`header::Header`] — the trait that defines succinct state representations.
//! - [`Proof`] / [`Pcd`] — the proof and proof-carrying-data structures.
//! - [`CompressedProof`] / [`CompressedPcd`] — their compressed forms.
//! - [`profile`] — the proof shapes: the standard profile wallets prove in,
//!   and the aggregator profile that will carry decompression.
//! - [`pasta`] — Ragu's fixed generators, derived and embedded at build time
//!   with the `baked` feature.
//! - [`Proof::to_bytes`] / [`Proof::from_bytes`] and their [`CompressedProof`]
//!   counterparts — versioned byte encodings for storing and transporting
//!   proofs.
//!
//! For each payload kind, decoding checks envelope, schema and protocol
//! versions, bounds the declared dimensions, then checks the exact length
//! fixed by the profile, rank and header size before decoding proof data. The
//! caller selects the expected application and cryptographic parameters
//! through its deployment or consensus rules. With the `serde` feature,
//! [`Proof`] and [`CompressedProof`] implement `Serialize` and `Deserialize`
//! directly, as the byte string `to_bytes` writes, envelope included.
//! A receiver compresses a decoded proof and accepts it on
//! [`verify_compressed`](Application::verify_compressed). See [`wire`] for
//! the envelope layout, version rules and input size limits, including the
//! limits callers must apply to Serde backends before they allocate buffers.
//!
//! Internally, each subprotocol keeps its prover and verifier side by side:
//! `fuse` constructs proofs (`fuse::prover`), constrains them recursively
//! (`fuse::circuits`) and holds the reference decider, a test oracle
//! (`fuse::decider`); `compress` compresses proofs and decides final
//! acceptance; `ipa` opens their commitments. The definitions they share live
//! in `protocol`. The crate's `ARCHITECTURE.md` maps each entry point to its
//! files and gives a reading order for review.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

#[cfg(not(feature = "alloc"))]
compile_error!("`ragu_pcd` requires the `alloc` feature to be enabled.");
extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

mod application;
mod backend;
mod compress;
mod fuse;
// The fuzzing surface. Its source lives in `tests/fuzzing/` with the crate's
// other test code. It gates itself behind `unstable-fuzzing` with an inner
// `#![cfg]` and hides itself from the docs, so no feature attribute appears
// here.
#[path = "../tests/fuzzing/mod.rs"]
pub mod fuzzing;
pub mod header;
pub mod ipa;
mod multicore;
pub mod pasta;
pub mod profile;
mod proof;
mod protocol;
pub mod step;
// The uncompressed verifier. Gates itself behind `test-utils` (or the crate's
// own tests) with an inner `#![cfg]`, like `fuzzing`.
mod test_support;
pub mod wire;

#[cfg(test)]
#[path = "../tests/setup_binding.rs"]
mod setup_binding_tests;

#[cfg(test)]
#[path = "../tests/profile_layout.rs"]
mod profile_layout_tests;

#[cfg(test)]
#[path = "../tests/online_fq_oracles.rs"]
mod online_fq_oracles_tests;

#[cfg(test)]
#[path = "../tests/decompress_statement.rs"]
mod decompress_statement_tests;

#[cfg(all(test, feature = "unstable-fuzzing"))]
#[path = "../tests/profile_corruption.rs"]
mod profile_corruption_tests;

pub use crate::{
    application::{Application, ApplicationBuilder},
    backend::SelectableBackend,
    proof::{CompressedPcd, CompressedProof, Pcd, Proof},
};

/// Domain separation tag for the Ragu PCD protocol.
///
/// This version is independent of crate releases. Bump it for incompatible changes
/// to the transcript schedule, encodings, challenge derivation, cryptographic suite,
/// or verification semantics. Compatible implementation changes retain the tag.
///
/// The prover and all verifier paths must agree on this tag. Changing it breaks
/// compatibility with existing proofs.
///
/// Profiles share this protocol domain. Their setup separation is carried by
/// the tagged native and nested registry polynomials committed in the fuse
/// and checked by the verifiers; see [`profile`].
pub(crate) const RAGU_TAG: &[u8] = b"ragu-pcd-v1";
