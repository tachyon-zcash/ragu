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
//! - [`SelectableBackend`] — the sealed choice of computational backend an
//!   application proves and verifies with.
//! - [`step::Step`] — the trait that defines computation nodes (transitions).
//! - [`header::Header`] — the trait that defines succinct state representations.
//! - [`Proof`] / [`Pcd`] — the proof and proof-carrying-data structures.
//! - [`CompressedProof`] / [`CompressedPcd`] — their compressed forms.
//! - [`ipa`] — the inner product argument compression ends in.
//! - [`profile`] — the proof shapes: the standard profile wallets prove in,
//!   and the aggregator profile, which carries decompression.
//! - [`pasta`] — Ragu's fixed generators, derived and embedded at build time
//!   with the `baked` feature.
//! - [`Proof::to_bytes`] / [`Proof::from_bytes`] and their [`CompressedProof`]
//!   counterparts — versioned byte encodings for storing and transporting
//!   proofs, defined in [`serialization`].
//!
//! The default `asm` feature enables Udon's AArch64 field arithmetic. On
//! x86-64, Udon uses its own assembly only in a build whose target features
//! include BMI2 and ADX, or with its `x86_64-asm` feature; it does not detect
//! the CPU at run time, and any other x86-64 build uses portable Rust. Other
//! targets and Miri use the portable Rust kernels. To select portable
//! arithmetic on AArch64, disable default features and retain `alloc`; on
//! x86-64, a build compiled for those extensions stays portable with Udon's
//! `portable` feature (`--features udon/portable` for this crate).
//! `multicore` is an independent, opt-in feature. Cargo unifies dependency
//! features, so portable AArch64 builds must ensure no other dependency
//! enables Udon's `aarch64-asm` feature.
//!
//! # Prover memory
//!
//! Proving holds witnesses and witness-derived polynomials in ordinary
//! process memory. Uncompressed proofs retain those polynomials for recursion.
//! Prover MSMs release their scratch when the call returns. Ordinary
//! deallocation provides no erasure guarantee. See [`ragu_core::msm`].

// Prover and verifier code.
//
// The prover is `fuse/`, every `prover.rs` (compression with its batch,
// revdot and IPA arguments, decompression, and the online polynomials), the
// uncompressed proof's builder and dummy proof in `proof/uncompressed/`, and
// the committer in `backend/`.
// `tests/prover_isolation.rs` fails if any other code reaches into it.
//
// The verifier takes three forms:
// - native: `compress/verifier.rs` and the `verifier.rs` of its batch, revdot
//   and IPA arguments, behind `Application::verify_compressed`;
// - recursive: the circuits in `internal/native/circuits/` and
//   `internal/nested/circuits/`, which every fuse proves over its children;
// - decompression: the gadgets and circuits in `decompress/`, which check
//   `verify_compressed`'s equations on a compressed proof in circuit.
//
// `proof/uncompressed/verifier.rs` is a test oracle, not a production
// verifier. The stages, claims, transcript, profiles, steps and
// serialization are shared by both sides.

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
#[cfg(feature = "unstable-aggregator")]
mod decompress;
mod fuse;
#[path = "../tests/fuzzing/mod.rs"]
pub mod fuzzing;
mod internal;
pub mod pasta;
pub mod profile;
mod proof;
pub mod serialization;
pub mod step;

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
#[path = "../tests/online_batch.rs"]
mod online_batch_tests;

#[cfg(test)]
#[path = "../tests/source_mesh.rs"]
mod source_mesh_tests;

#[cfg(test)]
#[path = "../tests/decompression/statement.rs"]
mod decompress_statement_tests;

#[cfg(all(test, feature = "unstable-fuzzing"))]
#[path = "../tests/profile_corruption.rs"]
mod profile_corruption_tests;

pub use application::{Application, ApplicationBuilder};
pub use backend::SelectableBackend;
/// The inner product argument compression ends in. The source lives with
/// the rest of compression, in `compress/ipa/`.
pub use compress::ipa;
use header::Header;
pub use proof::{CompressedPcd, CompressedProof, Pcd, Proof};
/// Headers, the succinct state a step reads and writes. The source lives with
/// the steps, in `step/header/`.
pub use step::header;

pub mod bridge_hash {
    //! The bridge hash $H^{bridge}(P)$ of a host-curve point, computed outside
    //! the circuit.
    //!
    //! A step's [`Oracles::bridge_hash`](crate::step::Oracles::bridge_hash) is
    //! the bridge hash of its own last online commitment. An application that
    //! hashes a polynomial commitment into state it also recomputes natively,
    //! such as an anchor, recomputes the same value with [`digest`], without
    //! building an [`Application`](crate::Application).
    //!
    //! [`digest`] is the commitment of the zero-alpha stage polynomial [`rx`]
    //! that holds the point's two coordinates, so it depends on the rank and
    //! the nested generators. It is the honest prover's encoding: an accepted
    //! bridge digest binds the point but need not use this encoding or be fixed
    //! before the step's challenge, so anchor applications must compare
    //! natively recomputed advancement against canonical-chain anchors.
    //!
    //! Every backend computes the same [`digest`]. A caller outside Ragu passes
    //! [`AcceleratedProver`](ragu_acceleration::AcceleratedProver) as its
    //! backend `B`, or the backend its [`Application`](crate::Application)
    //! uses.

    pub use crate::internal::nested::stages::bridge_hash::{digest, rx};
}

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
