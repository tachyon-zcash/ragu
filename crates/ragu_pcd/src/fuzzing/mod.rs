#![cfg(feature = "unstable-fuzzing")]
#![doc(hidden)]
//! The fuzzing surface of `ragu_pcd`: hooks for the out-of-tree fuzz harness
//! (`qa/fuzz`) and for the crate's own fuzz-shaped tests.
//!
//! Nothing here is part of the crate's API. The module gates itself behind
//! the `unstable-fuzzing` feature with the inner attribute above, so the
//! production modules carry no feature attributes, and it is hidden from the
//! rendered documentation. It may change or disappear in any release.
//!
//! * [`corrupt`] — proof corruption: a vocabulary of edits to a finished
//!   proof, each reporting whether the verifier is obliged to reject.
//! * [`patcher`] — the patcher seam: hands the internal recursion circuits,
//!   their honest witnesses and their oracle specifications to a visitor
//!   mid-fuse. Its source is `patcher.rs` in this directory, but the module
//!   itself is mounted under `fuse` (see `fuse/mod.rs`) so that it can call
//!   the same private pipeline steps `fuse` does; [`patcher`] is its public
//!   face.
//! * `access.rs` — the mutable component accessors [`corrupt`] writes
//!   through. Not a module of this namespace: it is mounted as a child of
//!   `proof` (see `proof/mod.rs`) so it can reach `Proof`'s private fields
//!   without loosening them, the same arrangement as `patcher` under `fuse`.

pub mod corrupt;

/// The patcher seam over the internal recursion circuits. The implementation
/// is `fuzzing/patcher.rs`, mounted as `fuse::patcher`.
pub mod patcher {
    pub use crate::fuse::patcher::{
        CircuitSpec, InternalCircuitVisitor, OutputRef, Resolution, capture_internal_circuits,
        capture_internal_circuits_bootstrap,
    };
}
