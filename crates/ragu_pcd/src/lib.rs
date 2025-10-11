//! # `ragu_pcd`
//!
//! This crate provides a PCD scheme to enable efficient recursive proof
//! composition through BCLMS21-inspired split-accumulation.
//!
//! # Structures
//!  
//! It defines the core accumulator types for PCD over the Pallas/Vesta curve cycle.
//!
//! Ragu treats all recursion steps as PCD-based, even when only IVC semantics are required for
//! a given step. This allows the use of a dummy second input to maintain a uniform structure.
//! Although conjectural, it’s likely the performance cost of two-path PCD over IVC is negligible,
//! which optimistically motivates this design choice. Visually, this corresponds to an arity-2 PCD tree,
//! where IVC emerges as the degenerate case with dummy accumulator inputs, forming a lopsided binary
//! tree structure.
//!
//! # Architecture
//!
//! - **Split-Accumulation**: Separates private accumulation witness from public accumulation instance data
//! - **Deferred Computation**: Non-native field/curve operations are deferred to the next recursion step where
//!   they become native and can be verified efficiently in-circuit.
//!
//! In Ragu, we aim to expose a accumulator single proof structure capable of operating in two modes:
//!     * Uncompressed: BCLMS21-style split-accumulation form that is non-succinct (not sublinear in the circuit size),
//!     with a large witness but inexpensive to generate.
//!     * Compressed: a succinct form (logarithmic in the circuit size) using an IPA polynomial commitment scheme, with
//!     a more expensive verifier (outer decision procedure) that's dominated by a linear-time MSM.
//!
//! The recursion operates in “uncompressed” mode, and then we perform a “compression” step at certain boundary conditions for
//! bandwidth reasons. For instance, in shielded transaction aggregation, broadcasting transaction data in the compressed mode
//! optimizes for bandwidth. Naturally, we’ll also need some notion of “uncompressing” the compressed proof.

#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
// #![deny(missing_docs)]
#![doc(html_favicon_url = "https://seanbowe.com/ragu_assets/icons/v1_favicon32.png")]
#![doc(html_logo_url = "https://seanbowe.com/ragu_assets/icons/v1_rustdoc128.png")]

extern crate alloc;

pub mod accumulator;
pub mod cycle;
pub mod deferreds;
pub mod engine;
pub mod prover;
pub mod session;
