//! # `ragu_acceleration`
//!
//! Optimized implementations of Ragu's computational backend.
//!
//! Overrides fall back to the defaults of [`ragu_backend::Backend`] where a
//! method has none. There is no override today: the defaults already run
//! Udon's MSMs and FFTs with caller-owned scratch and execution. This crate is
//! the home for the next ones (an external Poseidon, for instance). Overrides of the
//! kernels that `ragu_pcd`'s verifier consults belong in [`verifier`], which
//! carries a stricter review and testing bar than prover-only overrides. An
//! override arrives with its differential test against the default it
//! replaces; `ragu_pcd`'s `backend_equivalence` tests hold
//! [`AcceleratedProver`] to the reference end to end.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod verifier;

/// Ragu's accelerated computational backend, for proving and verification.
///
/// It carries no override yet and computes exactly what
/// [`ragu_backend::ReferenceBackend`] computes. Selecting this backend in
/// `ragu_pcd` also uses its verifier-consulted kernels (see [`verifier`]) when
/// verifying proofs. Select [`AcceleratedProver`] to accelerate proving only.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceleratedBackend;

/// [`AcceleratedBackend`] for proving, with verification on the reference
/// kernels.
///
/// Computes exactly what [`AcceleratedBackend`] computes; the two differ only
/// in which kernels `ragu_pcd` consults when verifying. Selecting this type
/// keeps every acceptance decision on the canonical code path, at the cost of
/// the verifier-side speedups.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceleratedProver;

// `AcceleratedProver` must forward every override to `AcceleratedBackend`,
// one method per override, so the two impl blocks stay comparable and a new
// override cannot be selected for proving while silently missing here.
impl ragu_backend::Backend for AcceleratedBackend {}

impl ragu_backend::Backend for AcceleratedProver {}
