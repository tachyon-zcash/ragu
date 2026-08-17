//! # `ragu_acceleration`
//!
//! Optimized implementations of Ragu's computational backend.

#![no_std]
#![deny(missing_docs)]

/// Ragu's accelerated computational backend.
///
/// It currently inherits every correctness-first default from
/// [`ragu_backend::Backend`]. Optimized overrides will be added individually
/// alongside reference-equivalence tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceleratedBackend;

impl ragu_backend::Backend for AcceleratedBackend {}
