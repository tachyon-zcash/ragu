//! Internal proving and verification engine for the recursive PCD protocol.
//!
//! This module defines the circuits, claim-building abstractions, and
//! supporting gadgets that implement recursion across both curves of the
//! cycle.
//!
//! # Submodules
//!
//! - [`native`] — circuits, indexed value containers, and claim
//!   orchestration for the native (host) field
//! - [`nested`] — circuits and claim orchestration for the nested
//!   (scalar) field, including endoscaling verification
//! - [`claims`] — generic [`claims::Builder`] for assembling revdot
//!   claims, shared by both fields
//! - [`fold_revdot`] — two-layer Horner-style folding that batch-reduces
//!   revdot claims
//! - [`endoscalar`] — endoscaling circuit and witness types for iterative
//!   curve scalar multiplication
//! - [`transcript`] — Fiat–Shamir transcript wrapper over a Poseidon
//!   sponge, with domain separation
//! - [`challenge`] — commit a polynomial and hash its commitment to derive a
//!   Fiat–Shamir challenge
//! - [`const_fns`] — compile-time helper functions for array construction

pub mod challenge;
pub mod claims;
pub mod const_fns;
pub mod endoscalar;
pub mod fold_revdot;
pub mod native;
pub mod nested;
pub mod transcript;

/// Identifies which of the two child proofs a component came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

#[cfg(test)]
pub mod tests;
