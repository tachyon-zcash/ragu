//! Internal verification circuits for the native curve.
//!
//! This module contains five circuits that implement the recursive verification
//! step on the native curve:
//! - [`hashes_1`] / [`hashes_2`]: Fiat-Shamir hash derivation
//! - [`inner_collapse`] / [`outer_collapse`]: two-layer revdot folding
//! - [`compute_v`]: final evaluation verification

pub mod compute_v;
pub mod hashes_1;
pub mod hashes_2;
pub mod inner_collapse;
pub mod outer_collapse;
