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
//! - [`const_fns`] — compile-time helper functions for array construction

pub mod claims;
pub mod const_fns;
pub mod endoscalar;
pub mod fold_revdot;
pub mod inverter;
pub mod ky;
pub mod native;
pub mod nested;
pub mod transcript;

use ragu_circuits::{polynomials::Rank, registry::RegistryBuilder};
use ragu_core::{Error, Result};
use udon::field::Field;

/// Identifies which of the two child proofs a component came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// Runs `hook`, a profile's registration hook for the `index`-th `what` of
/// its `side` extension, and checks that it registered exactly one entry,
/// so that the layout's indices stay the registry's.
///
/// # Errors
///
/// Propagates the hook's error, or fails if the hook registered other than
/// one entry.
pub(crate) fn register_one<'params, F: Field, R: Rank>(
    registry: RegistryBuilder<'params, F, R>,
    side: &str,
    what: &str,
    index: u32,
    hook: impl FnOnce(RegistryBuilder<'params, F, R>) -> Result<RegistryBuilder<'params, F, R>>,
) -> Result<RegistryBuilder<'params, F, R>> {
    let expected = registry.num_internal_circuits() + 1;
    let registry = hook(registry)?;
    let registered = registry.num_internal_circuits();
    if registered != expected {
        return Err(Error::Initialization(
            alloc::format!(
                "the profile's {side} extension hook for {what} {index} left {registered} internal entries registered, not {expected}"
            )
            .into(),
        ));
    }
    Ok(registry)
}

#[cfg(test)]
pub mod tests;
