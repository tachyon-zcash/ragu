//! Internal proving and verification engine for the recursive PCD protocol.
//!
//! This module defines the circuits, claim-building abstractions, and
//! supporting gadgets that implement recursion across both curves of the
//! cycle.
//!
//! # Submodules
//!
//! - [`native`] — circuits, indexed value containers, and claim
//!   orchestration for the native (host) field, including the header-associated
//!   [`online`](native::online) polynomials
//! - [`nested`] — circuits and claim orchestration for the nested
//!   (scalar) field, including endoscaling verification and the step's own
//!   [`online`](nested::online) polynomials
//! - [`claims`] — generic [`claims::Builder`] for assembling revdot
//!   claims, shared by both fields
//! - [`fold_revdot`] — two-layer quotient folding that batch-reduces
//!   revdot claims
//! - [`endoscalar`] — endoscaling circuit and witness types for iterative
//!   curve scalar multiplication
//! - [`transcript`] — Fiat–Shamir transcript wrapper over a Poseidon
//!   sponge, with domain separation
//! - [`const_fns`] — compile-time helper functions for array construction
//!
//! # Crossing the cycle
//!
//! A bridge commitment lets a native commitment, a host-curve ($E_q$) point,
//! be witnessed in a nested stage and committed on the nested curve ($E_p$),
//! so it can be bound and absorbed into the transcript:
//!
//! 1. Native commitments: $\mathbb{F}_p\[X\]$ polynomials committed on $E_q$
//!    give $E_q$ points, with coordinates in $\mathbb{F}_q$, which the
//!    circuit-field transcript cannot absorb.
//! 2. Bridge stage: a nested stage, an $\mathbb{F}_q\[X\]$ polynomial, holds
//!    those $E_q$ points, and in some bridges $\mathbb{F}_q$ values beside
//!    them.
//! 3. Bridge commitment: that stage committed on $E_p$ gives an $E_p$ point,
//!    with coordinates in $\mathbb{F}_p$, which the transcript absorbs.
//!
//! The exception is the bridge-hash stage, whose commitment is not absorbed
//! but is the digest [`Oracles::bridge_hash`] gives a step.
//!
//! A points stage holds the other side's batch commitments for this side's
//! endoscaling walk to fold into that batch's $P$.
//!
//! | stage         | stage polynomial                        | direction                    |
//! |---------------|-----------------------------------------|------------------------------|
//! | bridge        | $\mathbb{F}_q\[X\]$, committed on $E_p$ | native → **nested** → native |
//! | native points | $\mathbb{F}_p\[X\]$, committed on $E_q$ | nested → **native**          |
//! | nested points | $\mathbb{F}_q\[X\]$, committed on $E_p$ | native → **nested**          |
//!
//! The bold hop is where the stage lives.
//!
//! | stage         | holds                      | purpose               | how it's bound        |
//! |---------------|----------------------------|-----------------------|-----------------------|
//! | bridge        | host points + scalars      | transcript absorption | transcript absorbs it |
//! | native points | nested points + endoscalar | native walk, bindings | a bridge carries it   |
//! | nested points | host points                | nested walk           | [`loading`] ties it   |
//!
//! Commitment fields are named for their curve: `native_*` on the host
//! curve ($E_q$), `nested_*` and `bridge_*` on the nested curve ($E_p$).
//!
//! [`loading`]: nested::circuits::loading
//! [`Oracles::bridge_hash`]: crate::step::Oracles::bridge_hash

pub mod claims;
pub mod const_fns;
pub mod endoscalar;
pub mod fold_revdot;
pub mod inverter;
pub mod ky;
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
