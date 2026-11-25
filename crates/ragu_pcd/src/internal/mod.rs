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
//! - [`revdot`] — revdot claims: the generic [`revdot::Builder`] each
//!   side assembles its claims with, and the two-layer quotient folding
//!   that batch-reduces them
//! - [`endoscalar`] — endoscaling circuit and witness types for iterative
//!   curve scalar multiplication
//! - [`paging`] — one walk of a unit operation cut into circuits that
//!   share a stage of interstitial states, which both endoscaling walks
//!   are
//! - [`program`] — one computation cut by hand into step circuits that
//!   share a memory stage of cells, each defined by one step
//! - [`transcript`] — Fiat–Shamir transcript wrapper over a Poseidon
//!   sponge, with domain separation
//! - [`ky`] — the $k(y)$ targets of a proof's revdot claims, computed one
//!   way for every verifier
//! - [`inverter`] — batch inversion of the quotient denominators the
//!   `compute_v` circuits need
//! - [`const_fns`] — compile-time helper functions for array construction
//!
//! [`revdot`], [`endoscalar`], [`paging`], [`program`], [`transcript`],
//! [`ky`] and [`inverter`] live in `shared/` and are re-exported here.
//!
//! # Crossing the cycle
//!
//! A **bridge** commitment lets a native commitment, a host-curve ($E_q$)
//! point, be witnessed in a nested stage and committed on the nested curve
//! ($E_p$), so it can be bound and absorbed into the transcript:
//!
//! 1. Native commitments: $\mathbb{F}_p\[X\]$ polynomials committed on $E_q$
//!    give $E_q$ points, with coordinates in $\mathbb{F}_q$, which the
//!    circuit-field transcript cannot absorb.
//! 2. Bridge stage: a nested stage, an $\mathbb{F}_q\[X\]$ polynomial, holds
//!    those $E_q$ points, along with any other $\mathbb{F}_q$ values.
//! 3. Bridge commitment: that stage committed on $E_p$ gives an $E_p$ point,
//!    with coordinates in $\mathbb{F}_p$, which the transcript absorbs.
//!
//! The exception is the **bridge-hash** stage, whose commitment is not
//! absorbed but is the digest [`Oracles::bridge_hash`] gives a step.
//!
//! A **points** stage holds the other side's batch commitments for this
//! side's endoscaling walk to fold into that batch's $P$.
//!
//! | stages          | stage polynomial                        | direction                    |
//! |-----------------|-----------------------------------------|------------------------------|
//! | bridge          | $\mathbb{F}_q\[X\]$, committed on $E_p$ | native → **nested** → native |
//! | points (native) | $\mathbb{F}_p\[X\]$, committed on $E_q$ | nested → **native**          |
//! | points (nested) | $\mathbb{F}_q\[X\]$, committed on $E_p$ | native → **nested**          |
//!
//! In the direction column, the bold hop is the side the stage lives on.
//!
//! | stages          | holds                     | purpose               | how it's bound        |
//! |-----------------|---------------------------|-----------------------|-----------------------|
//! | bridge          | $E_q$ points + scalars    | transcript absorption | transcript absorbs it |
//! | points (native) | $E_p$ points + endoscalar | native walk, bindings | a bridge carries it   |
//! | points (nested) | $E_q$ points              | nested walk           | [`collapse`] ties it  |
//!
//! Commitment fields are named for their curve: `native_*` on the host
//! curve ($E_q$), `nested_*` and `bridge_*` on the nested curve ($E_p$).
//!
//! [`collapse`]: nested::circuits::collapse
//! [`Oracles::bridge_hash`]: crate::step::Oracles::bridge_hash

/// Compile-time helpers for building the index lists' constant arrays.
pub mod const_fns {
    /// Assigns `val` into the next slot and advances the counter.
    pub const fn push<T: Copy, const N: usize>(slots: &mut [Option<T>; N], c: &mut usize, val: T) {
        slots[*c] = Some(val);
        *c += 1;
    }

    /// Unwraps every element of an `Option` array at compile time.
    ///
    /// Panics (at compile time) if any slot is `None`.
    pub const fn unwrap_all<T: Copy, const N: usize>(slots: [Option<T>; N]) -> [T; N] {
        // The filler is immediately overwritten for every index; it exists only
        // because `[T; N]` requires an initializer in const context.
        let mut arr = [slots[0].unwrap(); N];
        let mut i = 1;
        while i < N {
            arr[i] = slots[i].unwrap();
            i += 1;
        }
        arr
    }
}

pub mod native;
pub mod nested;

/// The machinery both sides share, in `shared/`. Each module is re-exported
/// here, so its path stays `internal::<module>`.
mod shared {
    pub mod endoscalar;
    pub mod inverter;
    pub mod ky;
    pub mod paging;
    pub mod program;
    pub mod revdot;
    pub mod transcript;
}
#[expect(
    unused_imports,
    reason = "no circuit is a program yet: only the module's own tests use it"
)]
pub use shared::program;
pub use shared::{endoscalar, inverter, ky, paging, revdot, transcript};

/// Position `index` among a profile's `count` variants of one kind, for
/// either side's arithmetic index lookups.
///
/// # Panics
///
/// Panics if `index` is not below `count`, rejecting a variant the profile
/// does not have just as a lookup in the canonical list did.
fn checked_index(index: u32, count: usize) -> usize {
    let index = index as usize;
    assert!(index < count, "index is outside the profile");
    index
}

/// Identifies which of the two child proofs a component came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

#[cfg(test)]
#[path = "../../tests/internal.rs"]
pub mod tests;
