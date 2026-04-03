//! Internal implementation of the recursive verifier — circuits, proof
//! components, and claim-building machinery.
//!
//! # Submodules
//!
//! - [`native`] — circuits and types for the native (host) curve
//! - [`nested`] — circuits and types for the nested curve
//! - [`claims`] — shared claim-building abstraction used by both curves
//! - [`fold_revdot`], [`endoscalar`], [`suffix`], [`transcript`] —
//!   supporting gadgets and helpers

pub mod claims;
pub mod endoscalar;
pub mod fold_revdot;
pub mod native;
pub mod nested;
pub mod suffix;
pub mod transcript;

/// Identifies which of the two child proofs a value came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// Assigns `val` into the next slot and advances the counter.
pub(crate) const fn push<T: Copy, const N: usize>(
    slots: &mut [Option<T>; N],
    c: &mut usize,
    val: T,
) {
    slots[*c] = Some(val);
    *c += 1;
}

/// Unwraps every element of an `Option` array at compile time.
///
/// Panics (at compile time) if any slot is `None`.
pub(crate) const fn unwrap_all<T: Copy, const N: usize>(slots: [Option<T>; N]) -> [T; N] {
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

#[cfg(test)]
pub mod tests;
