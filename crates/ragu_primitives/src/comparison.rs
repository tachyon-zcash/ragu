//! Invariant-aware gadget equality.

use ragu_arithmetic::ff::Field;
use ragu_core::{
    Result,
    drivers::Driver,
    gadgets::{Bound, GadgetKind},
};

/// Gadget comparison utilities.
///
/// This trait is deliberately separate from
/// [`Gadget::enforce_conservative_equal`](ragu_core::gadgets::Gadget::enforce_conservative_equal).
/// The core gadget equality contract is conservative and constrains
/// corresponding wires pairwise. `GadgetEquals` is the ordinary equality hook
/// for circuit code and may use gadget semantics to enforce equality with fewer
/// constraints.
pub trait GadgetEquals<F: Field>: GadgetKind<F> {
    /// Enforce equality between two gadgets.
    ///
    /// Implementations may constrain fewer than all wire pairs by relying on
    /// invariants established by the gadget's constructors or consistency
    /// checks.
    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Bound<'dr, D2, Self>,
        b: &Bound<'dr, D2, Self>,
    ) -> Result<()>;
}

/// Derives [`GadgetEquals`] by enforcing raw wire equality and delegating to
/// [`GadgetEquals`] for nested gadgets.
pub use ragu_macros::GadgetEquals;
