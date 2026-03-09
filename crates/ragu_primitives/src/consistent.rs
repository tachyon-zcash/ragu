//! The [`Consistent`] trait for enforcing a gadget's internal constraints
//! on existing wires.

use alloc::boxed::Box;

use ragu_core::{Result, drivers::Driver, gadgets::Gadget};

/// Trait that enforces a gadget's internal constraints on existing wires.
///
/// Some gadgets require internal invariants for correctness; a [`Point`] must
/// satisfy its curve equation, a [`Boolean`] must be 0 or 1. This trait enforces
/// those constraints on wires allocated elsewhere, separating allocation from
/// constraint enforcement.
///
/// Gadgets without internal constraints (like [`Element`]) implement this as a
/// no-op. Composite gadgets delegate to their fields.
///
/// [`Point`]: crate::Point
/// [`Boolean`]: crate::Boolean
/// [`Element`]: crate::Element
pub trait Consistent<'dr, D: Driver<'dr>>: Gadget<'dr, D> {
    /// Enforce internal consistency constraints on this gadget's wires.
    fn enforce_consistent(&self, dr: &mut D) -> Result<()>;
}

/// Derives [`Consistent`] by calling `enforce_consistent` on `#[ragu(gadget)]` fields.
pub use ragu_macros::Consistent;

impl<'dr, D: Driver<'dr>> Consistent<'dr, D> for () {
    fn enforce_consistent(&self, _: &mut D) -> Result<()> {
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, G: Consistent<'dr, D>, const N: usize> Consistent<'dr, D> for [G; N] {
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        for item in self.iter() {
            item.enforce_consistent(dr)?;
        }
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, G1: Consistent<'dr, D>, G2: Consistent<'dr, D>> Consistent<'dr, D>
    for (G1, G2)
{
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        self.0.enforce_consistent(dr)?;
        self.1.enforce_consistent(dr)?;
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, G: Consistent<'dr, D>> Consistent<'dr, D> for Box<G> {
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        (**self).enforce_consistent(dr)
    }
}
