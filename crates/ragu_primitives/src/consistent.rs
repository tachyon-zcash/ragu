//! The [`Consistent`] trait — for gadgets that can re-emit their own wire
//! contracts.

use alloc::boxed::Box;

use ragu_core::{Result, drivers::Driver, gadgets::Gadget};

/// Gadgets that can re-emit their own wire contracts.
///
/// From a gadget's perspective, the wires it creates and the constraints over
/// them persist forever. Some internal Ragu operations break that expectation
/// by substituting wires into a context where those constraints were not
/// emitted, leaving the gadget without the wire contracts it expects to hold
/// for every instance.
///
/// This trait is used to ask the gadget to re-express those contracts via new
/// constraints. The gadget's own witness data is often required to do so;
/// gadgets without witness data generally cannot implement the trait.
///
/// Most impls allocate a fresh `Self` and constrain it equal to the existing
/// wires. That equality uses the conservative
/// [`Gadget::enforce_conservative_equal`] check because consistency is the
/// infrastructure path that re-establishes gadget wire contracts. There is no
/// blanket impl, since gadgets do not share a uniform constructor signature.
///
/// The [`Consistent`](derive@Consistent) macro can derive composites by
/// delegating to each `#[ragu(gadget)]` field, but it only re-emits each
/// field's own wire contracts. Composites that expect constraints between their
/// subgadgets' wires must instead implement the trait by hand.
pub trait Consistent<'dr, D: Driver<'dr>>: Gadget<'dr, D> {
    /// Emits constraints that re-express `Self`'s wire contracts on the wires
    /// inside `self`, against the driver `dr`.
    ///
    /// # Errors
    ///
    /// Returns any error encountered while enforcing the gadget's internal
    /// constraints.
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
