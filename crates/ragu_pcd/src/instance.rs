//! The wire forms of what the hooks put in the application circuit's public
//! instance. The adapter writes these and the native `preamble` stage reads
//! them back out of a child proof, so their derived `Write` impls *are* the
//! instance layout.
//!
//! Each has a value-form partner of the same name in
//! [`proof`](crate::proof). A witnessed polynomial needs none here — its wire
//! form is the [`PolyHandle`] a step is already handed.

use ragu_arithmetic::Cycle;
use ragu_core::{drivers::Driver, gadgets::Gadget};
use ragu_primitives::{Element, consistent::Consistent, io::Write};

use crate::poly_commitment::PolyHandle;

/// An opening claim $p(x) = y$ as the instance carries it.
#[derive(Gadget, Write, Consistent)]
pub(crate) struct PolyQuery<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    /// The same handle the step that witnessed the polynomial holds.
    #[ragu(gadget)]
    pub com: PolyHandle<'dr, D, C>,
    #[ragu(gadget)]
    pub x: Element<'dr, D>,
    #[ragu(gadget)]
    pub y: Element<'dr, D>,
}
