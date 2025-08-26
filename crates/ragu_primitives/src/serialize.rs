//! Traits for serializing gadgets into a sequence of [`Element`]s.
//!
//! The [`GadgetSerialize`] trait allows compatible [`Gadget`](crate::Gadget)s
//! to write [`Element`]s to a [`Buffer`] for serialization purposes. Because
//! gadgets are just containers for wires and witness data, they can usually
//! reconstitute their encapsulated [`Element`]s via promotion.
//!
//! The [`Buffer`] trait allows destination buffers to receive a [`Driver`] for
//! processing the elements they receive. This is handy for streaming hash
//! functions. Specific gadgets can have more optimal serialization strategies
//! by leveraging the provided [`Driver`] as well: a gadget that contains
//! boolean wires can [pack](crate::boolean::multipack) many of them into far
//! fewer [`Element`]s.
//!
//! ### Automatic Derivation
//!
//! Gadgets that consist mainly of other gadgets are candidates for [automatic
//! derivation](derive@GadgetSerialize) of the [`GadgetSerialize`] trait.

use ff::Field;
use ragu_core::{Result, drivers::Driver, gadgets::GadgetKind};

use crate::Element;

/// Represents a gadget that can be serialized into a sequence of [`Element`]s
/// that are written to a [`Buffer`].
///
/// Gadget serialization is implemented as a subtrait of [`GadgetKind`] to
/// satisfy Rust language restrictions and keep interfaces ergonomic. Concrete
/// [`Gadget`](crate::Gadget)s can be serialized using the
/// [`GadgetExt::serialize`](crate::GadgetExt::serialize) helper method.
pub trait GadgetSerialize<F: Field>: GadgetKind<F> {
    /// Serialize this gadget into wires that are written the provided buffer,
    /// using the driver to synthesize the elements if needed.
    fn serialize_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Self::Rebind<'dr, D>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()>;
}

/// Represents a destination for [`Element`]s to be written to using the
/// provided driver context.
pub trait Buffer<'dr, D: Driver<'dr>> {
    /// Push an `Element` into this buffer using the provided driver `D`.
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()>;
}

/// Automatically derives the [`GadgetSerialize`] trait for gadgets that merely
/// contain other gadgets.
///
/// This only works for structs with named fields. Similar to the
/// [`Gadget`](derive@ragu_core::gadgets::Gadget) derive macro, the driver type
/// can be annotated with `#[ragu(driver)]`. Fields with `#[ragu(skip)]` or
/// `#[ragu(phantom)]` annotations are ignored.
///
/// ## Example
///
/// ```rust
/// # use arithmetic::CurveAffine;
/// # use ragu_core::{drivers::{Driver, Witness}, gadgets::Gadget};
/// # use ragu_primitives::{Element, serialize::GadgetSerialize};
/// # use core::marker::PhantomData;
/// #[derive(Gadget, GadgetSerialize)]
/// pub struct Point<'dr, D: Driver<'dr>, C: CurveAffine> {
///     #[ragu(gadget)]
///     x: Element<'dr, D>,
///     #[ragu(gadget)]
///     y: Element<'dr, D>,
///     #[ragu(phantom)]
///     _marker: PhantomData<C>,
/// }
/// ```
pub use ragu_macros::GadgetSerialize;
