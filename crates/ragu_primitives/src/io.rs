//! Traits for serializing gadgets into buffers and deserializing from elements.
//!
//! The [`Write`] trait allows compatible [`Gadget`](crate::Gadget)s
//! to write [`Element`]s to a [`Buffer`] for serialization purposes. Because
//! gadgets are just containers for wires and witness data, they can usually
//! reconstitute their encapsulated [`Element`]s via promotion.
//!
//! The [`FromElements`] trait is the reverse operation: it constructs gadgets
//! from a fixed number of [`Element`]s. This is used for generating Fiat-Shamir
//! challenges in the [`Transcript`](crate::Transcript) API.
//!
//! The [`Buffer`] trait allows destination buffers to receive a [`Driver`] for
//! processing the elements they receive. This is handy for streaming hash
//! functions. Specific gadgets can have more optimal serialization strategies
//! by leveraging the provided [`Driver`] as well: as an example, a gadget that
//! contains multiple [`Boolean`](crate::Boolean)s can
//! [pack](crate::boolean::multipack) many of them into far fewer [`Element`]s.

mod pipe;

use ff::Field;
use ragu_core::{Result, drivers::Driver, gadgets::GadgetKind};

use crate::Element;

pub use pipe::Pipe;

/// Represents a gadget that can be serialized into a sequence of [`Element`]s
/// that are written to a [`Buffer`].
///
/// Gadget serialization is implemented as a subtrait of [`GadgetKind`] to
/// satisfy Rust language restrictions and keep interfaces ergonomic. Concrete
/// [`Gadget`](crate::Gadget)s can be serialized using the
/// [`GadgetExt::write`](crate::GadgetExt::write) helper method.
///
/// ### Automatic Derivation
///
/// Gadgets that consist mainly of other gadgets are candidates for [automatic
/// derivation](derive@Write) of this trait.
pub trait Write<F: Field>: GadgetKind<F> {
    /// Write this gadget into wires that are written the provided buffer,
    /// using the driver to synthesize the elements if needed.
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
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

/// Trait for types that can be constructed from a fixed number of field elements.
///
/// This trait is the reverse of [`Write`]: while `Write` serializes gadgets to
/// elements, `FromElements` constructs gadgets from elements. It is primarily
/// used for generating Fiat-Shamir challenges via [`challenge`].
///
/// The number of elements required is specified as a const generic parameter `N`.
///
/// # Wire Consistency
///
/// It's the responsibility of the implementor to ensure that the reconstructed
/// gadget is wire-consistent with the provided elements. Namely,
/// [`enforce_consistency`] should be called on the resulting gadget before it
/// is used in any further constraints.
///
/// # Examples
///
/// ```rust,ignore
/// // Element needs 1 field element
/// impl FromElements<'dr, D, 1> for Element<'dr, D> { ... }
///
/// // Point needs 2 field elements (x and y coordinates)
/// impl FromElements<'dr, D, 2> for Point<'dr, D, C> { ... }
///
/// // Array of N elements
/// impl FromElements<'dr, D, N> for [Element<'dr, D>; N] { ... }
/// ```
///
/// [`challenge`]: crate::transcript::TranscriptProtocol::challenge
/// [`enforce_consistency`]: ragu_core::gadgets::Consistent::enforce_consistent
pub trait FromElements<'dr, D: Driver<'dr>, const N: usize>: Sized {
    /// Construct this type from exactly `N` field elements.
    fn from_elements(dr: &mut D, elements: [Element<'dr, D>; N]) -> Result<Self>;
}

/// Automatically derives the [`Write`] trait for gadgets that merely
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
/// # use ragu_core::{drivers::{Driver, DriverValue}, gadgets::Gadget};
/// # use ragu_primitives::{Element, io::Write};
/// # use core::marker::PhantomData;
/// #[derive(Gadget, Write)]
/// pub struct Point<'dr, D: Driver<'dr>, C: CurveAffine> {
///     #[ragu(gadget)]
///     x: Element<'dr, D>,
///     #[ragu(gadget)]
///     y: Element<'dr, D>,
///     #[ragu(phantom)]
///     _marker: PhantomData<C>,
/// }
/// ```
pub use ragu_macros::Write;
