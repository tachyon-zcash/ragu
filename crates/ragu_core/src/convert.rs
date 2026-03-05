//! Conversions that translate gadgets from one [`Driver`] context to another.
//!
//! Gadgets are polymorphic over drivers, and translating a gadget from one
//! driver context to another while preserving its structure and semantics is a
//! fundamental operation. Any code that operates across multiple driver
//! contexts will need this: [routines](crate::routines) translate their inputs
//! onto [`Wireless`] [`Emulator`]s for prediction, wire-counting passes discard
//! wire values entirely, and driver implementations may need to inject or
//! rewrite wires during circuit analysis.
//!
//! [`WireMap`] provides a uniform mechanism for these conversions: an
//! implementor fixes a source and destination driver via associated types, then
//! converts wires one at a time. Because [`WireMap`] is a separate trait rather
//! than an associated type on [`GadgetKind`](crate::gadgets::GadgetKind), the
//! same gadget kind can be remapped by many different conversion strategies
//! without adding type parameters to
//! [`GadgetKind`](crate::gadgets::GadgetKind).
//!
//! ### Public API
//!
//! - [`WireMap`], the core conversion trait.
//! - [`CloneWires`], a [`WireMap`] that clones wires unchanged.
//! - [`EraseWires`], a [`WireMap`] that discards wire values for use with
//!   wireless emulators.
//!
//! [`Routine::predict`]: crate::routines::Routine::predict

use core::marker::PhantomData;
use ff::Field;

use crate::{
    Result,
    drivers::emulator::{Emulator, Wireless},
    drivers::{Driver, DriverTypes},
    gadgets::{Bound, Gadget},
};

/// Conversion context that maps wires from one driver to another.
///
/// Each implementor fixes a specific source and destination via associated
/// types. When the same conversion logic applies to a whole family of source
/// types, a wrapper struct parameterized by the source allows each distinct
/// source to map to a fixed destination through a single blanket impl. See
/// [`EraseWires`] for an example.
pub trait WireMap<F: Field> {
    /// The source [`DriverTypes`] whose wires are being converted.
    type Src: DriverTypes<ImplField = F>;

    /// The destination [`DriverTypes`] whose wires are produced.
    type Dst: DriverTypes<ImplField = F>;

    /// Converts a wire from the source driver to the destination driver.
    fn convert_wire(
        &mut self,
        wire: &<Self::Src as DriverTypes>::ImplWire,
    ) -> Result<<Self::Dst as DriverTypes>::ImplWire>;
}

/// A [`WireMap`] that passes wires through unchanged by cloning them.
///
/// The source and destination must share the same wire type, so conversion
/// calls [`.clone()`](Clone::clone) on each wire. This is useful when
/// rebinding a gadget to a new lifetime without changing its wire
/// representation.
pub struct CloneWires<Src: DriverTypes, Dst: DriverTypes>(PhantomData<(Src, Dst)>);

impl<Src: DriverTypes, Dst: DriverTypes> Default for CloneWires<Src, Dst> {
    fn default() -> Self {
        CloneWires(PhantomData)
    }
}

impl<F: Field, Src, Dst> CloneWires<Src, Dst>
where
    Src: DriverTypes<ImplField = F>,
    Dst: DriverTypes<ImplField = F, ImplWire = Src::ImplWire>,
{
    /// Maps a gadget to a destination driver by cloning its wires.
    ///
    /// `Src` is inferred from the gadget; `Dst` can be inferred from the
    /// return context or spelled out explicitly:
    ///
    /// ```ignore
    /// // Inferred from context:
    /// let output: Bound<'_, DstDriver, _> = CloneWires::convert(&gadget)?;
    /// // Explicit:
    /// let output = CloneWires::<_, DstDriver>::convert(&gadget)?;
    /// ```
    pub fn convert<'src, 'dst, G: Gadget<'src, Src>>(
        gadget: &G,
    ) -> Result<Bound<'dst, Dst, G::Kind>>
    where
        Src: Driver<'src, F = F>,
        Dst: Driver<'dst, F = F, Wire = Src::Wire>,
    {
        gadget.map(&mut Self::default())
    }
}

impl<F: Field, Src, Dst> WireMap<F> for CloneWires<Src, Dst>
where
    Src: DriverTypes<ImplField = F>,
    Dst: DriverTypes<ImplField = F, ImplWire = Src::ImplWire>,
{
    type Src = Src;
    type Dst = Dst;

    fn convert_wire(
        &mut self,
        wire: &<Src as DriverTypes>::ImplWire,
    ) -> Result<<Dst as DriverTypes>::ImplWire> {
        Ok(wire.clone())
    }
}

/// A [`WireMap`] that maps any driver's wires to `()`, discarding wire
/// values for use with `Emulator<Wireless<D::MaybeKind, D::ImplField>>`.
///
/// This conversion is used to pass a gadget from a concrete driver into
/// [`Routine::predict`], which operates on a [`Wireless`] emulator. The
/// wrapper struct is parameterized by the source driver so that each source
/// type gets its own blanket [`WireMap`] impl.
///
/// [`Routine::predict`]: crate::routines::Routine::predict
pub struct EraseWires<D: DriverTypes>(PhantomData<D>);

impl<D: DriverTypes> Default for EraseWires<D> {
    fn default() -> Self {
        EraseWires(PhantomData)
    }
}

impl<F: Field, D: DriverTypes<ImplField = F>> WireMap<F> for EraseWires<D> {
    type Src = D;
    type Dst = Emulator<Wireless<D::MaybeKind, F>>;

    fn convert_wire(&mut self, _: &D::ImplWire) -> Result<()> {
        Ok(())
    }
}
