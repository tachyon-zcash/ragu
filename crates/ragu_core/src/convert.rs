//! Wire conversion between drivers.
//!
//! Routines execute circuit synthesis within well-defined abstraction
//! boundaries and may need to move gadgets --- and their wires --- from one
//! [`Driver`] context to another. For example, [`Routine::predict`] is
//! evaluated on a [`Wireless`](crate::drivers::emulator::Wireless)
//! [`Emulator`](crate::drivers::emulator::Emulator) so that no constraints
//! are synthesized, but the input gadget originates from a concrete source
//! driver. Without a uniform conversion mechanism, every call site would
//! need ad-hoc remapping logic.
//!
//! [`WireMap`] provides that mechanism: an implementor fixes a source and
//! destination driver via associated types, then converts wires one at a
//! time. Because [`WireMap`] is a separate trait rather than an associated
//! type on [`GadgetKind`](crate::gadgets::GadgetKind), the same gadget kind
//! can be remapped by many different conversion strategies (discarding wires,
//! cloning them, recording them) without proliferating trait parameters.
//!
//! ### Public API
//!
//! - [`WireMap`] --- the core conversion trait.
//! - [`CloneWires`] --- a [`WireMap`] that clones wires unchanged.
//!
//! The companion type
//! [`WirelessFrom`](crate::drivers::emulator::WirelessFrom) lives in
//! [`crate::drivers::emulator`] and discards wire values for use with
//! wireless emulators.
//!
//! [`Routine::predict`]: crate::routines::Routine::predict

use core::marker::PhantomData;
use ff::Field;

use crate::{
    Result,
    drivers::{Driver, DriverTypes},
    gadgets::{Bound, Gadget},
};

/// Conversion context that maps wires from one driver to another.
///
/// Each implementor fixes a specific source and destination via associated
/// types. When the same conversion logic applies to a whole family of
/// source types, use a wrapper struct parameterized by the source --- each
/// distinct source then maps to a fixed destination through a single blanket
/// impl. See [`WirelessFrom`](crate::drivers::emulator::WirelessFrom) for
/// an example.
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
/// Useful when the source and destination share the same wire type, so
/// conversion is a bitwise clone --- for example, when rebinding a gadget
/// to a new lifetime without changing its wire representation.
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
