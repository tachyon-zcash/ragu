//! Wire conversion between drivers.
//!
//! Gadgets must be remappable between different [`Driver`](crate::drivers::Driver)
//! contexts --- for example, to send a gadget from a real driver into a wireless
//! [`Emulator`](crate::drivers::emulator::Emulator) during routine prediction.
//! The [`WireMap`] trait provides the conversion context for these
//! transformations.

use core::marker::PhantomData;
use ff::Field;

use crate::{
    Result,
    drivers::{Driver, DriverTypes},
    gadgets::{Bound, Gadget},
};

/// Conversion context that maps wires from one driver to another.
///
/// Each implementor fixes a specific source and destination driver via
/// associated types. When the same conversion logic applies to multiple
/// source/destination pairs, use a wrapper struct parameterized by those
/// types --- see [`WirelessFrom`](crate::drivers::emulator::WirelessFrom)
/// for an example.
pub trait WireMap<F: Field> {
    /// The source driver whose wires are being converted.
    type Src: DriverTypes<ImplField = F>;

    /// The destination driver whose wires are produced.
    type Dst: DriverTypes<ImplField = F>;

    /// Converts a wire from the source driver to the destination driver.
    fn convert_wire(
        &mut self,
        wire: &<Self::Src as DriverTypes>::ImplWire,
    ) -> Result<<Self::Dst as DriverTypes>::ImplWire>;
}

/// A [`WireMap`] that passes wires through unchanged by cloning them.
///
/// Useful when the source and destination share the same wire type --- for
/// example, when demoting a driver to strip witness data while preserving
/// wire values.
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
    /// `Src` is inferred from the gadget and `Dst` from the return context,
    /// so no turbofish is needed:
    ///
    /// ```ignore
    /// let output: Bound<'_, DstDriver, _> = CloneWires::convert(&gadget)?;
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
