//! Gadget-input helpers used only by the formal-verification extractor.
//!
//! The helpers build ordinary gadgets on a constraint-free wireless emulator,
//! then use the public gadget-mapping API to replace their dummy wires with the
//! extraction inputs. This lets instances call the real gadget implementations
//! without exposing any extraction-specific API from `ragu_primitives`.

use std::vec::{IntoIter, Vec};

use ragu_core::{
    Error, Result,
    convert::WireMap,
    drivers::{
        Driver, DriverTypes, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Gadget},
};
use ragu_primitives::{Boolean, Endoscalar, HoistedEndoscalar, Invertible, Uendo};
use udon::field::Field;

type TemplateDriver<D> =
    Emulator<Wireless<<D as DriverTypes>::MaybeKind, <D as DriverTypes>::ImplField>>;

struct WireRemapper<D: DriverTypes> {
    wires: IntoIter<D::ImplWire>,
    actual: usize,
    consumed: usize,
}

impl<D: DriverTypes> WireRemapper<D> {
    fn new(wires: Vec<D::ImplWire>) -> Self {
        let actual = wires.len();
        Self {
            wires: wires.into_iter(),
            actual,
            consumed: 0,
        }
    }
}

impl<D: DriverTypes> WireMap<D::ImplField> for WireRemapper<D> {
    type Src = TemplateDriver<D>;
    type Dst = D;

    fn convert_wire(&mut self, _: &()) -> Result<D::ImplWire> {
        let wire = self.wires.next().ok_or(Error::VectorLengthMismatch {
            expected: self.consumed + 1,
            actual: self.actual,
        })?;
        self.consumed += 1;
        Ok(wire)
    }
}

fn remap_template<'src, 'dst, D, G>(
    template: &G,
    wires: Vec<D::ImplWire>,
) -> Result<Bound<'dst, D, G::Kind>>
where
    D: Driver<'dst>,
    G: Gadget<'src, TemplateDriver<D>>,
{
    let expected = template.num_wires()?;
    let actual = wires.len();
    if actual != expected {
        return Err(Error::VectorLengthMismatch { expected, actual });
    }

    template.map(&mut WireRemapper::<D>::new(wires))
}

/// Wraps an existing wire as a [`Boolean`] without constraining it.
fn boolean_unchecked<'dr, D: Driver<'dr>>(
    wire: D::Wire,
    value: DriverValue<D, bool>,
) -> Result<Boolean<'dr, D>> {
    let mut dr = TemplateDriver::<D>::wireless();
    let template = Boolean::alloc(&mut dr, &mut (), value)?;
    remap_template(&template, vec![wire])
}

/// Assembles an [`Endoscalar`] from exactly `ENDOSCALAR_BITS` input-wire booleans.
fn endoscalar_unchecked<'dr, D: Driver<'dr>>(
    bits: &[Boolean<'dr, D>],
    value: DriverValue<D, Uendo>,
) -> Result<Endoscalar<'dr, D>> {
    let mut dr = TemplateDriver::<D>::wireless();
    let template = Endoscalar::alloc(&mut dr, value)?;
    let wires = bits.iter().map(|bit| bit.wire().clone()).collect();
    remap_template(&template, wires)
}

/// Wraps an input wire as a [`Boolean`] without emitting any operation, so an
/// instance can pass it to real gadget methods that take `&Boolean`.
///
/// This does not establish the boolean-ness of the wire. Each extracted
/// instance supplies any required Boolean precondition through its Lean
/// `Assumptions`.
///
/// # Errors
///
/// Propagates a structural error from the gadget remapping.
pub(crate) fn boolean_from_wire<'dr, D: Driver<'dr>>(wire: D::Wire) -> Result<Boolean<'dr, D>> {
    boolean_unchecked(wire, D::just(|| false))
}

/// Assembles an [`Endoscalar`] from exactly `ENDOSCALAR_BITS` wrapped input bits without
/// emitting any operation.
///
/// This does not add Boolean constraints; the endoscalar instances require
/// `IsBool` for each input bit through their Lean `Assumptions`.
///
/// # Errors
///
/// Propagates a structural error from the gadget remapping.
pub(crate) fn endoscalar_from_bits<'dr, D: Driver<'dr>>(
    bits: &[Boolean<'dr, D>],
) -> Result<Endoscalar<'dr, D>> {
    endoscalar_unchecked(bits, D::just(|| Uendo::ZERO))
}

/// Assembles a [`HoistedEndoscalar`] from its `ENDOSCALAR_BITS` bit wires and
/// `ENDOSCALAR_PRODUCTS` product wires, all wrapped booleans, without
/// emitting any operation.
///
/// This adds neither Boolean constraints nor the product constraints; the
/// hoisted instances require `IsBool` for every input wire through their
/// Lean `Assumptions`, and the products' relation to the bits is the
/// `EnforceProducts` instance's own contract.
///
/// # Errors
///
/// Propagates a structural error from the gadget remapping.
pub(crate) fn hoisted_endoscalar_from_bits<'dr, D: Driver<'dr>>(
    bits: &[Boolean<'dr, D>],
    products: &[Boolean<'dr, D>],
) -> Result<HoistedEndoscalar<'dr, D>> {
    let mut dr = TemplateDriver::<D>::wireless();
    let template = HoistedEndoscalar::alloc(&mut dr, D::just(|| Uendo::ZERO))?;
    let wires = bits
        .iter()
        .chain(products)
        .map(|bit| bit.wire().clone())
        .collect();
    remap_template(&template, wires)
}

/// Assembles an [`Invertible`] from its element and inverse wires without
/// emitting the allocation gate used by [`Invertible::alloc_with_advice`].
///
/// The caller is responsible for imposing the relation it wants to test. This
/// is used by the consistency instance, whose real operation immediately
/// allocates a fresh checked pair and links it to these two input wires.
pub(crate) fn invertible_from_wires<'dr, D: Driver<'dr>>(
    wires: Vec<D::Wire>,
) -> Result<Invertible<'dr, D>> {
    let mut dr = TemplateDriver::<D>::wireless();
    let value = D::just(|| D::F::ZERO);
    let inverse = D::just(|| D::F::ZERO);
    let template = Invertible::alloc_with_advice(&mut dr, value, inverse)?;
    remap_template(&template, wires)
}
