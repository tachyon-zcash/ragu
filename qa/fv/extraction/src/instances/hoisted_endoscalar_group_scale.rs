use ragu_core::pasta::{EpAffine, Fp};
use ragu_primitives::{ENDOSCALAR_BITS, ENDOSCALAR_PRODUCTS, Point};
use udon::curve::Affine;

use crate::{
    instance::{CircuitInstance, InstanceDriver, WireCollector, WireDeserializer},
    wire_remap::{boolean_from_wire, hoisted_endoscalar_from_bits},
};

pub struct HoistedEndoscalarGroupScaleInstance;

impl CircuitInstance for HoistedEndoscalarGroupScaleInstance {
    type Field = Fp;

    /// Drives the real `HoistedEndoscalar::group_scale` on a gadget assembled
    /// from the bit and product input wires (see [`boolean_from_wire`] and
    /// [`hoisted_endoscalar_from_bits`]) and a point assembled from the
    /// coordinate input wires. Like `Endoscalar::group_scale`, the gadget
    /// walks with an unchecked `NonzeroBank`, so no fold or discharge
    /// constraints are emitted and the Lean reimplementation carries that
    /// non-degeneracy as an explicit `Assumptions` conjunct, together with
    /// the products' relation to the bits.
    ///
    /// Input wires (in order): `bits[0..ENDOSCALAR_BITS]` (least significant
    /// first), `products[0..ENDOSCALAR_PRODUCTS]` (per digit, `e1 * e2` then
    /// `e1 * e2 * s`), then the point's `(x, y)`. Output: the scaled point's
    /// `(x, y)`.
    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = Fp>,
    {
        let bits: Vec<_> = dr
            .alloc_input_wires(ENDOSCALAR_BITS)
            .into_iter()
            .map(boolean_from_wire)
            .collect::<ragu_core::Result<_>>()?;
        let products: Vec<_> = dr
            .alloc_input_wires(ENDOSCALAR_PRODUCTS)
            .into_iter()
            .map(boolean_from_wire)
            .collect::<ragu_core::Result<_>>()?;
        let point_wires = dr.alloc_input_wires(2);

        let endo = hoisted_endoscalar_from_bits(&bits, &products)?;
        let point_template = Point::constant(dr, EpAffine::generator())?;
        let p = WireDeserializer::new(point_wires).into_gadget(&point_template)?;

        let acc = endo.group_scale(dr, &p)?;

        WireCollector::collect_from(&acc)
    }
}
