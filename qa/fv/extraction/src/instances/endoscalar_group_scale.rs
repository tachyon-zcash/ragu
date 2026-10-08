use ragu_core::pasta::{EpAffine, Fp};
use ragu_primitives::{ENDOSCALAR_BITS, Point};
use udon::curve::Affine;

use crate::{
    instance::{CircuitInstance, InstanceDriver, WireCollector, WireDeserializer},
    wire_remap::{boolean_from_wire, endoscalar_from_bits},
};

pub struct EndoscalarGroupScaleInstance;

impl CircuitInstance for EndoscalarGroupScaleInstance {
    type Field = Fp;

    /// Drives the real `Endoscalar::group_scale` on an `Endoscalar` assembled
    /// from the bit input wires (see [`boolean_from_wire`] and
    /// [`endoscalar_from_bits`]) and a point assembled from the
    /// coordinate input wires. The gadget builds its own unchecked
    /// `NonzeroBank`, so — as in the deployed circuit — no fold or discharge
    /// constraints are emitted; the Lean reimplementation carries that
    /// non-degeneracy as an explicit `Assumptions` conjunct.
    ///
    /// Input wires (in order): `bits[0..ENDOSCALAR_BITS]` (least significant first), then
    /// the point's `(x, y)`. Output: the scaled point's `(x, y)`.
    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = Fp>,
    {
        let bits: Vec<_> = dr
            .alloc_input_wires(ENDOSCALAR_BITS)
            .into_iter()
            .map(boolean_from_wire)
            .collect::<ragu_core::Result<_>>()?;
        let point_wires = dr.alloc_input_wires(2);

        let endo = endoscalar_from_bits(&bits)?;
        let point_template = Point::constant(dr, EpAffine::generator())?;
        let p = WireDeserializer::new(point_wires).into_gadget(&point_template)?;

        let acc = endo.group_scale(dr, &p)?;

        WireCollector::collect_from(&acc)
    }
}
