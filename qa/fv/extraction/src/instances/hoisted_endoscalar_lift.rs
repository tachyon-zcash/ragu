use ragu_core::pasta::Fp;
use ragu_primitives::{ENDOSCALAR_BITS, ENDOSCALAR_PRODUCTS};

use crate::{
    instance::{CircuitInstance, InstanceDriver, WireCollector},
    wire_remap::{boolean_from_wire, hoisted_endoscalar_from_bits},
};

pub struct HoistedEndoscalarLiftInstance;

impl CircuitInstance for HoistedEndoscalarLiftInstance {
    type Field = Fp;

    /// Drives the real `HoistedEndoscalar::lift` on a gadget assembled from
    /// the bit and product input wires (see [`boolean_from_wire`] and
    /// [`hoisted_endoscalar_from_bits`]).
    ///
    /// Input wires: `bits[0..ENDOSCALAR_BITS]` (least significant first), then
    /// `products[0..ENDOSCALAR_PRODUCTS]`. Output: the lifted element.
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
        let endo = hoisted_endoscalar_from_bits(&bits, &products)?;

        let lifted = endo.lift(dr)?;

        WireCollector::collect_from(&lifted)
    }
}
