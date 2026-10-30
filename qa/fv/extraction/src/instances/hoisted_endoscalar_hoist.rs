use core::marker::PhantomData;

use ragu_core::pasta::Fp;
use ragu_primitives::{ENDOSCALAR_BITS, HoistedEndoscalar};
use udon::field::Field;

use crate::{
    instance::{CircuitInstance, InstanceDriver},
    wire_remap::{boolean_from_wire, endoscalar_from_bits},
};

pub struct HoistedEndoscalarHoistInstance<F = Fp>(PhantomData<F>);

impl<F: Field> CircuitInstance for HoistedEndoscalarHoistInstance<F> {
    type Field = F;

    /// Drives the real `HoistedEndoscalar::hoist` on an endoscalar assembled
    /// from the bit input wires (see [`boolean_from_wire`] and
    /// [`endoscalar_from_bits`]): the two `Boolean::and` gates per digit that
    /// derive the product wires from the bits, which is the part of
    /// `HoistedEndoscalar::alloc` beyond `Endoscalar::alloc`.
    ///
    /// Input wires: `bits[0..ENDOSCALAR_BITS]` (least significant first).
    /// Output: `products[0..ENDOSCALAR_PRODUCTS]`, per digit `e1 * e2` then
    /// `e1 * e2 * s`.
    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = F>,
    {
        let bits: Vec<_> = dr
            .alloc_input_wires(ENDOSCALAR_BITS)
            .into_iter()
            .map(boolean_from_wire)
            .collect::<ragu_core::Result<_>>()?;
        let endo = endoscalar_from_bits(&bits)?;

        let hoisted = HoistedEndoscalar::hoist(dr, endo)?;

        Ok(hoisted
            .products()
            .flat_map(|(p, q)| [p.wire().clone(), q.wire().clone()])
            .collect())
    }
}
