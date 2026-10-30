use core::marker::PhantomData;

use ragu_core::pasta::Fp;
use ragu_primitives::{ENDOSCALAR_BITS, ENDOSCALAR_PRODUCTS, consistent::Consistent};
use udon::field::Field;

use crate::{
    instance::{CircuitInstance, InstanceDriver},
    wire_remap::{boolean_from_wire, hoisted_endoscalar_from_bits},
};

/// `HoistedEndoscalar::enforce_consistent` on a gadget assembled from the bit
/// and product input wires (see [`boolean_from_wire`] and
/// [`hoisted_endoscalar_from_bits`]): a fresh `HoistedEndoscalar::alloc`
/// seeded from the gadget's own witness, linked to it wire by wire. This is
/// the constraint the staging machinery re-emits when it substitutes the
/// gadget's wires into a context where `alloc` never ran.
///
/// Input wires: `bits[0..ENDOSCALAR_BITS]` (least significant first), then
/// `products[0..ENDOSCALAR_PRODUCTS]`. No outputs.
pub struct HoistedEndoscalarConsistentInstance<F = Fp>(PhantomData<F>);

impl<F: Field> CircuitInstance for HoistedEndoscalarConsistentInstance<F> {
    type Field = F;

    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = F>,
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

        endo.enforce_consistent(dr)?;

        Ok(Vec::new())
    }
}
