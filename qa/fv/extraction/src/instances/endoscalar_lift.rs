use core::marker::PhantomData;

use ragu_core::pasta::Fp;
use ragu_primitives::ENDOSCALAR_BITS;
use udon::field::Field;

use crate::{
    instance::{CircuitInstance, InstanceDriver, WireCollector},
    wire_remap::{boolean_from_wire, endoscalar_from_bits},
};

pub struct EndoscalarLiftInstance<F = Fp>(PhantomData<F>);

impl<F: Field> CircuitInstance for EndoscalarLiftInstance<F> {
    type Field = F;

    /// Drives the real `Endoscalar::lift` on an `Endoscalar` assembled from the
    /// `ENDOSCALAR_BITS` input wires (see [`boolean_from_wire`] and [`endoscalar_from_bits`]).
    ///
    /// Input wires: `bits[0..ENDOSCALAR_BITS]`, least significant first. Output: the lifted
    /// element.
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

        let lifted = endo.lift(dr)?;

        WireCollector::collect_from(&lifted)
    }
}
