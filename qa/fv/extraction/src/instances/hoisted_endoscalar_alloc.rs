use core::marker::PhantomData;

use ragu_core::pasta::Fp;
use ragu_primitives::{HoistedEndoscalar, Uendo};
use udon::field::Field;

use crate::instance::{CircuitInstance, InstanceDriver, WireCollector};

pub struct HoistedEndoscalarAllocInstance<F = Fp>(PhantomData<F>);

impl<F: Field> CircuitInstance for HoistedEndoscalarAllocInstance<F> {
    type Field = F;

    /// Drives the real `HoistedEndoscalar::alloc`: `Boolean::alloc` creates
    /// the `ENDOSCALAR_BITS` bit wires, then `Boolean::and` derives the
    /// `ENDOSCALAR_PRODUCTS` product wires. Output: all of them, in that order.
    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = F>,
    {
        // MaybeKind = Empty: the value closure threaded into the per-wire
        // `Boolean::alloc` calls is never executed under extraction.
        let value = D::just(|| Uendo::ZERO);
        let endo = HoistedEndoscalar::alloc(dr, value)?;
        WireCollector::collect_from(&endo)
    }
}
