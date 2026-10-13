use ragu_core::pasta::Fp;
use ragu_primitives::{HoistedEndoscalar, Uendo};

use crate::instance::{CircuitInstance, InstanceDriver, WireCollector};

pub struct HoistedEndoscalarAllocInstance;

impl CircuitInstance for HoistedEndoscalarAllocInstance {
    type Field = Fp;

    /// Drives the real `HoistedEndoscalar::alloc`: the `ENDOSCALAR_BITS` bit
    /// wires followed by the `ENDOSCALAR_PRODUCTS` product wires, every one a
    /// `Boolean::alloc`. Output: all of them, in that order.
    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = Fp>,
    {
        // MaybeKind = Empty: the value closure threaded into the per-wire
        // `Boolean::alloc` calls is never executed under extraction.
        let value = D::just(|| Uendo::ZERO);
        let endo = HoistedEndoscalar::alloc(dr, value)?;
        WireCollector::collect_from(&endo)
    }
}
