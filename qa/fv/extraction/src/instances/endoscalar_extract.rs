use ragu_core::pasta::Fp;
use ragu_primitives::{Element, Endoscalar, EndoscalarChallenge};
use udon::field::Field;

use crate::instance::{CircuitInstance, InstanceDriver, WireCollector, WireDeserializer};

pub struct EndoscalarExtractInstance;

impl CircuitInstance for EndoscalarExtractInstance {
    type Field = Fp;

    /// Drives the real `EndoscalarChallenge::from_element` followed by
    /// `Endoscalar::extract` — the in-circuit path `compute_v` takes — on a
    /// single input wire holding the challenge element.
    ///
    /// `from_element` emits `Fp::CAPACITY` (254) `Boolean::alloc` gates and
    /// one recomposition constraint binding their weighted sum to the element
    /// (`boolean.rs::decompose`); `extract` emits nothing and returns the low
    /// `ENDOSCALAR_BITS` bits. Under `MaybeKind = Empty` the witness-side range check
    /// (`try_just`) and the per-bit witness closures never run, so the trace
    /// is exactly those constraints.
    ///
    /// The unit allocator stands in for `compute_v`'s `Standard` pool: the only
    /// thing `Boolean::alloc` hands an allocator is its gate's spare `D` wire,
    /// which the extractor's three-wire model does not have (`Extra = ()`), so
    /// the choice of allocator leaves the trace unchanged.
    ///
    /// Input wire: `elem` (1 wire). Output: the `ENDOSCALAR_BITS` endoscalar bit wires,
    /// least significant first.
    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = Fp>,
    {
        let input_wires = dr.alloc_input_wires(1);
        let element_template = Element::constant(dr, Fp::ZERO);
        let elem = WireDeserializer::new(input_wires).into_gadget(&element_template)?;

        let challenge = EndoscalarChallenge::from_element(dr, &mut (), elem)?;
        let endo = Endoscalar::extract(challenge);

        WireCollector::collect_from(&endo)
    }
}
