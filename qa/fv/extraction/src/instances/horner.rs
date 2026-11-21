use ragu_circuits::horner::Horner;
use ragu_core::pasta::Fp;
use ragu_primitives::{Element, io::Buffer};
use udon::field::Field;

use crate::instance::{CircuitInstance, InstanceDriver, WireCollector, WireDeserializer};

/// `Horner::write` is `acc.mul(point).add(value)` for every element after
/// the first, which is the exact operation trace of `Element::fold` over the
/// same elements with `point` as the scale factor. These instances drive the
/// real `Horner` buffer and are tied to the `Fold` Lean reimpl, so the `Fold`
/// theorems carry over to `Horner` through the fingerprint check.
pub struct HornerInstanceN3;

impl CircuitInstance for HornerInstanceN3 {
    type Field = Fp;

    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = Fp>,
    {
        // n = 3: smallest shape with two `Mul` gates, matching `FoldN3`.
        horner_at_length::<D, 3, false>(dr)
    }
}

pub struct HornerInstanceN7;

impl CircuitInstance for HornerInstanceN7 {
    type Field = Fp;

    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = Fp>,
    {
        // n = 7: matches `FoldN7` (`RevdotParameters::GroupSize`), so the
        // Horner and fold shapes used by `protocol/revdot/fold.rs` share one digest.
        horner_at_length::<D, 7, false>(dr)
    }
}

pub struct HornerInstanceN19;

impl CircuitInstance for HornerInstanceN19 {
    type Field = Fp;

    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = Fp>,
    {
        // n = 19: matches `FoldN19` (`RevdotParameters::NumGroups`).
        horner_at_length::<D, 19, false>(dr)
    }
}

/// `Horner::finish_ky` writes the constant `1` as a final term before
/// finishing, following the $k(Y)$ polynomial convention: the trailing
/// `acc.mul(point).add(one)` has a constant, not an input wire, as its
/// addend, so this is a distinct trace from `HornerInstanceN3`.
pub struct HornerKyInstanceN3;

impl CircuitInstance for HornerKyInstanceN3 {
    type Field = Fp;

    fn circuit<'dr, D>(dr: &mut D) -> ragu_core::Result<Vec<D::Wire>>
    where
        D: InstanceDriver<'dr, F = Fp>,
    {
        horner_at_length::<D, 3, true>(dr)
    }
}

/// Allocates `N` coefficient input wires followed by the evaluation point,
/// mirroring `element_fold.rs` (elements first, scale factor last), writes
/// the coefficients into a fresh `Horner` in order (highest degree first),
/// and finishes with `finish_ky` when `KY` is set, `finish` otherwise.
fn horner_at_length<'dr, D: InstanceDriver<'dr, F = Fp>, const N: usize, const KY: bool>(
    dr: &mut D,
) -> ragu_core::Result<Vec<D::Wire>> {
    let element_template = Element::constant(dr, Fp::ZERO);

    let mut coefficients = Vec::with_capacity(N);
    for _ in 0..N {
        let input_wires = dr.alloc_input_wires(1);
        let coefficient = WireDeserializer::new(input_wires).into_gadget(&element_template)?;
        coefficients.push(coefficient);
    }
    let point_wires = dr.alloc_input_wires(1);
    let point = WireDeserializer::new(point_wires).into_gadget(&element_template)?;

    let mut horner = Horner::new(&point);
    for coefficient in &coefficients {
        horner.write(dr, coefficient)?;
    }
    let result = if KY {
        horner.finish_ky(dr)?
    } else {
        horner.finish(dr)
    };

    WireCollector::collect_from(&result)
}
