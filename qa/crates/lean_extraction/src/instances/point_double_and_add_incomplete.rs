use group::CurveAffine;
use ragu_pasta::{EpAffine, Fp};
use ragu_primitives::{NonzeroBank, Point};

use crate::{
    driver::ExtractionDriver,
    expr::Expr,
    instance::{CircuitInstance, WireCollector, WireDeserializer},
};

pub struct PointDoubleAndAddIncompleteInstance;

impl CircuitInstance for PointDoubleAndAddIncompleteInstance {
    type Field = Fp;

    fn circuit(dr: &mut ExtractionDriver<Fp>) -> ragu_core::Result<Vec<Expr<Fp>>> {
        let input_wires_self = dr.alloc_input_wires(2);
        let input_wires_other = dr.alloc_input_wires(2);

        let template = Point::constant(dr, EpAffine::generator())?;
        let self_p = WireDeserializer::new(input_wires_self).into_gadget(&template)?;
        let other = WireDeserializer::new(input_wires_other).into_gadget(&template)?;

        // Computes 2·self + other via the standard zcash trick: one div_nonzero
        // for λ₁ = (y_Q - y_P)/(x_Q - x_P), one square for λ₁², one div_nonzero
        // for (2y_P)/(x_P - x_r), one square for λ₂², one mul for
        // λ₂·(x_P - x_s). Five gate-emitting subcircuits total. The bank's
        // scope discharges both `x_P ≠ x_Q` and `x_P ≠ x_r` in-circuit.
        let result = NonzeroBank::scope(dr, |dr, bank| {
            self_p.double_and_add_incomplete(dr, &other, bank)
        })?;

        WireCollector::collect_from(&result)
    }
}
