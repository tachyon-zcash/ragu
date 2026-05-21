use group::CurveAffine;
use ragu_pasta::{EpAffine, Fp};
use ragu_primitives::{Element, Point};

use crate::{
    driver::ExtractionDriver,
    expr::Expr,
    instance::{CircuitInstance, WireCollector, WireDeserializer},
};

pub struct PointAddIncompleteInstance;

impl CircuitInstance for PointAddIncompleteInstance {
    type Field = Fp;

    fn circuit(dr: &mut ExtractionDriver<Fp>) -> ragu_core::Result<Vec<Expr<Fp>>> {
        let input_wires_1 = dr.alloc_input_wires(2);
        let input_wires_2 = dr.alloc_input_wires(2);
        let nonzero_input = dr.alloc_input_wires(1);

        // Reuse a constant point as a structural template, then substitute the
        // raw input wires into its `[x, y]` gadget fields.
        let point_template = Point::constant(dr, EpAffine::generator())?;
        let p1 = WireDeserializer::new(input_wires_1).into_gadget(&point_template)?;
        let p2 = WireDeserializer::new(input_wires_2).into_gadget(&point_template)?;

        let element_template = Element::constant(dr, Fp::zero());
        let mut nonzero = WireDeserializer::new(nonzero_input).into_gadget(&element_template)?;

        let p3 = p1.add_incomplete(dr, &p2, Some(&mut nonzero))?;

        let mut point_serialized = WireCollector::collect_from(&p3)?;
        let mut nonzero_serialized = WireCollector::collect_from(&nonzero)?;
        point_serialized.append(&mut nonzero_serialized);
        Ok(point_serialized)
    }
}
