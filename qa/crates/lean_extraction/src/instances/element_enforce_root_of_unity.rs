use ragu_pasta::Fp;
use ragu_primitives::Element;

use crate::{
    driver::ExtractionDriver,
    expr::Expr,
    instance::{CircuitInstance, WireDeserializer},
};

pub struct ElementEnforceRootOfUnityInstanceK2;

impl CircuitInstance for ElementEnforceRootOfUnityInstanceK2 {
    type Field = Fp;

    fn circuit(dr: &mut ExtractionDriver<Fp>) -> ragu_core::Result<Vec<Expr<Fp>>> {
        let input_wires = dr.alloc_input_wires(1);

        let element_template = Element::constant(dr, Fp::zero());
        let input = WireDeserializer::new(input_wires).into_gadget(&element_template)?;

        // k = 2: smallest non-trivial case (k = 0 is `self = 1`,
        // k = 1 is `self^2 = 1`). The polymorphic Lean reimpl is universal
        // in `k`; this instance pins it to k=2 for byte-equality against the
        // extracted trace. See `ElementEnforceRootOfUnityInstanceK5` for the
        // production-shape instance.
        input.enforce_root_of_unity(dr, 2)?;

        // No output wires; the gadget is an action, not a value.
        Ok(Vec::new())
    }
}

pub struct ElementEnforceRootOfUnityInstanceK5;

impl CircuitInstance for ElementEnforceRootOfUnityInstanceK5 {
    type Field = Fp;

    fn circuit(dr: &mut ExtractionDriver<Fp>) -> ragu_core::Result<Vec<Expr<Fp>>> {
        let input_wires = dr.alloc_input_wires(1);

        let element_template = Element::constant(dr, Fp::zero());
        let input = WireDeserializer::new(input_wires).into_gadget(&element_template)?;

        // k = 5: enforce `self^32 = 1`. This matches the production
        // `log2_circuits` value used by Applications with up to 17 registered
        // steps (the common case in `ragu_pcd`). See
        // `crates/ragu_pcd/src/internal/native/mod.rs::total_circuit_counts`
        // for the derivation; with 13 internal circuits + 2 internal steps,
        // any app step count in [1, 17] gives `log2_circuits = 5`.
        input.enforce_root_of_unity(dr, 5)?;

        Ok(Vec::new())
    }
}
