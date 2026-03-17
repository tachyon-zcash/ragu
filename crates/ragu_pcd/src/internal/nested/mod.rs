//! Nested field circuits for endoscaling verification.
//!
//! These circuits operate over the scalar field and verify that the
//! commitment accumulation was computed correctly via Horner's rule.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::MultiStage,
};
use ragu_core::Result;
use ragu_primitives::vec::Len;

use crate::internal::endoscalar::{EndoscalarStage, EndoscalingStep, NumStepsLen, PointsStage};

/// Number of curve points accumulated during `compute_p` for nested field
/// endoscaling verification.
///
/// This is the sum of:
/// - 2 proofs × 15 commitment components = 30
/// - 6 stage proof components (registry_wx0, registry_wx1, registry_wy, ab.a, ab.b, registry_xy)
/// - 1 f.commitment (base polynomial)
///
/// The endoscaling circuits process these 37 points across
/// `NumStepsLen::<NUM_ENDOSCALING_POINTS>::len()` = 9 steps.
pub const NUM_ENDOSCALING_POINTS: usize = 37;

/// Index of internal nested circuits registered into the registry.
///
/// These correspond to the circuit objects registered in [`register_all`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCircuitIndex {
    /// `EndoscalingStep` circuit at given step.
    EndoscalingStep(u32),
    /// `EndoscalarStage` stage mask.
    EndoscalarStage,
    /// `PointsStage` stage mask.
    PointsStage,
    /// `PointsStage` final staged mask.
    PointsFinalStaged,
}

impl InternalCircuitIndex {
    /// Convert to a [`CircuitIndex`] for registry lookup.
    ///
    /// Circuit indices follow the `RegistryBuilder::finalize()` concatenation
    /// order: internal circuits first, then internal masks.
    pub fn circuit_index(self) -> CircuitIndex {
        let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len() as u32;
        match self {
            Self::EndoscalingStep(step) => CircuitIndex::from_u32(step),
            Self::EndoscalarStage => CircuitIndex::from_u32(num_steps),
            Self::PointsStage => CircuitIndex::from_u32(num_steps + 1),
            Self::PointsFinalStaged => CircuitIndex::from_u32(num_steps + 2),
        }
    }
}

pub mod claims;

pub mod stages;

/// Registers internal nested circuits into the provided registry.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: Cycle, R: Rank>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    // Circuits first, then masks — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();
    for step in 0..num_steps {
        let step_circuit = EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(step);
        let staged = MultiStage::new(step_circuit);
        registry = registry.register_internal_circuit(staged)?;
    }

    registry = registry.register_internal_mask::<EndoscalarStage>()?;

    registry =
        registry.register_internal_mask::<PointsStage<C::HostCurve, NUM_ENDOSCALING_POINTS>>()?;

    registry = registry
        .register_internal_final_mask::<PointsStage<C::HostCurve, NUM_ENDOSCALING_POINTS>>()?;

    Ok(registry)
}
