//! Nested field circuits for endoscaling verification.
//!
//! These circuits operate over the scalar field and verify that the
//! commitment accumulation was computed correctly via Horner's rule.

use arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    polynomials::Rank,
    registry::CircuitIndex,
    staging::{MultiStage, StageExt},
};
use ragu_core::Result;
use ragu_primitives::vec::Len;

use crate::{
    NestedRegistryBuilder,
    components::endoscalar::{EndoscalarStage, EndoscalingStep, NumStepsLen, PointsStage},
};

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
pub(crate) const NUM_ENDOSCALING_POINTS: usize = 37;

/// Index of internal nested circuits registered into the registry.
///
/// These correspond to the circuit objects registered in [`register_all`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum InternalCircuitIndex {
    /// `EndoscalarStage` stage mask.
    EndoscalarStage,
    /// `PointsStage` stage mask.
    PointsStage,
    /// `PointsStage` final staged mask.
    PointsFinalStaged,
    /// `EndoscalingStep` circuit at given step.
    EndoscalingStep(u32),
}

impl InternalCircuitIndex {
    /// Convert to a [`CircuitIndex`] for registry lookup.
    pub(crate) const fn circuit_index(self) -> CircuitIndex {
        match self {
            Self::EndoscalarStage => CircuitIndex::from_u32(0),
            Self::PointsStage => CircuitIndex::from_u32(1),
            Self::PointsFinalStaged => CircuitIndex::from_u32(2),
            Self::EndoscalingStep(step) => CircuitIndex::from_u32(3 + step),
        }
    }
}

pub mod stages;

/// Register internal nested circuits into the provided registry.
pub(crate) fn register_all<'params, C: Cycle, R: Rank>(
    mut registry: NestedRegistryBuilder<'params, C, R>,
) -> Result<NestedRegistryBuilder<'params, C, R>> {
    registry = registry.register_circuit_object(EndoscalarStage::mask()?)?;

    registry = registry
        .register_circuit_object(PointsStage::<C::HostCurve, NUM_ENDOSCALING_POINTS>::mask()?)?;

    registry = registry
        .register_circuit_object(
            PointsStage::<C::HostCurve, NUM_ENDOSCALING_POINTS>::final_mask()?,
        )?;

    let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();
    for step in 0..num_steps {
        let step_circuit = EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(step);
        let staged = MultiStage::new(step_circuit);
        registry = registry.register_circuit_object(staged.into_object()?)?;
    }
    Ok(registry)
}
