//! Nested field circuits for endoscaling verification.
//!
//! These circuits operate over the scalar field and verify that the
//! commitment accumulation was computed correctly via Horner's rule.

use arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    mesh::{CircuitIndex, MeshBuilder},
    polynomials::Rank,
    staging::{StageExt, Staged},
};
use ragu_core::Result;
use ragu_primitives::vec::Len;

use crate::components::endoscalar::{EndoscalarStage, EndoscalingStep, NumStepsLen, PointsStage};

/// Number of curve points accumulated during `compute_p` for nested field
/// endoscaling verification.
///
/// This is the sum of:
/// - 2 proofs × 15 commitment components = 30
/// - 6 stage proof components (mesh_wx0, mesh_wx1, mesh_wy, ab.a, ab.b, mesh_xy)
/// - 1 f.commitment (base polynomial)
///
/// The endoscaling circuits process these 37 points across
/// `NumStepsLen::<NUM_ENDOSCALING_POINTS>::len()` = 9 steps.
pub(crate) const NUM_ENDOSCALING_POINTS: usize = 37;

/// Index of internal nested circuits registered into the mesh.
///
/// These correspond to the circuit objects registered in [`register_all`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum InternalCircuitIndex {
    /// `EndoscalarStage` stage mask (index 0)
    EndoscalarStage,
    /// `PointsStage` stage mask (index 1)
    PointsStage,
    /// `PointsStage` final staged mask (index 2)
    PointsFinalStaged,
    /// `EndoscalingStep` circuit at given step (indices 3+)
    EndoscalingStep(usize),
}

impl InternalCircuitIndex {
    /// Convert to a [`CircuitIndex`] for mesh lookup.
    pub(crate) fn circuit_index(self) -> CircuitIndex {
        let idx = match self {
            Self::EndoscalarStage => 0,
            Self::PointsStage => 1,
            Self::PointsFinalStaged => 2,
            Self::EndoscalingStep(step) => 3 + step,
        };
        CircuitIndex::new(idx)
    }
}

pub mod stages;

/// Register internal nested circuits into the provided mesh.
pub(crate) fn register_all<'params, C: Cycle, R: Rank>(
    mut mesh: MeshBuilder<'params, C::ScalarField, R>,
) -> Result<MeshBuilder<'params, C::ScalarField, R>> {
    mesh = mesh.register_circuit_object(EndoscalarStage::mask()?)?;

    mesh =
        mesh.register_circuit_object(PointsStage::<C::HostCurve, NUM_ENDOSCALING_POINTS>::mask()?)?;

    mesh = mesh.register_circuit_object(
        PointsStage::<C::HostCurve, NUM_ENDOSCALING_POINTS>::final_mask()?,
    )?;

    let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();
    for step in 0..num_steps {
        let step_circuit = EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(step);
        let staged = Staged::new(step_circuit);
        mesh = mesh.register_circuit_object(staged.into_object()?)?;
    }
    Ok(mesh)
}
