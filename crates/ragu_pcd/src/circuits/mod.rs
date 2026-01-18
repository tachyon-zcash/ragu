use arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    mesh::MeshBuilder,
    polynomials::Rank,
    staging::{StageExt, Staged},
};
use ragu_core::Result;
use ragu_primitives::vec::Len;

use crate::components::endoscalar::{EndoscalarStage, EndoscalingStep, NumStepsLen, PointsStage};
use crate::proof::NUM_P_COMMITMENTS;

pub(crate) mod native;
pub(crate) mod nested;

pub(crate) use crate::components::fold_revdot::NativeParameters;

/// Register internal nested circuits into the provided mesh.
pub(crate) fn register_all_nested<'params, C: Cycle, R: Rank>(
    mut mesh: MeshBuilder<'params, C::ScalarField, R>,
) -> Result<MeshBuilder<'params, C::ScalarField, R>> {
    mesh = mesh.register_circuit_object(EndoscalarStage::into_object()?)?;

    mesh = mesh
        .register_circuit_object(PointsStage::<C::HostCurve, NUM_P_COMMITMENTS>::into_object()?)?;

    mesh = mesh.register_circuit_object(
        PointsStage::<C::HostCurve, NUM_P_COMMITMENTS>::final_into_object()?,
    )?;

    let num_steps = NumStepsLen::<NUM_P_COMMITMENTS>::len();
    for step in 0..num_steps {
        let step_circuit = EndoscalingStep::<C::HostCurve, R, NUM_P_COMMITMENTS>::new(step);
        let staged = Staged::new(step_circuit);
        mesh = mesh.register_circuit_object(staged.into_object()?)?;
    }
    Ok(mesh)
}

#[cfg(test)]
pub(crate) mod tests;
