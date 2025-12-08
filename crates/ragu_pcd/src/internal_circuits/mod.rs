use arithmetic::Cycle;
use ragu_circuits::{mesh::MeshBuilder, polynomials::Rank, staging::StageExt};
use ragu_core::Result;

// TODO: This should be derived from the actual number of circuits in the mesh.
pub const NUM_REVDOT_CLAIMS: usize = 3;

pub mod c;
pub mod dummy;
pub mod stages;
pub mod unified;

const DUMMY_CIRCUIT_ID: usize = 0;
const C_STAGED_ID: usize = 1;
const C_CIRCUIT_ID: usize = 2;
const NATIVE_PREAMBLE_STAGING_ID: usize = 3;

pub fn index(num_application_steps: usize, internal_index: usize) -> usize {
    num_application_steps + super::step::NUM_INTERNAL_STEPS + internal_index
}

pub fn register_all<'params, C: Cycle, R: Rank>(
    mesh: MeshBuilder<'params, C::CircuitField, R>,
    params: &'params C,
) -> Result<MeshBuilder<'params, C::CircuitField, R>> {
    let mesh = mesh.register_circuit(dummy::Circuit)?;
    let mesh = {
        let c = c::Circuit::<C, R, NUM_REVDOT_CLAIMS>::new(params);
        mesh.register_circuit_object(c.final_into_object()?)?
            .register_circuit(c)?
    };

    let mesh =
        mesh.register_circuit_object(stages::native::preamble::Stage::<C, R>::into_object()?)?;
    Ok(mesh)
}
