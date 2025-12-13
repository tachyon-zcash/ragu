use arithmetic::Cycle;
use ragu_circuits::{
    mesh::{CircuitIndex, MeshBuilder},
    polynomials::Rank,
    staging::StageExt,
};
use ragu_core::Result;

use crate::components::root_of_unity::Log2Circuits;

pub mod c;
pub mod dummy;
pub mod stages;
pub mod unified;
pub mod v;

// TODO: Placeholder value for the number of revdot claims.
pub const NUM_NATIVE_REVDOT_CLAIMS: usize = 3;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum InternalCircuitIndex {
    DummyCircuit = 0,
    ClaimStaged = 1,
    ClaimCircuit = 2,
    VStaged = 3,
    VCircuit = 4,
    PreambleStage = 5,
    QueryStage = 6,
    EvalStage = 7,
}

/// The number of internal circuits used for recursion plumbing.
pub const NUM_INTERNAL_CIRCUITS: usize = 8;

impl InternalCircuitIndex {
    pub fn circuit_index(self, num_application_steps: usize) -> CircuitIndex {
        CircuitIndex::new(num_application_steps + super::step::NUM_INTERNAL_STEPS + self as usize)
    }
}

pub fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    mesh: MeshBuilder<'params, C::CircuitField, R>,
    params: &'params C,
    log2_circuits: u32,
) -> Result<MeshBuilder<'params, C::CircuitField, R>> {
    let log2_circuits = Log2Circuits::new(log2_circuits);
    let initial_count = mesh.num_circuits();
    let mesh = mesh.register_circuit(dummy::Circuit)?;
    let mesh = {
        let c =
            c::Circuit::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::new(params, log2_circuits);
        mesh.register_circuit_object(c.final_into_object()?)?
            .register_circuit(c)?
    };
    let mesh = {
        let v =
            v::Circuit::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::new(params, log2_circuits);
        mesh.register_circuit_object(v.final_into_object()?)?
            .register_circuit(v)?
    };

    let mesh = mesh.register_circuit_object(
        stages::native::preamble::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;
    let mesh = mesh.register_circuit_object(
        stages::native::query::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;
    let mesh = mesh.register_circuit_object(
        stages::native::eval::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;

    // Assert exactly NUM_INTERNAL_CIRCUITS were registered.
    assert_eq!(mesh.num_circuits(), initial_count + NUM_INTERNAL_CIRCUITS,);

    Ok(mesh)
}
