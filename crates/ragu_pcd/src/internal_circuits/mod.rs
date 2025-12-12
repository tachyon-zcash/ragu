use arithmetic::Cycle;
use ragu_circuits::{
    mesh::{CircuitIndex, MeshBuilder},
    polynomials::Rank,
    staging::StageExt,
};
use ragu_core::Result;

pub mod c;
pub mod dummy;
pub mod stages;
pub mod unified;
pub mod v;

// TODO: Placeholder value for the number of revdot claims.
pub const NUM_NATIVE_REVDOT_CLAIMS: usize = 3;

/// The number of internal circuits registered by [`register_all`].
pub const NUM_INTERNAL_CIRCUITS: usize = 8;

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

impl InternalCircuitIndex {
    pub fn circuit_index(self, num_application_steps: usize) -> CircuitIndex {
        CircuitIndex::new(num_application_steps + super::step::NUM_INTERNAL_STEPS + self as usize)
    }
}

pub fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    mesh: MeshBuilder<'params, C::CircuitField, R>,
    params: &'params C,
) -> Result<MeshBuilder<'params, C::CircuitField, R>> {
    let initial_count = mesh.circuit_count();

    // Predict final circuit count before registration.
    let expected_final_circuits = initial_count + NUM_INTERNAL_CIRCUITS;
    let log2_domain_size = expected_final_circuits.next_power_of_two().trailing_zeros();

    let mesh = mesh.register_circuit(dummy::Circuit)?;
    let mesh = {
        let c = c::Circuit::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::new(
            params,
            log2_domain_size,
        );
        mesh.register_circuit_object(c.final_into_object()?)?
            .register_circuit(c)?
    };
    let mesh = {
        let v = v::Circuit::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::new(params);
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

    // Verify prediction was correct (defense in depth).
    assert_eq!(
        mesh.circuit_count() - initial_count,
        NUM_INTERNAL_CIRCUITS,
        "internal circuit count mismatch"
    );
    assert_eq!(
        mesh.circuit_count(),
        expected_final_circuits,
        "circuit count prediction mismatch"
    );

    Ok(mesh)
}
