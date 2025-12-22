use arithmetic::Cycle;
use ragu_circuits::{
    mesh::{CircuitIndex, MeshBuilder},
    polynomials::Rank,
    staging::StageExt,
};
use ragu_core::Result;

pub mod bridge;
pub mod compute_c;
pub mod compute_v;
pub mod dummy;
pub mod fold;
pub mod hashes_1;
pub mod hashes_2;
pub mod stages;
pub mod unified;

pub use crate::components::fold_revdot::NativeParameters;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum InternalCircuitIndex {
    DummyCircuit = 0,
    Hashes1Staged = 1,
    Hashes1Circuit = 2,
    Hashes2Staged = 3,
    Hashes2Circuit = 4,
    FoldStaged = 5,
    FoldCircuit = 6,
    ComputeCStaged = 7,
    ComputeCCircuit = 8,
    ComputeVStaged = 9,
    ComputeVCircuit = 10,
    BridgeStaged = 11,
    BridgeCircuit = 12,
    PreambleStage = 13,
    ErrorMStage = 14,
    ErrorNStage = 15,
    QueryStage = 16,
    EvalStage = 17,
}

/// The number of internal circuits registered by [`register_all`],
/// and the number of variants in [`InternalCircuitIndex`].
pub const NUM_INTERNAL_CIRCUITS: usize = 18;

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
    let initial_num_circuits = mesh.num_circuits();

    let mesh = mesh.register_circuit(dummy::Circuit)?;
    let mesh = {
        let hashes_1 =
            hashes_1::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(params, log2_circuits);
        mesh.register_circuit_object(hashes_1.final_into_object()?)?
            .register_circuit(hashes_1)?
    };
    let mesh = {
        let hashes_2 = hashes_2::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(params);
        mesh.register_circuit_object(hashes_2.final_into_object()?)?
            .register_circuit(hashes_2)?
    };
    let mesh = {
        let fold = fold::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new();
        mesh.register_circuit_object(fold.final_into_object()?)?
            .register_circuit(fold)?
    };
    let mesh = {
        let compute_c = compute_c::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new();
        mesh.register_circuit_object(compute_c.final_into_object()?)?
            .register_circuit(compute_c)?
    };
    let mesh = {
        let compute_v = compute_v::Circuit::<C, R, HEADER_SIZE>::new();
        mesh.register_circuit_object(compute_v.final_into_object()?)?
            .register_circuit(compute_v)?
    };
    let mesh = {
        let bridge = bridge::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new();
        mesh.register_circuit_object(bridge.final_into_object()?)?
            .register_circuit(bridge)?
    };

    let mesh = mesh.register_circuit_object(
        stages::native::preamble::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;
    let mesh = mesh.register_circuit_object(stages::native::error_m::Stage::<
        C,
        R,
        HEADER_SIZE,
        NativeParameters,
    >::into_object()?)?;
    let mesh = mesh.register_circuit_object(stages::native::error_n::Stage::<
        C,
        R,
        HEADER_SIZE,
        NativeParameters,
    >::into_object()?)?;
    let mesh = mesh.register_circuit_object(
        stages::native::query::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;
    let mesh = mesh.register_circuit_object(
        stages::native::eval::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;

    // Verify we registered the expected number of circuits.
    assert_eq!(
        mesh.num_circuits(),
        initial_num_circuits + NUM_INTERNAL_CIRCUITS,
        "internal circuit count mismatch"
    );

    Ok(mesh)
}
