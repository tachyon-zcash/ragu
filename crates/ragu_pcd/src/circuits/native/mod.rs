use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::StageExt,
};
use ragu_core::Result;

use super::NativeParameters;
use crate::step;

pub mod stages;

pub(crate) mod compute_v;
pub(crate) mod full_collapse;
pub(crate) mod hashes_1;
pub(crate) mod hashes_2;
pub(crate) mod partial_collapse;
pub(crate) mod unified;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub(crate) enum InternalCircuitIndex {
    // Native stages
    PreambleStage = 0,
    ErrorMStage = 1,
    ErrorNStage = 2,
    QueryStage = 3,
    EvalStage = 4,
    // Final stage masks
    ErrorMFinalStaged = 5,
    ErrorNFinalStaged = 6,
    EvalFinalStaged = 7,
    // Actual circuits
    Hashes1Circuit = 8,
    Hashes2Circuit = 9,
    PartialCollapseCircuit = 10,
    FullCollapseCircuit = 11,
    ComputeVCircuit = 12,
}

/// The number of internal circuits registered by [`register_all`] and
/// [`super::nested::register_all`], and the number of variants in [`InternalCircuitIndex`].
pub(crate) const NUM_INTERNAL_CIRCUITS: usize = 13;

/// Compute the total circuit count and log2 domain size from the number of
/// application-defined steps.
pub(crate) fn total_circuit_counts(num_application_steps: usize) -> (usize, u32) {
    let total_circuits = num_application_steps + step::NUM_INTERNAL_STEPS + NUM_INTERNAL_CIRCUITS;
    let log2_circuits = total_circuits.next_power_of_two().trailing_zeros();
    (total_circuits, log2_circuits)
}

impl InternalCircuitIndex {
    pub(crate) fn circuit_index(self, num_application_steps: usize) -> CircuitIndex {
        CircuitIndex::new(num_application_steps + step::NUM_INTERNAL_STEPS + self as usize)
    }
}

/// Register internal native circuits into the provided registry.
pub(crate) fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    mut registry: RegistryBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
    num_application_steps: usize,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>> {
    let initial_num_circuits = registry.num_circuits();

    // Insert the stages.
    {
        // preamble stage
        registry = registry
            .register_circuit_object(stages::preamble::Stage::<C, R, HEADER_SIZE>::mask()?)?;

        // error_m stage
        registry = registry.register_circuit_object(stages::error_m::Stage::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::mask()?)?;

        // error_n stage
        registry = registry.register_circuit_object(stages::error_n::Stage::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::mask()?)?;

        // query stage
        registry =
            registry.register_circuit_object(stages::query::Stage::<C, R, HEADER_SIZE>::mask()?)?;

        // eval stage
        registry =
            registry.register_circuit_object(stages::eval::Stage::<C, R, HEADER_SIZE>::mask()?)?;
    }

    // Insert the "final stage polynomials" for each stage.
    //
    // These are sometimes shared by multiple circuits. Each unique `Final`
    // stage is only registered once here.
    {
        // preamble -> error_n -> error_m -> [CIRCUIT] (partial_collapse)
        registry = registry.register_circuit_object(stages::error_m::Stage::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::final_mask()?)?;

        // preamble -> error_n -> [CIRCUIT] (hashes_1, hashes_2, full_collapse)
        registry = registry.register_circuit_object(stages::error_n::Stage::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::final_mask()?)?;

        // preamble -> query -> eval -> [CIRCUIT] (compute_v)
        registry = registry
            .register_circuit_object(stages::eval::Stage::<C, R, HEADER_SIZE>::final_mask()?)?;
    }

    // Insert the internal circuits.
    {
        // hashes_1
        registry = registry.register_circuit(hashes_1::Circuit::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::new(params, log2_circuits))?;

        // hashes_2
        registry =
            registry.register_circuit(
                hashes_2::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(params),
            )?;

        // partial_collapse
        registry = registry.register_circuit(partial_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::new())?;

        // full_collapse
        registry = registry.register_circuit(full_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::new())?;

        // compute_v
        registry = registry.register_circuit(compute_v::Circuit::<C, R, HEADER_SIZE>::new(
            num_application_steps,
        ))?;
    }

    // Verify we registered the expected number of circuits.
    assert_eq!(
        registry.num_circuits(),
        initial_num_circuits + NUM_INTERNAL_CIRCUITS,
        "internal circuit count mismatch"
    );

    Ok(registry)
}
