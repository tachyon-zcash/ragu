//! Native curve circuits for recursive verification.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
};
use ragu_core::Result;

use super::NativeParameters;
use crate::step;

pub mod stages;

pub(crate) mod compute_v;
pub(crate) mod endoscale_challenges;
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
    // Native circuits
    Hashes1Circuit = 8,
    Hashes2Circuit = 9,
    PartialCollapseCircuit = 10,
    FullCollapseCircuit = 11,
    ComputeVCircuit = 12,
    EndoscaleChallengesCircuit = 13,
}

/// The number of internal circuits registered by [`register_all`] and
/// [`super::nested::register_all`], and the number of variants in [`InternalCircuitIndex`].
pub(crate) const NUM_INTERNAL_CIRCUITS: usize = 14;

/// Compute the total circuit count and log2 domain size from the number of
/// application-defined steps.
pub(crate) const fn total_circuit_counts(num_application_steps: usize) -> (usize, u32) {
    let total_circuits = num_application_steps + step::NUM_INTERNAL_STEPS + NUM_INTERNAL_CIRCUITS;
    let log2_circuits = total_circuits.next_power_of_two().trailing_zeros();
    (total_circuits, log2_circuits)
}

impl InternalCircuitIndex {
    pub(crate) const fn circuit_index(self) -> CircuitIndex {
        // Internal masks and circuits precede internal steps, so no offset
        // is needed.
        CircuitIndex::from_u32(self as u32)
    }
}

/// Registers internal native circuits into the provided registry.
///
/// All circuits registered here are internal and will be placed
/// before any application steps.
pub(crate) fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    mut registry: RegistryBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();

    // Insert the stages.
    {
        // preamble stage
        registry =
            registry.register_internal_mask::<stages::preamble::Stage<C, R, HEADER_SIZE>>()?;

        // error_m stage
        registry = registry
            .register_internal_mask::<stages::error_m::Stage<C, R, HEADER_SIZE, NativeParameters>>(
            )?;

        // error_n stage
        registry = registry
            .register_internal_mask::<stages::error_n::Stage<C, R, HEADER_SIZE, NativeParameters>>(
            )?;

        // query stage
        registry = registry.register_internal_mask::<stages::query::Stage<C, R, HEADER_SIZE>>()?;

        // eval stage
        registry = registry.register_internal_mask::<stages::eval::Stage<C, R, HEADER_SIZE>>()?;
    }

    // Insert the "final stage polynomials" for each stage.
    //
    // These are sometimes shared by multiple circuits. Each unique `Final`
    // stage is only registered once here.
    {
        // preamble -> error_n -> error_m -> [CIRCUIT] (partial_collapse)
        registry = registry.register_internal_final_mask::<stages::error_m::Stage<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >>()?;

        // preamble -> error_n -> [CIRCUIT] (hashes_1, hashes_2, full_collapse)
        registry = registry.register_internal_final_mask::<stages::error_n::Stage<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >>()?;

        // preamble -> query -> eval -> [CIRCUIT] (compute_v)
        registry =
            registry.register_internal_final_mask::<stages::eval::Stage<C, R, HEADER_SIZE>>()?;
    }

    // Insert the internal circuits.
    {
        // hashes_1
        registry = registry.register_internal_circuit(hashes_1::Circuit::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::new(params, log2_circuits))?;

        // hashes_2
        registry = registry.register_internal_circuit(hashes_2::Circuit::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::new(params))?;

        // partial_collapse
        registry = registry.register_internal_circuit(partial_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::new())?;

        // full_collapse
        registry = registry.register_internal_circuit(full_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::new())?;

        // compute_v
        registry =
            registry.register_internal_circuit(compute_v::Circuit::<C, R, HEADER_SIZE>::new())?;

        // endoscale_challenges
        registry = registry.register_internal_circuit(endoscale_challenges::Circuit::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::new())?;
    }

    // Verify we registered the expected number of internal circuits.
    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + NUM_INTERNAL_CIRCUITS,
        "internal circuit count mismatch"
    );

    Ok(registry)
}
