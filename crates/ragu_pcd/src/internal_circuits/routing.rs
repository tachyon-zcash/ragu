//! Circuit for routing `NestedCurve` commitments to endoscaling slots.
//!
//! This circuit enforces that the commitments in the aggregate stage slots
//! match the corresponding nested commitments from the unified instance.

pub use crate::internal_circuits::InternalCircuitIndex::RoutingCircuit as CIRCUIT_ID;

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind},
    maybe::Maybe,
};

use core::marker::PhantomData;

use super::{
    stages::native::aggregate,
    unified::{self, OutputBuilder},
};

/// Number of endoscaling slots for routing the commitments.
///
/// This matches the number of nested commitments in the unified instance:
/// - nested_preamble_commitment
/// - nested_s_prime_commitment
/// - nested_error_m_commitment
/// - nested_error_n_commitment
/// - nested_ab_commitment
/// - nested_query_commitment
/// - nested_f_commitment
/// - nested_eval_commitment
/// - TODO: nested_p_commitment
pub const NUM_SLOTS: usize = 8;

/// The routing circuit that places commitments into aggregate slots for endoscaling.
pub struct Circuit<C: Cycle, R: Rank, const NUM_SLOTS: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const NUM_SLOTS: usize> Circuit<C, R, NUM_SLOTS> {
    pub fn new() -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness for the routing circuit.
pub struct Witness<'a, C: Cycle, const NUM_SLOTS: usize> {
    /// The unified instance containing challenges and nested commitments.
    pub unified_instance: &'a unified::Instance<C>,
    /// The aggregate stage witness.
    pub aggregate_witness: &'a aggregate::Witness<C::NestedCurve, NUM_SLOTS>,
}

impl<C: Cycle, R: Rank, const NUM_SLOTS: usize> StagedCircuit<C::CircuitField, R>
    for Circuit<C, R, NUM_SLOTS>
{
    type Final = aggregate::Stage<C::NestedCurve, NUM_SLOTS>;
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, NUM_SLOTS>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (aggregate_guard, builder) =
            builder.add_stage::<aggregate::Stage<C::NestedCurve, NUM_SLOTS>>()?;
        let dr = builder.finish();

        let aggregate_output =
            aggregate_guard.enforced(dr, witness.view().map(|w| w.aggregate_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Get the nested commitments from the unified instance.
        let nested_preamble = unified_output
            .nested_preamble_commitment
            .get(dr, unified_instance)?;
        let nested_s_prime = unified_output
            .nested_s_prime_commitment
            .get(dr, unified_instance)?;
        let nested_error_m = unified_output
            .nested_error_m_commitment
            .get(dr, unified_instance)?;
        let nested_error_n = unified_output
            .nested_error_n_commitment
            .get(dr, unified_instance)?;
        let nested_ab = unified_output
            .nested_ab_commitment
            .get(dr, unified_instance)?;
        let nested_query = unified_output
            .nested_query_commitment
            .get(dr, unified_instance)?;
        let nested_f = unified_output
            .nested_f_commitment
            .get(dr, unified_instance)?;
        let nested_eval = unified_output
            .nested_eval_commitment
            .get(dr, unified_instance)?;

        // Enforce that the aggregate slots match the unified instance's nested commitments.
        aggregate_output.slots[0].enforce_equal(dr, &nested_preamble)?;
        aggregate_output.slots[1].enforce_equal(dr, &nested_s_prime)?;
        aggregate_output.slots[2].enforce_equal(dr, &nested_error_m)?;
        aggregate_output.slots[3].enforce_equal(dr, &nested_error_n)?;
        aggregate_output.slots[4].enforce_equal(dr, &nested_ab)?;
        aggregate_output.slots[5].enforce_equal(dr, &nested_query)?;
        aggregate_output.slots[6].enforce_equal(dr, &nested_f)?;
        aggregate_output.slots[7].enforce_equal(dr, &nested_eval)?;

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
