//! Circuit for routing `NestedCurve` commitments to endoscaling slots,
//! collecting commitments from the unified instance and placing them
//! into the aggregate stage for endoscaling.

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};

use core::marker::PhantomData;

use super::{
    stages::native::aggregate,
    unified::{self, OutputBuilder},
};

/// The routing circuit that places commitments into aggregate slots for endoscaling.
pub struct Circuit<C: Cycle, R: Rank, const NUM_SLOTS: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const NUM_SLOTS: usize> Circuit<C, R, NUM_SLOTS> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
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

        let _aggregate_output =
            aggregate_guard.enforced(dr, witness.view().map(|w| w.aggregate_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let unified_output = OutputBuilder::new();

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
