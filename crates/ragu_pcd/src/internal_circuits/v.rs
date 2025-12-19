use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, txz::Evaluate},
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};

use core::marker::PhantomData;

use super::{
    stages::native::{eval as native_eval, preamble as native_preamble, query as native_query},
    unified::{self, OutputBuilder},
};
pub use crate::internal_circuits::InternalCircuitIndex::VCircuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::VStaged as STAGED_ID;

pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Circuit<C, R, HEADER_SIZE> {
    pub fn new() -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle> {
    pub unified_instance: &'a unified::Instance<C>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> StagedCircuit<C::CircuitField, R>
    for Circuit<C, R, HEADER_SIZE>
{
    type Final = native_eval::Stage<C, R, HEADER_SIZE>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        OutputBuilder::new().finish(dr, &instance)
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
        let builder = builder.skip_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let builder = builder.skip_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
        let builder = builder.skip_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        let x = unified_output.x.get(dr, unified_instance)?;
        let z = unified_output.z.get(dr, unified_instance)?;

        let _txz = dr.routine(Evaluate::new(R::RANK), (x, z))?;

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
