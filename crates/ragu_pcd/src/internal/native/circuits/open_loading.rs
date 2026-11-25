//! The loading bondings of an opening program run in chunks.
//!
//! The circuits that run the program ([`open`](super::open)) cannot
//! reserve the `query` and `eval` stages, which hold every evaluation of
//! the children's proofs: each reads copies of the values its steps take,
//! in its own polynomial of the [`band`](super::super::stages::open)
//! stage, committed with the circuits' polynomials. The evaluations the
//! program is over are the ones the transcript absorbed, in the two
//! stages, so each copy must be the value its stage holds: the bonding of a
//! band reserves the chain through the `eval` stage, with that band's
//! polynomial, and enforces every slot of the band equal to the stage wire
//! the [`Schedule`] gives it.
//!
//! `compute_v` has a band of its own, for what it exports off the two
//! stages, and a bonding for it.
//!
//! A bonding has no trace of its own: its claim is over the stage
//! polynomials alone, and it takes no gate beyond the stages'. A program
//! `compute_v` runs whole has none.

use alloc::sync::Arc;
use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::GadgetExt as _;

use super::super::{
    open::{Input, Schedule},
    stages::{
        eval as native_eval,
        open::{BandStage, CarryStage},
        points::BindingStage,
        preamble as native_preamble, query as native_query,
    },
};
use crate::profile::ProfiledCycle;

/// The loading bonding of one band of an opening program run in chunks.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize> {
    band: usize,
    schedule: Arc<Schedule>,
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Circuit<C, R, HEADER_SIZE> {
    /// The loading bonding of band `band` of the program `schedule`
    /// shares: a chunk's band by its index, and `compute_v`'s own after
    /// the chunks'.
    ///
    /// # Panics
    ///
    /// Panics if the schedule has no such band.
    pub fn new(band: usize, schedule: Arc<Schedule>) -> Self {
        assert!(band <= schedule.chunks(), "no such band");
        Self {
            band,
            schedule,
            _marker: PhantomData,
        }
    }
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> MultiStageCircuit<C::CircuitField, R>
    for Circuit<C, R, HEADER_SIZE>
{
    type Last = native_eval::Stage<C, R, HEADER_SIZE>;
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, ()>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        _witness: DriverValue<D, ()>,
    ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
        let dr = dr.skip_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let dr = dr.skip_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let dr = dr.skip_stage::<CarryStage<C, R, HEADER_SIZE>>()?;
        let (band, dr) = dr.add_stage::<BandStage<C, R, HEADER_SIZE>>()?;
        let (query, dr) = dr.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
        let (eval, dr) = dr.add_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
        let dr = dr.finish();

        // Load stage gadgets. Witness values are never accessed: the
        // circuit only runs during `into_bonding_object`, where MaybeKind =
        // Empty.
        macro_rules! w {
            () => {
                _witness.as_ref().map(|_| unreachable!())
            };
        }
        let band = band.unenforced(dr, w!())?;
        let query = query.unenforced(dr, w!())?;
        let eval = eval.unenforced(dr, w!())?;

        // Every copy is the value its stage holds.
        for (slot, &input) in self.schedule.band(self.band).iter().enumerate() {
            let source = match input {
                Input::Query(key) => query.value(key),
                Input::Eval(key) => eval.value(key),
            };
            band[slot].enforce_equal(dr, source)?;
        }

        Ok(WithAux::new((), D::unit()))
    }
}
