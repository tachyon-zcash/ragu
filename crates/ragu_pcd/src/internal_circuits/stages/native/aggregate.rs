//! Aggregate stage for routing nested commitments to endoscaling slots.

use arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    vec::{ConstLen, FixedVec},
};

use core::marker::PhantomData;

/// Contains all the commitments to be routed to endoscaling slots.
pub struct Witness<C: CurveAffine, const NUM_SLOTS: usize> {
    pub commitments: FixedVec<C, ConstLen<NUM_SLOTS>>,
}

/// Output gadget for the aggregate stage.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine, const NUM_SLOTS: usize> {
    #[ragu(gadget)]
    pub slots: FixedVec<Point<'dr, D, C>, ConstLen<NUM_SLOTS>>,
}

/// Stage that holds all nested commitments for endoscaling.
#[derive(Default)]
pub struct Stage<C: CurveAffine, const NUM_SLOTS: usize> {
    _marker: PhantomData<C>,
}

impl<C: CurveAffine, R: Rank, const NUM_SLOTS: usize> staging::Stage<C::Base, R>
    for Stage<C, NUM_SLOTS>
{
    type Parent = ();
    type Witness<'source> = &'source Witness<C, NUM_SLOTS>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, NUM_SLOTS>];

    fn values() -> usize {
        2 * NUM_SLOTS
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let slots =
            FixedVec::try_from_fn(|i| Point::alloc(dr, witness.view().map(|w| w.commitments[i])))?;
        Ok(Output { slots })
    }
}
