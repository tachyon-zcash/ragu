//! Nested A/B stage for merge operations.

use arithmetic::CurveAffine;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::Point;

use core::marker::PhantomData;

/// Output gadget for the nested A/B stage.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine> {
    /// The A commitment point.
    #[ragu(gadget)]
    pub a_commitment: Point<'dr, D, C>,
    /// The B commitment point.
    #[ragu(gadget)]
    pub b_commitment: Point<'dr, D, C>,
}

/// The nested A/B stage witnesses the commitment points for A and B polynomials.
pub struct Stage<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = ();
    type Witness<'source> = (C, C);
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        4 // 2 points = 4 elements
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let a_commitment = Point::alloc(dr, witness.view().map(|(a, _)| *a))?;
        let b_commitment = Point::alloc(dr, witness.view().map(|(_, b)| *b))?;
        Ok(Output {
            a_commitment,
            b_commitment,
        })
    }
}
