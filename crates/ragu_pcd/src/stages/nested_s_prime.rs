//! Nested s' stage for merge operations.

use arithmetic::CurveAffine;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::Point;

use core::marker::PhantomData;

/// The nested s' stage witnesses the mesh polynomial commitments.
pub struct Stage<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = ();
    type Witness<'source> = (C, C);
    type OutputKind = Kind![C::Base; (Point<'_, _, C>, Point<'_, _, C>)];

    fn values() -> usize {
        4
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let mesh_wx0 = Point::alloc(dr, witness.view().map(|w| w.0))?;
        let mesh_wx1 = Point::alloc(dr, witness.view().map(|w| w.1))?;
        Ok((mesh_wx0, mesh_wx1))
    }
}
