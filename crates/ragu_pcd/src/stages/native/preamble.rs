use arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};

use core::marker::PhantomData;

pub struct Stage<C: Cycle, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank> staging::Stage<C::CircuitField, R> for Stage<C, R> {
    type Parent = ();
    type Witness<'source> = ();
    type OutputKind = ();

    fn values() -> usize {
        0
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        _dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        Ok(())
    }
}
