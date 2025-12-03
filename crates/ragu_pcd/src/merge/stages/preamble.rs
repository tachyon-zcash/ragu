//! Preamble stage for merge operations.

use ff::Field;
use ragu_circuits::{polynomials::Rank, staging::Stage};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};

/// The preamble stage of the merge witness.
pub struct Preamble<F, R> {
    _marker: core::marker::PhantomData<(F, R)>,
}

impl<F: Field, R: Rank> Stage<F, R> for Preamble<F, R> {
    type Parent = ();
    type Witness<'source> = ();
    type OutputKind = ();

    fn values() -> usize {
        0
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        _dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<F>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        Ok(())
    }
}
