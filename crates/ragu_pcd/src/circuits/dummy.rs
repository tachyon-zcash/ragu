use ff::Field;
use ragu_circuits::Circuit;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
};
use ragu_primitives::{Element, vec::FixedVec};

use alloc::vec;

use crate::step::adapter::TripleConstLen;

pub struct Dummy<const HEADER_SIZE: usize>;

impl<F: Field, const HEADER_SIZE: usize> Circuit<F> for Dummy<HEADER_SIZE> {
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = Kind![F; FixedVec<Element<'_, _>, TripleConstLen<HEADER_SIZE>>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let mut trivial_header = vec![Element::zero(dr); HEADER_SIZE * 3];
        trivial_header[0] = Element::one(); // Reserved prefix for trivial header.

        Ok(FixedVec::try_from(trivial_header).unwrap())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let mut trivial_header = vec![Element::zero(dr); HEADER_SIZE * 3];
        trivial_header[0] = Element::one(); // Reserved prefix for trivial header.

        Ok((FixedVec::try_from(trivial_header).unwrap(), D::just(|| ())))
    }
}
