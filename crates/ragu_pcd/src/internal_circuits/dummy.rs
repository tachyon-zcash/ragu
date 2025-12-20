use core::marker::PhantomData;

use arithmetic::PrimeFieldExt;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
};
use ragu_primitives::{Element, vec::FixedVec};

use crate::step::adapter::TripleConstLen;

pub use crate::internal_circuits::InternalCircuitIndex::DummyCircuit as CIRCUIT_ID;

/// The dummy circuit for trivial proofs.
pub struct Circuit<const HEADER_SIZE: usize> {
    _marker: PhantomData<()>,
}

impl<const HEADER_SIZE: usize> Circuit<HEADER_SIZE> {
    pub fn new() -> Self {
        Circuit {
            _marker: PhantomData,
        }
    }
}

impl<const HEADER_SIZE: usize> Default for Circuit<HEADER_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeFieldExt, const HEADER_SIZE: usize> ragu_circuits::Circuit<F>
    for Circuit<HEADER_SIZE>
{
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = Kind![F; FixedVec<Element<'_, _>, TripleConstLen<HEADER_SIZE>>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let mut elements = alloc::vec::Vec::with_capacity(HEADER_SIZE * 3);

        for _ in 0..HEADER_SIZE {
            elements.push(Element::constant(dr, F::todo()));
        }

        for _ in 0..HEADER_SIZE {
            elements.push(Element::constant(dr, F::todo()));
        }

        for _ in 0..(HEADER_SIZE - 1) {
            elements.push(Element::zero(dr));
        }
        // Suffix for the () type.
        elements.push(Element::one());

        FixedVec::try_from(elements)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let instance = self.instance(dr, D::just(|| ()))?;
        Ok((instance, D::just(|| ())))
    }
}
