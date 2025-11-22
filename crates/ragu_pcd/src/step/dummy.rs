//! Dummy step for trivial proofs.
//!
//! This is the simplest step: it takes two trivial headers `()` and combines
//! them to produce another trivial header `()`. This is used to create the
//! base trivial proof that can be used as input to other steps.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};

use core::marker::PhantomData;

use super::{Encoded, Encoder, Index, Step};

pub(crate) struct DummyStep {
    _marker: PhantomData<()>,
}

impl DummyStep {
    pub fn new() -> Self {
        DummyStep {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle> Step<C> for DummyStep {
    const INDEX: Index = Index::internal(1);

    type Witness<'source> = ();
    type Aux<'source> = ();

    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let left = left.encode(dr)?;
        let right = right.encode(dr)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::just(|| ())))
    }
}
