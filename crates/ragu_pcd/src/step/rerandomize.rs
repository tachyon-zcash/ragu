//! Rerandomization step for PCDs.
//!
//! This is a simple step: it takes any left header and combines it with the
//! trivial header `()` to produce the same left header. In order to ensure that
//! this rerandomization step synthesizes the same circuit no matter what the
//! left header is, we use a _raw_ encoding of the left header.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};

use core::marker::PhantomData;

use super::{Encoded, Encoder, Header, Index, Step};

pub(crate) struct Rerandomize<H> {
    _marker: PhantomData<H>,
}

impl<H> Rerandomize<H> {
    pub fn new() -> Self {
        Rerandomize {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, H: Header<C::CircuitField>> Step<C> for Rerandomize<H> {
    const INDEX: Index = Index::internal(0);

    type Witness<'source> = ();
    type Aux<'source> = ();

    type Left = H;
    type Right = ();
    type Output = H;

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
        let left = left.raw_encode(dr)?;
        let right = right.raw_encode(dr)?;

        // TODO(ebfull): It's possible that the witness for this step needs to
        // be populated with some random data, for actual re-randomization
        // (zero-knowledge), though it's not certain at this stage in
        // development. It's possible some other component(s) of the proof being
        // randomized is sufficient, which would be nice since it would avoid
        // extra work here. It would also be complicated to add random wires
        // here if the amount of wires needed depended on HEADER_SIZE and R:
        // Rank, both of which are not in scope here.

        Ok(((left.clone(), right, left), D::just(|| ())))
    }
}
