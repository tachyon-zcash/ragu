//! Internal step that produces a valid proof with trivial header.
//!
//! Used in rerandomization to create a properly-structured trivial proof that
//! can be folded with a valid proof without causing C value mismatches.

use ragu_arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};

use super::super::{Encoded, Step};

pub(crate) struct Trivial;

impl Trivial {
    pub fn new() -> Self {
        Trivial
    }
}

impl<C: Cycle> Step<C> for Trivial {
    type Witness<'source> = ();
    type Aux<'source> = ();

    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::just(|| ())))
    }
}
