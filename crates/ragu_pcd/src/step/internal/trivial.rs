//! Internal step that produces a valid proof with trivial header.
//!
//! Used in rerandomization to create a properly-structured trivial proof that
//! can be folded with a valid proof without causing C value mismatches.

use ragu_arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};
use ragu_primitives::allocator::Standard;

use super::super::{BasicCx, Cx, Encoded, Index, Step};
pub(crate) use crate::step::InternalStepIndex::Trivial as INTERNAL_ID;
use crate::Header;

pub(crate) struct Trivial;

impl Trivial {
    pub fn new() -> Self {
        Trivial
    }
}

impl<C: Cycle> Step<C> for Trivial {
    const INDEX: Index = Index::internal(INTERNAL_ID);

    type Witness<'source> = ();
    type Aux<'source> = ();

    type Left = ();
    type Right = ();
    type Output = ();

    type Context<'a, 'dr, D>
        = BasicCx<'a, D>
    where
        'dr: 'a,
        D: Driver<'dr, F = C::CircuitField> + 'a;

    fn witness<
        'a,
        'dr,
        'source: 'dr,
        D: Driver<'dr, F = C::CircuitField>,
        const HEADER_SIZE: usize,
    >(
        &self,
        cx: &mut BasicCx<'a, D>,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        'dr: 'a,
    {
        let dr = cx.driver();
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::unit(), D::unit()))
    }
}
