//! Internal step that bootstraps the recursion.
//!
//! This is the only step declaring [`Dummy`] inputs, and so the only circuit
//! that can take the base case: its fuse skips the child revdot claim (see
//! [`outer_collapse`]). [`finalize`] runs it once over two synthesized
//! [`dummy_pcd`] proofs to produce the bootstrap proof, which [`seed`] then
//! consumes as an ordinary, fully verified child of every seed step.
//!
//! Because this step ignores its children and outputs the data-less unit
//! header, its proof attests nothing and any prover can mint one. Confining the
//! base case here rests on every other circuit's declared input suffixes being
//! unable to equal `Dummy` — constants for application steps, and a wire
//! constrained away from it for rerandomization. An ordinary step consuming
//! the resulting `Pcd<()>` still verifies its child claim.
//!
//! [`dummy_pcd`]: crate::Application::dummy_pcd
//! [`finalize`]: crate::ApplicationBuilder::finalize
//! [`seed`]: crate::Application::seed
//! [`outer_collapse`]: crate::internal::native::circuits::outer_collapse

use ragu_arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};
use ragu_primitives::allocator::Standard;

use super::super::{Encoded, Index, Step};
pub(crate) use crate::step::InternalStepIndex::Bootstrap as INTERNAL_ID;
use crate::{Header, header::Dummy};

pub(crate) struct Bootstrap;

impl Bootstrap {
    pub fn new() -> Self {
        Bootstrap
    }
}

impl<C: Cycle> Step<C> for Bootstrap {
    const INDEX: Index = Index::internal(INTERNAL_ID);

    type Witness<'source> = ();
    type Aux<'source> = ();

    type Left = Dummy;
    type Right = Dummy;
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
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::unit(), D::unit()))
    }
}
