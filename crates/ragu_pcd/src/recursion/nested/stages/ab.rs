//! AB stage for nested fuse operations: the native $A$ and $B$
//! commitments, and the commitment of the native points stage holding $A_n$
//! and $B_n$.

use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    io::Write,
    vec::{FixedVec, Len},
};
use udon::curve::EndomorphismAffine as Affine;

use crate::profile::{
    Profile,
    online::stages::{Native, PhaseLen},
};

/// Number of curve points in this stage.
const NUM: usize = 3;

/// Witness data for this bridge stage.
pub struct Witness<C: Affine, P: Profile> {
    /// Native auxiliary commitments fixed at this boundary.
    pub online_points: FixedVec<C, PhaseLen<P, Native, 2>>,
    pub a: C,
    pub b: C,
    /// Commitment of the native points stage holding the nested
    /// `registry_wy` commitment, $A_n$ and $B_n$, fixed here before $x$ is
    /// squeezed.
    pub native_points_ab: C,
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    /// Native auxiliary points bound to the walk and common claim target.
    #[ragu(gadget)]
    pub online_points: FixedVec<Point<'dr, D, C>, PhaseLen<P, Native, 2>>,
    #[ragu(gadget)]
    pub a: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub b: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub native_points_ab: Point<'dr, D, C>,
}

#[derive(Default)]
pub struct Stage<C: Affine, R, P> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R, P> {
    type Parent = super::outer_error::Stage<C, R, P>;
    type Witness<'source> = &'source Witness<C, P>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, P>];

    fn values() -> usize {
        (NUM + PhaseLen::<P, Native, 2>::len()) * 2
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Output {
            online_points: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.online_points[i]))
            })?,
            a: Point::alloc(dr, witness.as_ref().map(|w| w.a))?,
            b: Point::alloc(dr, witness.as_ref().map(|w| w.b))?,
            native_points_ab: Point::alloc(dr, witness.as_ref().map(|w| w.native_points_ab))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::EqAffine;

    use super::*;
    use crate::{
        profile::Standard,
        recursion::tests::{R, assert_stage_values},
    };

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R, Standard>::default());
    }
}
