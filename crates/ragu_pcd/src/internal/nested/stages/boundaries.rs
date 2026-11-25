//! Boundaries stage for nested fuse operations: the points a nested walk of
//! several segments hands from each segment to the next.
//!
//! A walk of several segments has one polynomial of the points stage per
//! segment (see [`Walk`](crate::internal::nested::Walk)), each a walk of
//! its own from its initial point. A step loads one of them, so no step
//! sees both the interstitial a segment ends in and the initial point the
//! next segment starts from. This stage holds one point per segment but
//! the last, and the loading circuit of each segment, which loads this
//! stage beside the segment's polynomial, holds the segment's initial
//! point to the previous segment's entry and its last interstitial to its
//! own: the next segment so starts where the last one ended.
//!
//! The stage follows the points stage and precedes the bridge stages, so
//! the instance circuits reserve it; they do not read it. Its points need
//! no curve check of their own: each equals an interstitial its step holds
//! to the curve. A walk of one segment has no boundary: the stage holds
//! nothing, takes no gate, and is neither registered nor committed.

use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    vec::{FixedVec, Len},
};
use udon::curve::EndomorphismAffine as Affine;

use crate::{
    internal::nested::{NumBoundaries, PointsStage},
    profile::Profile,
};

/// The boundaries stage: each segment's last interstitial, the last
/// segment's aside, in walk order.
pub struct Stage<C: Affine, P: Profile> {
    _marker: PhantomData<(C, P)>,
}

impl<C: Affine, P: Profile> Default for Stage<C, P> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Profile> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, P> {
    type Parent = PointsStage<C, P>;
    type Witness<'source> = &'source FixedVec<C, NumBoundaries<P>>;
    type OutputKind = Kind![C::Base; FixedVec<Point<'_, _, C>, NumBoundaries<P>>];

    fn values() -> usize {
        // (x, y) per point.
        2 * NumBoundaries::<P>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        FixedVec::try_from_fn(|i| Point::alloc(dr, witness.as_ref().map(|w| w[i])))
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::EqAffine;

    use super::*;
    use crate::{
        internal::tests::{R, assert_stage_values},
        profile::{Standard, testing::Segmented},
    };

    #[test]
    fn stage_values_matches_wire_count() {
        // Nothing for a walk of one segment, a point per further segment
        // otherwise.
        assert_eq!(
            <Stage<EqAffine, Standard> as ragu_circuits::staging::Stage<_, R>>::values(),
            0
        );
        assert_stage_values::<_, R, _>(&Stage::<EqAffine, Standard>::default());
        assert!(<Stage<EqAffine, Segmented> as ragu_circuits::staging::Stage<_, R>>::values() > 0);
        assert_stage_values::<_, R, _>(&Stage::<EqAffine, Segmented>::default());
    }
}
