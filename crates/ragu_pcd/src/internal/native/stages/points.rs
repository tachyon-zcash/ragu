//! The native points stages: the nested-curve commitments the nested batch
//! folds into $P_n$, and the interstitials of the endoscaling walk over
//! them.
//!
//! The nested side keeps its points in one stage, committed after $\beta$,
//! and binds that stage's inputs to the transcript-absorbed bridge stages
//! with a loading circuit. Here the inputs *are* the transcript-bound stage:
//! [`InputsStage`] holds the $f_n$ commitment and every other point, is
//! committed before $\beta$ is squeezed, and its host-curve commitment rides
//! in the `eval` bridge stage, so the points are fixed before the scalar
//! they are walked with. [`InterstitialsStage`] holds the walk's outputs
//! and is committed afterwards. A native stage holding copies alongside a
//! single points stage would not fit an endoscaling step in the gate
//! budget, which is why the layout differs from the nested one.
//!
//! The stages form a chain of their own, rooted at the
//! [`EndoscalarStage`], so that the endoscaling steps reserve only these
//! three stages.

use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    vec::{FixedVec, Len},
};

use crate::internal::endoscalar::{EndoscalarStage, InputsLen, NumStepsLen, PointsWitness};

/// The points the walk starts from and consumes.
#[derive(Clone)]
pub struct InputsWitness<C: CurveAffine, const NUM_POINTS: usize> {
    /// The initial accumulator: the $f_n$ commitment.
    pub initial: C,
    /// The remaining points, in walk order.
    pub inputs: FixedVec<C, InputsLen<NUM_POINTS>>,
}

impl<C: CurveAffine, const NUM_POINTS: usize> InputsWitness<C, NUM_POINTS> {
    /// The first point becomes `initial`, the rest `inputs`.
    ///
    /// # Panics
    ///
    /// Panics if `points.len() != NUM_POINTS`.
    pub fn new(points: &[C]) -> Self {
        assert_eq!(points.len(), NUM_POINTS, "expected {NUM_POINTS} points");
        Self {
            initial: points[0],
            inputs: FixedVec::from_fn(|i| points[1 + i]),
        }
    }
}

/// The walk's outputs, one per step.
#[derive(Clone)]
pub struct InterstitialsWitness<C: CurveAffine, const NUM_POINTS: usize> {
    pub interstitials: FixedVec<C, NumStepsLen<NUM_POINTS>>,
}

impl<C: CurveAffine, const NUM_POINTS: usize> From<PointsWitness<C, NUM_POINTS>>
    for InterstitialsWitness<C, NUM_POINTS>
{
    fn from(walk: PointsWitness<C, NUM_POINTS>) -> Self {
        Self {
            interstitials: walk.interstitials,
        }
    }
}

/// Output gadget of [`InputsStage`].
#[derive(Gadget)]
pub struct Inputs<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, const NUM_POINTS: usize> {
    #[ragu(gadget)]
    pub initial: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub inputs: FixedVec<Point<'dr, D, C>, InputsLen<NUM_POINTS>>,
}

/// Output gadget of [`InterstitialsStage`].
#[derive(Gadget)]
pub struct Interstitials<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, const NUM_POINTS: usize>
{
    #[ragu(gadget)]
    pub interstitials: FixedVec<Point<'dr, D, C>, NumStepsLen<NUM_POINTS>>,
}

/// Stage holding the walk's inputs.
#[derive(Default)]
pub struct InputsStage<C: CurveAffine, const NUM_POINTS: usize>(PhantomData<C>);

impl<C: CurveAffine, R: Rank, const NUM_POINTS: usize> staging::Stage<C::Base, R>
    for InputsStage<C, NUM_POINTS>
{
    type Parent = EndoscalarStage;
    type Witness<'source> = &'source InputsWitness<C, NUM_POINTS>;
    type OutputKind = Kind![C::Base; Inputs<'_, _, C, NUM_POINTS>];

    fn values() -> usize {
        // (x, y) of the initial point and of every input.
        2 * NUM_POINTS
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Inputs {
            initial: Point::alloc(dr, witness.as_ref().map(|w| w.initial))?,
            inputs: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.inputs[i]))
            })?,
        })
    }
}

/// Stage holding the walk's interstitials.
#[derive(Default)]
pub struct InterstitialsStage<C: CurveAffine, const NUM_POINTS: usize>(PhantomData<C>);

impl<C: CurveAffine, R: Rank, const NUM_POINTS: usize> staging::Stage<C::Base, R>
    for InterstitialsStage<C, NUM_POINTS>
{
    type Parent = InputsStage<C, NUM_POINTS>;
    type Witness<'source> = &'source InterstitialsWitness<C, NUM_POINTS>;
    type OutputKind = Kind![C::Base; Interstitials<'_, _, C, NUM_POINTS>];

    fn values() -> usize {
        // (x, y) of one interstitial per step.
        2 * NumStepsLen::<NUM_POINTS>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Interstitials {
            interstitials: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.interstitials[i]))
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::{EpAffine, Pasta};

    use super::*;
    use crate::internal::{
        native::NUM_ENDOSCALING_POINTS,
        tests::{R, assert_stage_values},
    };

    type C = <Pasta as ragu_arithmetic::Cycle>::NestedCurve;

    #[test]
    fn stage_values_match_wire_counts() {
        let _: PhantomData<EpAffine> = PhantomData::<C>;
        assert_stage_values::<_, R, _>(&InputsStage::<C, NUM_ENDOSCALING_POINTS>::default());
        assert_stage_values::<_, R, _>(&InterstitialsStage::<C, NUM_ENDOSCALING_POINTS>::default());
    }
}
