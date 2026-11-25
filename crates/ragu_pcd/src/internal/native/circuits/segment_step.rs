//! The steps of a native walk of several segments: the Horner walk over the
//! nested-curve commitments the nested batch folds into $P_n$, the
//! profile's endoscalings per step, over one segment's points.
//!
//! A step of a walk held in one stage
//! ([`endoscaling_step`](super::endoscaling_step)) reserves every stage that
//! commits a point of the walk. A walk of several segments
//! ([`Walk`](crate::internal::native::Walk)) is past what a step can
//! reserve, so its steps read [`SegmentStage`] instead, which holds one
//! segment as a walk of its own: step $k$ of the segment starts from the
//! previous interstitial (or the segment's initial point for step 0),
//! endoscales it by [`BitsStage`]'s endoscalar bits and adds each of its
//! inputs in turn, and enforces the result equal to its own interstitial. A
//! proof carries a polynomial of [`SegmentStage`] per segment, and the
//! step's claim names its own segment's.
//!
//! The segment's points are copies: a
//! [`walk_loading`](super::walk_loading) bonding holds each to the stage
//! that committed it, and chains the segments. `bind_endoscalar` binds the
//! bits to `pre_beta` as it does the walk stage's, but it loads one
//! polynomial of [`SegmentStage`], so it cannot hold every segment's points
//! to the curve: the step holds the points it reads and writes to the curve
//! itself, and the bondings carry that to the stages the points were
//! committed in.
//!
//! A step exposes no values, and its public output is the zero suffix every
//! internal circuit carries, as a step's of a walk of one segment is.

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, NonzeroBank, WithSuffix, consistent::Consistent};

use super::{
    super::{
        segments,
        stages::points::{BindingStage, BitsStage, SegmentStage},
    },
    endoscaling_step::Witness,
};
use crate::{
    internal::endoscalar::input_range,
    profile::{Profile, ProfiledCycle},
};

/// One step of a native endoscaling walk of several segments.
#[derive(Clone)]
pub struct Circuit<C: Cycle, R: Rank> {
    step: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank> Circuit<C, R> {
    /// Creates step `step` of the walk.
    ///
    /// # Panics
    ///
    /// Panics if the profile's walk is one segment, or if `step` is not a
    /// step of the walk.
    pub fn new(step: usize) -> MultiStage<C::CircuitField, R, Self> {
        let walk = segments::<C::Profile>();
        assert!(
            walk.is_split(),
            "the steps of a walk of one segment read the stages that commit its points"
        );
        assert!(
            step < walk.steps(),
            "step {step} exceeds available steps ({})",
            walk.steps()
        );
        MultiStage::new(Self {
            step,
            _marker: PhantomData,
        })
    }
}

impl<C: ProfiledCycle, R: Rank> MultiStageCircuit<C::CircuitField, R> for Circuit<C, R> {
    type Last = SegmentStage<C::NestedCurve, C::Profile>;
    type Instance<'source> = ();
    type Witness<'source> = Witness<'source, C>;
    type Output = Kind![C::CircuitField; WithSuffix<'_, _, ()>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(WithSuffix::new((), Element::zero(dr)))
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        // The binding stage is the root of every native chain; the step
        // reads none of it.
        let dr = dr.skip_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let (bits, dr) = dr.add_stage::<BitsStage<C::NestedCurve, C::Profile>>()?;
        let (segment, dr) = dr.add_stage::<SegmentStage<C::NestedCurve, C::Profile>>()?;
        let dr = dr.finish();

        let walk = segments::<C::Profile>();
        let (index, local) = walk.locate(self.step);

        let bits = bits.unenforced(dr, witness.as_ref().map(|w| w.walk))?;
        let segment =
            segment.unenforced(dr, witness.as_ref().map(|w| w.walk.segment_of(self.step)))?;
        let endoscalar = &bits[0];

        // The step's inputs, among the ones its segment holds: the segment
        // the walk ends in may hold fewer than the stage has room for.
        let range = input_range(
            C::Profile::NATIVE_ENDOSCALINGS_PER_STEP,
            local,
            walk.inputs_of(index).len(),
        );
        assert!(!range.is_empty());

        // The points the step reads and writes lie on the curve. The
        // interstitial a later step starts from is the one the step before
        // it held there.
        if local == 0 {
            segment.initial[0].enforce_consistent(dr)?;
        }
        for idx in range.clone() {
            segment.inputs[idx].enforce_consistent(dr)?;
        }
        segment.interstitials[local].enforce_consistent(dr)?;

        let initial = local
            .checked_sub(1)
            .map(|previous| &segment.interstitials[previous])
            .unwrap_or(&segment.initial[0])
            .clone();

        let acc = NonzeroBank::scope(dr, |dr, bank| {
            let mut acc = initial;
            for idx in range {
                let scaled = endoscalar.group_scale(dr, &acc)?;
                acc = scaled.add_incomplete(dr, &segment.inputs[idx], bank)?;
            }
            Ok(acc)
        })?;
        acc.enforce_equal(dr, &segment.interstitials[local])?;

        Ok(WithAux::new(
            WithSuffix::new((), Element::zero(dr)),
            D::unit(),
        ))
    }
}
