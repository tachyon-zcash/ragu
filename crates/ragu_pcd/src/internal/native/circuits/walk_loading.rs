//! The loading bondings of a native walk of several segments.
//!
//! The steps of such a walk ([`segment_step`](super::segment_step)) read
//! copies of the walk's points from their segment's polynomial of
//! [`SegmentStage`], committed after $\beta$. The walk is over the points
//! the transcript absorbed before $\beta$, so each copy must be the point
//! its stage committed: the bonding of a segment reserves the whole points
//! chain, with that segment's polynomial, and enforces
//!
//! - every input the segment holds equal to the walk's input at the same
//!   position, read from the stage that committed it;
//! - the segment's initial point equal to $F_n$, the walk's, for the first
//!   segment, and to the boundary the previous segment ended in for every
//!   other;
//! - the interstitial of the segment's last step equal to its own boundary,
//!   for every segment but the last.
//!
//! So the segments, each a walk of its own, are one walk over the committed
//! points, and the last segment's last interstitial, which
//! `bind_endoscalar` pins to the instance, is its result. The equalities
//! also carry the curve membership the steps enforce on their copies to
//! the stages the points were committed in.
//!
//! A bonding has no trace of its own: its claim is over the stage
//! polynomials alone, and it takes no gate beyond the stages'. A walk of
//! one segment has none.

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::GadgetExt as _;

use super::super::{
    segments,
    stages::points::{
        AbStage, BindingStage, BitsStage, BoundariesStage, FStage, PreambleStage, RegistryWxStage,
        SegmentStage, WalkInputs,
    },
};
use crate::profile::ProfiledCycle;

/// The loading bonding of one segment of a native walk of several
/// segments.
pub struct Circuit<C: Cycle, R> {
    segment: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank> Circuit<C, R> {
    /// The loading bonding of segment `segment` of the walk.
    ///
    /// # Panics
    ///
    /// Panics if the profile's walk is one segment, or has no such
    /// segment.
    pub fn new(segment: usize) -> Self {
        let walk = segments::<C::Profile>();
        assert!(
            walk.is_split(),
            "a walk of one segment reads the stages that commit its points"
        );
        assert!(segment < walk.count(), "no such segment");
        Self {
            segment,
            _marker: PhantomData,
        }
    }
}

impl<C: ProfiledCycle, R: Rank> MultiStageCircuit<C::CircuitField, R> for Circuit<C, R> {
    type Last = FStage<C::NestedCurve, C::Profile>;
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, ()>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        _witness: DriverValue<D, ()>,
    ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
        let (binding, dr) = dr.add_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let dr = dr.skip_stage::<BitsStage<C::NestedCurve, C::Profile>>()?;
        let (segment, dr) = dr.add_stage::<SegmentStage<C::NestedCurve, C::Profile>>()?;
        let (boundaries, dr) = dr.add_stage::<BoundariesStage<C::NestedCurve, C::Profile>>()?;
        let (preamble, dr) = dr.add_stage::<PreambleStage<C::NestedCurve, C::Profile>>()?;
        let (registry_wx, dr) = dr.add_stage::<RegistryWxStage<C::NestedCurve, C::Profile>>()?;
        let (ab, dr) = dr.add_stage::<AbStage<C::NestedCurve, C::Profile>>()?;
        let (f, dr) = dr.add_stage::<FStage<C::NestedCurve, C::Profile>>()?;
        let dr = dr.finish();

        // Load stage gadgets. Witness values are never accessed: the
        // circuit only runs during `into_bonding_object`, where MaybeKind =
        // Empty.
        macro_rules! w {
            () => {
                _witness.as_ref().map(|_| unreachable!())
            };
        }
        let binding = binding.unenforced(dr, w!())?;
        let segment = segment.unenforced(dr, w!())?;
        let boundaries = boundaries.unenforced(dr, w!())?;
        let preamble = preamble.unenforced(dr, w!())?;
        let registry_wx = registry_wx.unenforced(dr, w!())?;
        let ab = ab.unenforced(dr, w!())?;
        let f = f.unenforced(dr, w!())?;
        let inputs = WalkInputs {
            binding: &binding,
            preamble: &preamble,
            registry_wx: &registry_wx,
            ab: &ab,
            f: &f,
        };

        // The inputs the segment holds, each where the walk has it.
        let walk = segments::<C::Profile>();
        for (slot, input) in walk.inputs_of(self.segment).enumerate() {
            segment.inputs[slot].enforce_equal(dr, inputs.input(input))?;
        }

        // The initial point: the walk's, $F_n$, or the boundary the
        // previous segment ended in.
        match self.segment.checked_sub(1) {
            None => segment.initial[0].enforce_equal(dr, inputs.initial())?,
            Some(previous) => segment.initial[0].enforce_equal(dr, &boundaries[previous])?,
        }
        // Every segment but the last ends in its own boundary: the
        // interstitial of its last step.
        if self.segment + 1 < walk.count() {
            segment.interstitials[walk.steps_per_segment() - 1]
                .enforce_equal(dr, &boundaries[self.segment])?;
        }

        Ok(WithAux::new((), D::unit()))
    }
}
