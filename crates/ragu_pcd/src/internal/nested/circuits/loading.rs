//! Loading circuit for the nested section.
//!
//! Loads [`PointsStage`] and bridge stages (`preamble`, `s_prime`,
//! `inner_error`, `ab`, `query`, `f`) and enforces equality for all
//! [`PointsStage`] positions: every input (matched against
//! [`ChildWitness`](crate::internal::nested::stages::preamble::ChildWitness)
//! stash fields, current-step bridge stage fields and the online
//! commitments the preamble holds) plus `initial` (matched against
//! `BridgeF.native_f`). The accumulation walk mirrors `compute_p` in
//! `_10_p` so that correctness can be verified by visual comparison.
//!
//! A nested walk of several segments (see
//! [`Walk`](crate::internal::nested::Walk)) has a polynomial of
//! [`PointsStage`] per segment, and a loading circuit per segment over it:
//! the circuit holds the inputs its segment holds to their positions in the
//! same walk, and ties the segment to its neighbours through the
//! [`boundaries`](stages::boundaries) stage. The first segment's initial
//! point is `BridgeF.native_f` as before; every further segment's is the
//! boundary the previous segment ended in, and every segment but the last
//! ends in its own.

use core::{marker::PhantomData, ops::Range};

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{GadgetExt as _, Point, vec::Len};
use udon::curve::EndomorphismAffine as Affine;

use crate::{
    internal::{
        endoscalar::EndoscalarStage,
        native::RxIndex,
        nested::{NumPoints, Points, PointsStage, segments, stages},
    },
    profile::Profile,
};

/// A cursor over the walk's inputs that enforces equality between the
/// [`PointsStage`] inputs of one segment and the corresponding bridge stage
/// elements, and passes over the inputs other segments hold.
struct Walker<'pts, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    points: &'pts Points<'dr, D, C, P>,
    /// The walk's inputs the segment holds.
    held: Range<usize>,
    /// The walk's input the cursor is at.
    index: usize,
}

impl<'pts, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> Walker<'pts, 'dr, D, C, P> {
    fn new(points: &'pts Points<'dr, D, C, P>, held: Range<usize>) -> Self {
        Self {
            points,
            held,
            index: 0,
        }
    }

    /// Enforce that the walk's current input equals `point`, if the segment
    /// holds it.
    fn enforce_equal(&mut self, dr: &mut D, point: &Point<'dr, D, C>) -> Result<()> {
        if self.held.contains(&self.index) {
            self.points.inputs[self.index - self.held.start].enforce_equal(dr, point)?;
        }
        self.index += 1;
        Ok(())
    }

    /// Assert that the cursor passed every input of the walk.
    fn finish(self) {
        assert_eq!(
            self.index,
            NumPoints::<P>::len() - 1,
            "walker did not exhaust all PointsStage inputs"
        );
    }
}

/// Loading circuit that loads the entire nested stage hierarchy, over one
/// segment of the walk.
pub struct Circuit<C: Affine, R: Rank, P: Profile> {
    segment: usize,
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> Circuit<C, R, P> {
    /// The loading circuit of the walk's first segment: of the whole walk
    /// when it is one segment.
    pub fn new() -> Self {
        Self::segment(0)
    }

    /// The loading circuit of segment `segment` of the walk.
    ///
    /// # Panics
    ///
    /// Panics if the walk has no such segment.
    pub fn segment(segment: usize) -> Self {
        assert!(segment < segments::<P>().count(), "no such segment");
        Self {
            segment,
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Profile> MultiStageCircuit<C::Base, R> for Circuit<C, R, P> {
    type Last = stages::eval::Stage<C, R, P>;
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, ()>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        _witness: DriverValue<D, ()>,
    ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
        let dr = dr.skip_stage::<EndoscalarStage>()?;
        let dr = dr.skip_stage::<stages::bridge_hash::Stage<C>>()?;
        let (points_guard, dr) = dr.add_stage::<PointsStage<C, P>>()?;
        let (boundaries_guard, dr) = dr.add_stage::<stages::boundaries::Stage<C, P>>()?;
        let dr = dr.skip_stage::<stages::targets::Stage<C, P>>()?;
        let (preamble_guard, dr) = dr.add_stage::<stages::preamble::Stage<C, R, P>>()?;
        let (s_prime_guard, dr) = dr.add_stage::<stages::s_prime::Stage<C, R, P>>()?;
        let (inner_error_guard, dr) = dr.add_stage::<stages::inner_error::Stage<C, R, P>>()?;
        let dr = dr.skip_stage::<stages::outer_error::Stage<C, R, P>>()?;
        let (ab_guard, dr) = dr.add_stage::<stages::ab::Stage<C, R, P>>()?;
        let (query_guard, dr) = dr.add_stage::<stages::query::Stage<C, R, P>>()?;
        let (f_guard, dr) = dr.add_stage::<stages::f::Stage<C, R, P>>()?;
        let dr = dr.skip_stage::<stages::eval::Stage<C, R, P>>()?;
        let dr = dr.finish();

        // Load stage gadgets. Witness values are never accessed — the circuit
        // only runs during `into_bonding_object` where MaybeKind = Empty.
        macro_rules! w {
            () => {
                _witness.as_ref().map(|_| unreachable!())
            };
        }
        let points = points_guard.unenforced(dr, w!())?;
        let boundaries = boundaries_guard.unenforced(dr, w!())?;
        let preamble = preamble_guard.unenforced(dr, w!())?;
        let s_prime = s_prime_guard.unenforced(dr, w!())?;
        let inner_error = inner_error_guard.unenforced(dr, w!())?;
        let ab = ab_guard.unenforced(dr, w!())?;
        let query = query_guard.unenforced(dr, w!())?;
        let f_stage = f_guard.unenforced(dr, w!())?;

        // Walk through the walk's inputs, mirroring the accumulation order
        // in `compute_p` (_10_p.rs), and hold the ones this segment holds.
        let walk = segments::<P>();
        let mut walker = Walker::new(&points, walk.inputs_of(self.segment));

        for child in [&preamble.left, &preamble.right] {
            for id in RxIndex::all::<P>() {
                walker.enforce_equal(dr, &child[id])?;
            }
            walker.enforce_equal(dr, &child.stashed_ab_a)?;
            walker.enforce_equal(dr, &child.stashed_ab_b)?;
            walker.enforce_equal(dr, &child.stashed_registry_xy)?;
            walker.enforce_equal(dr, &child.stashed_p)?;
        }

        walker.enforce_equal(dr, &s_prime.registry_wx0)?;
        walker.enforce_equal(dr, &s_prime.registry_wx1)?;
        walker.enforce_equal(dr, &s_prime.native_application)?;
        walker.enforce_equal(dr, &preamble.application_stage)?;
        walker.enforce_equal(dr, &inner_error.registry_wy)?;
        walker.enforce_equal(dr, &ab.a)?;
        walker.enforce_equal(dr, &ab.b)?;
        walker.enforce_equal(dr, &query.registry_xy)?;
        walker.enforce_equal(dr, &s_prime.randomizer_a)?;
        walker.enforce_equal(dr, &s_prime.randomizer_b)?;
        walker.enforce_equal(dr, &f_stage.native_mask)?;

        // The online slots, in slot order: the children's exported
        // polynomials as the left and right slots, then the step's own.
        for child in [&preamble.left, &preamble.right] {
            for point in child.stashed_online_commitments.iter() {
                walker.enforce_equal(dr, point)?;
            }
        }
        for point in preamble.online_commitments.iter() {
            walker.enforce_equal(dr, point)?;
        }

        for point in preamble
            .online_points
            .iter()
            .chain(s_prime.online_points.iter())
            .chain(ab.online_points.iter())
            .chain(query.online_points.iter())
        {
            walker.enforce_equal(dr, point)?;
        }
        walker.finish();

        // The initial point: the walk's (f.commitment), which must match
        // BridgeF.native_f, or the boundary the previous segment ended in.
        match self.segment.checked_sub(1) {
            None => points.initial.enforce_equal(dr, &f_stage.native_f)?,
            Some(previous) => points.initial.enforce_equal(dr, &boundaries[previous])?,
        }
        // Every segment but the last ends in its own boundary: the
        // interstitial of its last step.
        if self.segment + 1 < walk.count() {
            points.interstitials[walk.steps_per_segment() - 1]
                .enforce_equal(dr, &boundaries[self.segment])?;
        }

        Ok(WithAux::new((), D::unit()))
    }
}
