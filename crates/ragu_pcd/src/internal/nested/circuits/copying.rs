//! Copying circuit for the nested section.
//!
//! Relates the current fuse step's preamble to the child proof's stages,
//! ensuring that child commitments stashed in
//! [`ChildWitness`](crate::internal::nested::stages::preamble::ChildWitness) match the
//! actual values committed in the child's bridge stages. One instance per
//! child proof ([`Side::Left`] and [`Side::Right`]).
//!
//! The copying circuit loads the child's bridge stages in its own trace
//! (no wire-position collision with loading, which loads the current
//! step's stages) and enforces equality between each `ChildWitness`
//! stash field and the corresponding child bridge stage field.

use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
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
use ragu_primitives::GadgetExt as _;

use crate::internal::{
    Side,
    endoscalar::{EndoscalarStage, PointsStage},
    nested::{NUM_ENDOSCALING_POINTS, stages},
};

/// Copying circuit that relates the current preamble to a child's stages.
pub struct Circuit<C: CurveAffine, R: Rank> {
    side: Side,
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> Circuit<C, R> {
    pub fn new(side: Side) -> Self {
        Self {
            side,
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> MultiStageCircuit<C::Base, R> for Circuit<C, R> {
    type Last = stages::eval::Stage<C, R>;
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
        let (points_guard, dr) = dr.add_stage::<PointsStage<C, NUM_ENDOSCALING_POINTS>>()?;
        let (preamble_guard, dr) = dr.add_stage::<stages::preamble::Stage<C, R>>()?;
        let (s_prime_guard, dr) = dr.add_stage::<stages::s_prime::Stage<C, R>>()?;
        let (inner_error_guard, dr) = dr.add_stage::<stages::inner_error::Stage<C, R>>()?;
        let (outer_error_guard, dr) = dr.add_stage::<stages::outer_error::Stage<C, R>>()?;
        let (ab_guard, dr) = dr.add_stage::<stages::ab::Stage<C, R>>()?;
        let (query_guard, dr) = dr.add_stage::<stages::query::Stage<C, R>>()?;
        let dr = dr.skip_stage::<stages::f::Stage<C, R>>()?;
        let (eval_guard, dr) = dr.add_stage::<stages::eval::Stage<C, R>>()?;
        let dr = dr.finish();

        // Load stage gadgets. Witness values are never accessed — the circuit
        // only runs during `into_bonding_object` where MaybeKind = Empty.
        macro_rules! w {
            () => {
                _witness.as_ref().map(|_| unreachable!())
            };
        }
        let points = points_guard.unenforced(dr, w!())?;
        let preamble = preamble_guard.unenforced(dr, w!())?;
        let s_prime = s_prime_guard.unenforced(dr, w!())?;
        let inner_error = inner_error_guard.unenforced(dr, w!())?;
        let outer_error = outer_error_guard.unenforced(dr, w!())?;
        let ab = ab_guard.unenforced(dr, w!())?;
        let query = query_guard.unenforced(dr, w!())?;
        let eval = eval_guard.unenforced(dr, w!())?;

        // Select the child corresponding to this circuit's side.
        let child = match self.side {
            Side::Left => &preamble.left,
            Side::Right => &preamble.right,
        };

        // Enforce that each ChildWitness stash field matches the
        // corresponding child bridge stage field.
        //
        // stashed_preamble: routes through this step's BridgeSPrime,
        // which was enforced by loading to equal
        // preamble.native_preamble at proof-generation time.
        child
            .stashed_preamble
            .enforce_equal(dr, &s_prime.stashed_preamble)?;
        child
            .stashed_inner_error
            .enforce_equal(dr, &inner_error.native_inner_error)?;
        child
            .stashed_outer_error
            .enforce_equal(dr, &outer_error.native_outer_error)?;
        child.stashed_ab_a.enforce_equal(dr, &ab.a)?;
        child.stashed_ab_b.enforce_equal(dr, &ab.b)?;
        child.stashed_query.enforce_equal(dr, &query.native_query)?;
        child
            .stashed_registry_xy
            .enforce_equal(dr, &query.registry_xy)?;
        child.stashed_eval.enforce_equal(dr, &eval.native_eval)?;

        // P: the child's accumulated p commitment is the last interstitial
        // of the child's PointsStage.
        let last_interstitial = points
            .interstitials
            .last()
            .expect("NUM_ENDOSCALING_POINTS guarantees >= 1 interstitial");
        child.stashed_p.enforce_equal(dr, last_interstitial)?;

        Ok(WithAux::new((), D::unit()))
    }
}
