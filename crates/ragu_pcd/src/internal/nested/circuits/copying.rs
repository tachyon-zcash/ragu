//! Copying circuit for the nested field.
//!
//! This bonding circuit enforces that each child proof's commitments witnessed
//! in the preamble [`ChildOutput`](super::super::stages::preamble::ChildOutput) match the native commitments inside that
//! child's own bridge stages. It uses `enforce_equal` to bind each preamble
//! child field to the corresponding bridge stage field.
//!
//! There are two instances — one per [`Side`] — because the left and right
//! children constrain different parts of the preamble output.
//!
//! Because it only uses `enforce_equal`, it qualifies as a bonding polynomial
//! via `MultiStage::into_bonding_object`.

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
    gadgets::{Bound, Gadget, Kind},
    maybe::MaybeKind,
};

use crate::internal::{
    Side,
    endoscalar::{EndoscalarStage, PointsStage},
    nested::{NUM_ENDOSCALING_POINTS, stages},
};

/// A copying circuit that binds preamble child commitments to bridge stage
/// native commitments for one child proof (left or right).
pub struct Copying<C: CurveAffine, R: Rank> {
    side: Side,
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> Copying<C, R> {
    pub fn new(side: Side) -> Self {
        Self {
            side,
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> MultiStageCircuit<C::Base, R> for Copying<C, R> {
    type Last = stages::eval::Stage<C, R>;
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = Kind![C::Base; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        _witness: DriverValue<D, ()>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        // Build stage chain, skipping stages whose data is not needed.
        let builder = builder.skip_stage::<EndoscalarStage>()?;
        let builder = builder.skip_stage::<PointsStage<C, NUM_ENDOSCALING_POINTS>>()?;
        let (preamble_guard, builder) = builder.add_stage::<stages::preamble::Stage<C, R>>()?;
        let builder = builder.skip_stage::<stages::s_prime::Stage<C, R>>()?;
        let (inner_error_guard, builder) =
            builder.add_stage::<stages::inner_error::Stage<C, R>>()?;
        let (outer_error_guard, builder) =
            builder.add_stage::<stages::outer_error::Stage<C, R>>()?;
        let (ab_guard, builder) = builder.add_stage::<stages::ab::Stage<C, R>>()?;
        let (query_guard, builder) = builder.add_stage::<stages::query::Stage<C, R>>()?;
        let builder = builder.skip_stage::<stages::f::Stage<C, R>>()?;
        let (eval_guard, builder) = builder.add_stage::<stages::eval::Stage<C, R>>()?;
        let dr = builder.finish();

        // Load stage outputs. Witness values are empty because this circuit is
        // only used as a bonding polynomial (never traced with real data).
        let preamble_out = preamble_guard.unenforced(dr, D::MaybeKind::empty())?;
        let inner_error_out = inner_error_guard.unenforced(dr, D::MaybeKind::empty())?;
        let outer_error_out = outer_error_guard.unenforced(dr, D::MaybeKind::empty())?;
        let ab_out = ab_guard.unenforced(dr, D::MaybeKind::empty())?;
        let query_out = query_guard.unenforced(dr, D::MaybeKind::empty())?;
        let eval_out = eval_guard.unenforced(dr, D::MaybeKind::empty())?;

        // Select the child output for this side.
        let child = match self.side {
            Side::Left => &preamble_out.left,
            Side::Right => &preamble_out.right,
        };

        // Enforce that preamble child commitments match the corresponding
        // bridge stage native commitments.
        child
            .inner_error
            .enforce_equal(dr, &inner_error_out.native_inner_error)?;
        child
            .outer_error
            .enforce_equal(dr, &outer_error_out.native_outer_error)?;
        child.query_rx.enforce_equal(dr, &query_out.native_query)?;
        child.eval.enforce_equal(dr, &eval_out.native_eval)?;
        child.a.enforce_equal(dr, &ab_out.a)?;
        child.b.enforce_equal(dr, &ab_out.b)?;
        child
            .registry_xy
            .enforce_equal(dr, &query_out.registry_xy)?;
        child
            .preamble
            .enforce_equal(dr, &inner_error_out.stashed_native_preamble)?;

        Ok(WithAux::new((), D::unit()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragu_circuits::{polynomials::ProductionRank, staging::MultiStage};
    use ragu_pasta::EqAffine;

    type R = ProductionRank;

    #[test]
    fn into_bonding_object_succeeds_left() {
        let circuit = Copying::<EqAffine, R>::new(Side::Left);
        MultiStage::new(circuit)
            .into_bonding_object()
            .expect("copying circuit (left) should produce a valid bonding object");
    }

    #[test]
    fn into_bonding_object_succeeds_right() {
        let circuit = Copying::<EqAffine, R>::new(Side::Right);
        MultiStage::new(circuit)
            .into_bonding_object()
            .expect("copying circuit (right) should produce a valid bonding object");
    }
}
