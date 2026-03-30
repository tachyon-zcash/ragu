//! Loading circuit for the nested field.
//!
//! This bonding circuit enforces that the endoscaling [`PointsStage`] contains
//! the same commitments as the bridge stages. It mirrors the accumulation order
//! from `fuse::_10_p` and uses `enforce_equal` to bind each
//! bridge stage point to its corresponding position in the points stage.
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
use ragu_primitives::{Point, vec::FixedVec};

use crate::internal::{
    endoscalar::{EndoscalarStage, InputsLen, PointsStage},
    native::RxIndex,
    nested::{NUM_ENDOSCALING_POINTS, stages},
};

/// A walker over `points.inputs` that enforces equalities or skips entries in order.
struct InputWalker<'a, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    inputs: &'a FixedVec<Point<'dr, D, C>, InputsLen<NUM_ENDOSCALING_POINTS>>,
    idx: usize,
}

impl<'a, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> InputWalker<'a, 'dr, D, C> {
    fn new(inputs: &'a FixedVec<Point<'dr, D, C>, InputsLen<NUM_ENDOSCALING_POINTS>>) -> Self {
        Self { inputs, idx: 0 }
    }

    fn enforce_equal<D2: Driver<'dr, F = D::F, Wire = D::Wire>>(
        &mut self,
        dr: &mut D2,
        point: &Point<'dr, D, C>,
    ) -> Result<()> {
        self.inputs[self.idx].enforce_equal(dr, point)?;
        self.idx += 1;
        Ok(())
    }

    fn finish(self) {
        assert_eq!(
            self.idx,
            self.inputs.len(),
            "InputWalker did not consume all points"
        );
    }
}

/// A loading circuit that binds bridge stage commitments to the points stage.
pub struct Loading<C: CurveAffine, R: Rank> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> Loading<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> MultiStageCircuit<C::Base, R> for Loading<C, R> {
    type Last = stages::f::Stage<C, R>;
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
        let (points_guard, builder) =
            builder.add_stage::<PointsStage<C, NUM_ENDOSCALING_POINTS>>()?;
        let (preamble_guard, builder) = builder.add_stage::<stages::preamble::Stage<C, R>>()?;
        let (s_prime_guard, builder) = builder.add_stage::<stages::s_prime::Stage<C, R>>()?;
        let (inner_error_guard, builder) =
            builder.add_stage::<stages::inner_error::Stage<C, R>>()?;
        let builder = builder.skip_stage::<stages::outer_error::Stage<C, R>>()?;
        let (ab_guard, builder) = builder.add_stage::<stages::ab::Stage<C, R>>()?;
        let (query_guard, builder) = builder.add_stage::<stages::query::Stage<C, R>>()?;
        let (f_guard, builder) = builder.add_stage::<stages::f::Stage<C, R>>()?;
        let dr = builder.finish();

        // Load stage outputs. Witness values are empty because this circuit is
        // only used as a bonding polynomial (never traced with real data).
        let points = points_guard.unenforced(dr, D::MaybeKind::empty())?;
        let preamble_out = preamble_guard.unenforced(dr, D::MaybeKind::empty())?;
        let s_prime_out = s_prime_guard.unenforced(dr, D::MaybeKind::empty())?;
        let inner_error_out = inner_error_guard.unenforced(dr, D::MaybeKind::empty())?;
        let ab_out = ab_guard.unenforced(dr, D::MaybeKind::empty())?;
        let query_out = query_guard.unenforced(dr, D::MaybeKind::empty())?;
        let f_out = f_guard.unenforced(dr, D::MaybeKind::empty())?;

        // Initial point: f.commitment
        points.initial.enforce_equal(dr, &f_out.native_f)?;

        // Child proof commitments, mirroring the accumulation order in _10_p.rs.
        let mut walker = InputWalker::new(&points.inputs);
        for child in [&preamble_out.left, &preamble_out.right] {
            for &id in &RxIndex::ALL {
                walker.enforce_equal(dr, child.rx(id))?;
            }
            walker.enforce_equal(dr, &child.a)?;
            walker.enforce_equal(dr, &child.b)?;
            walker.enforce_equal(dr, &child.registry_xy)?;
            walker.enforce_equal(dr, &child.p)?;
        }

        // Current proof components.
        walker.enforce_equal(dr, &s_prime_out.registry_wx0)?;
        walker.enforce_equal(dr, &s_prime_out.registry_wx1)?;
        walker.enforce_equal(dr, &inner_error_out.registry_wy)?;

        // Bind the stashed native_preamble duplicate in inner_error to the
        // preamble's native_preamble. This allows the Copying circuit to check
        // child.preamble against inner_error positions (avoiding the preamble
        // wire position collision).
        preamble_out
            .native_preamble
            .enforce_equal(dr, &inner_error_out.stashed_native_preamble)?;
        walker.enforce_equal(dr, &ab_out.a)?;
        walker.enforce_equal(dr, &ab_out.b)?;
        walker.enforce_equal(dr, &query_out.registry_xy)?;
        walker.finish();

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
    fn into_bonding_object_succeeds() {
        let circuit = Loading::<EqAffine, R>::new();
        MultiStage::new(circuit)
            .into_bonding_object()
            .expect("loading circuit should produce a valid bonding object");
    }
}
