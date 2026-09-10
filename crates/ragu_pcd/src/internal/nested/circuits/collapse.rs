//! Collapse circuit for the nested section: verifies both layers of the
//! two-layer revdot fold of the children's nested claims.
//!
//! The native side spreads this over `inner_collapse` and `outer_collapse`
//! because its stages leave no room for both layers in one circuit; the
//! nested stage chain is small enough that one circuit does it.
//!
//! ## Operations
//!
//! - **Layer 1.** For each group of the children's nested claims, folds the
//!   `inner_error` stage's error terms with the group's $k(y_n)$ values under
//!   the lifted $\mu$ and $\nu$ ([`ClaimFolder::fold_inner`]) and enforces
//!   the result equal to the collapsed value the `outer_error` stage
//!   witnessed.
//! - **Layer 2.** Folds the collapsed values with the `outer_error` stage's
//!   error terms under the lifted $\mu'$ and $\nu'$
//!   ([`ClaimFolder::fold_outer`]) and enforces the result equal to the
//!   instance's $c_n$, outside the base case.
//!
//! ## $k(y_n)$ values
//!
//! The values come from [`TwoProofKySource`], in the order [`build`] emits
//! the claims: each child's raw accumulator value $c$ and the $k(y_n)$ of
//! its nested unified instance, both read off the `preamble` bridge stage's
//! copies (the instance's through [`ChildOutput::nested_instance`]), at the
//! $y_n$ the instance carries; one for each endoscaling step; zero for each
//! bonding claim.
//!
//! ## Base case
//!
//! When both children are trivial their claims are not satisfied, and the
//! prover witnesses whatever $c_n$ its folded accumulator has, exactly as
//! the native `outer_collapse` allows. The verdict is the sign the challenge
//! stage carries, which the native binding circuits tie to the headers.
//!
//! [`ClaimFolder::fold_inner`]: fold_revdot::ClaimFolder::fold_inner
//! [`ClaimFolder::fold_outer`]: fold_revdot::ClaimFolder::fold_outer
//! [`TwoProofKySource`]: crate::internal::nested::claims::TwoProofKySource
//! [`build`]: crate::internal::nested::claims::build
//! [`ChildOutput::nested_instance`]: stages::preamble::ChildOutput::nested_instance

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
use ragu_primitives::{Element, GadgetExt as _, allocator::Standard, vec::FixedVec};

use super::common;
use crate::internal::{
    fold_revdot,
    nested::{
        RevdotParameters,
        claims::{TwoProofKySource, ky_values},
        stages::{self, challenges},
        unified,
    },
};

/// Collapse circuit verifying the nested fold.
pub struct Circuit<C: CurveAffine, R: Rank> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> Circuit<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> MultiStageCircuit<C::Base, R> for Circuit<C, R> {
    type Last = stages::beta::Stage<C, R>;
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = common::Witness<'source, C>;
    type Output = unified::OutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (dr, stages) = common::load_all(dr, &witness)?;

        let allocator = &mut Standard::new();
        let mut unified = unified::OutputBuilder::new(witness.map(|w| w.instance));
        let lifts = &stages.challenges.pairs;

        // The children's k(y_n) values, from the preamble's copies, at the
        // y_n the instance carries (pinned to the challenge stage by the
        // export circuit).
        let y = unified.y.read(dr, allocator)?;
        let left_unified = stages.preamble.left.nested_instance().ky(dr, &y)?;
        let right_unified = stages.preamble.right.nested_instance().ky(dr, &y)?;
        let ky = TwoProofKySource::new(
            dr,
            stages.preamble.left.nested.c.clone(),
            stages.preamble.right.nested.c.clone(),
            left_unified,
            right_unified,
        );
        let mut ky = ky_values(&ky);

        // Layer 1: each group's fold must be the collapsed value witnessed.
        let fold = fold_revdot::ClaimFolder::new(
            dr,
            &lifts[challenges::MU].lift,
            &lifts[challenges::NU].lift,
        )?;
        for (error_terms, collapsed) in stages
            .inner_error
            .error_terms
            .iter()
            .zip(stages.outer_error.collapsed.iter())
        {
            let ky = FixedVec::from_fn(|_| ky.next().expect("ky_values is infinite"));
            fold.fold_inner::<RevdotParameters>(dr, error_terms, &ky)?
                .enforce_equal(dr, collapsed)?;
        }

        // Layer 2: the fold of the collapsed values is c_n, outside the base
        // case.
        let fold = fold_revdot::ClaimFolder::new(
            dr,
            &lifts[challenges::MU_PRIME].lift,
            &lifts[challenges::NU_PRIME].lift,
        )?;
        let computed_c = fold.fold_outer::<RevdotParameters>(
            dr,
            &stages.outer_error.error_terms,
            &stages.outer_error.collapsed,
        )?;
        let witnessed_c = unified.c.receive(dr, allocator)?;
        let is_base_case =
            stages
                .challenges
                .base_case
                .lift
                .is_equal(dr, allocator, &Element::one())?;
        is_base_case
            .not(dr)
            .conditional_enforce_equal(dr, allocator, &witnessed_c, &computed_c)?;

        let (output, instance) = unified.finish(dr, allocator)?;
        Ok(WithAux::new(output, instance))
    }
}
