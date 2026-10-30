//! Collapse circuit for the nested section: verifies both layers of the
//! two-layer revdot fold of the children's nested claims.
//!
//! It also pins the nested unified instance's lifted x, y and u to the
//! challenge stage and its exported commitments to their stage copies, and
//! re-emits the stage contracts the endoscaling walk rests on, which the
//! loading circuit, a bonding claim, cannot: every point of the points stage
//! lies on the curve, and the endoscalar stage's
//! [`HoistedEndoscalar`](ragu_primitives::HoistedEndoscalar) holds boolean
//! bits and the products of those bits. `compute_v` ties that endoscalar's
//! lift to the challenge stage's beta lift and computes v_n.
//!
//! ## Operations
//!
//! - **Layer 1.** For each group of the children's nested claims, folds the
//!   `inner_error` stage's error terms with the group's $k(y_n)$ values under
//!   the lifted $\mu$ ([`ClaimFolder::fold_inner`]) and enforces
//!   the result equal to the collapsed value the `outer_error` stage
//!   witnessed.
//! - **Layer 2.** Folds the collapsed values with the `outer_error` stage's
//!   error terms under the lifted $\mu'$
//!   ([`ClaimFolder::fold_outer`]) and enforces the result equal to the
//!   instance's $c_n$, outside the base case.
//!
//! ## $k(y_n)$ values
//!
//! The values come from [`TwoProofKySource`], in the order [`build`] emits
//! the claims: each child's raw accumulator value $c$ and the $k(y_n)$ of
//! its nested unified instance, both read off the `preamble` bridge stage's
//! copies (the instance's through [`ChildOutput::nested_instance`]), at the
//! current step's $y_n$ from the challenge stage; one for each endoscaling
//! step; for a profile whose nested extension has a binding circuit, the
//! $k(y_n)$ of the child's native extension stages it names, read off the
//! same stage's copies (see [`Binding`](crate::profile::Binding)); zero
//! for each bonding claim. The current instance's $y_n$ is equated with
//! that stage value here.
//!
//! ## Base case
//!
//! When Bootstrap consumes two dummy children, their claims are not
//! satisfied, and the prover witnesses whatever $c_n$ its folded accumulator
//! has, exactly as the native `collapse` allows. The layer-one
//! equalities remain enforced; only the final $c_n$ comparison is waived.
//! The verdict is the sign the challenge stage carries. No nested circuit
//! constrains that wire:
//! this step's parent, or the decider at the root, holds the challenge stage
//! polynomial to the sign the native binding circuits derive from the headers
//! (see [`challenges`]), so a step cannot select the exception its headers do
//! not.
//!
//! [`challenges`]: stages::challenges
//! [`ClaimFolder::fold_inner`]: fold_revdot::ClaimFolder::fold_inner
//! [`ClaimFolder::fold_outer`]: fold_revdot::ClaimFolder::fold_outer
//! [`TwoProofKySource`]: crate::internal::nested::claims::TwoProofKySource
//! [`build`]: crate::internal::nested::claims::build
//! [`ChildOutput::nested_instance`]: stages::preamble::ChildOutput::nested_instance

use core::marker::PhantomData;

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
use ragu_primitives::{
    Element, GadgetExt as _, allocator::Standard, consistent::Consistent, vec::FixedVec,
};
use udon::curve::EndomorphismAffine as Affine;

use super::common;
use crate::{
    internal::{
        fold_revdot, ky,
        nested::{
            RevdotParameters,
            claims::{TwoProofKySource, ky_values},
            stages::{self, challenges},
            unified,
        },
    },
    profile::Profile,
};

/// Circuit binding the nested instance to its stages and verifying the nested fold.
pub struct Circuit<C: Affine, R: Rank, P: Profile> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> Circuit<C, R, P> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Profile> MultiStageCircuit<C::Base, R> for Circuit<C, R, P> {
    type Last = stages::challenges::Stage<C, R, P>;
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = common::Witness<'source, C, P>;
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

        // The walk's contracts: points on the curve, and the endoscalar
        // stage's bit wires bits with its product wires the products of those
        // bits, each gadget re-emitted on the stage's wires.
        stages.points.enforce_consistent(dr)?;
        stages.endoscalar.enforce_consistent(dr)?;

        let allocator = &mut Standard::new();
        let mut unified = unified::OutputBuilder::new(witness.map(|w| w.instance));

        // The lifted challenges a parent opens this step at.
        let pairs = &stages.challenges.pairs;
        unified
            .x
            .receive(dr, allocator)?
            .enforce_equal(dr, &pairs[stages::challenges::X].lift)?;
        unified
            .y
            .receive(dr, allocator)?
            .enforce_equal(dr, &pairs[stages::challenges::Y].lift)?;
        unified
            .u
            .receive(dr, allocator)?
            .enforce_equal(dr, &pairs[stages::challenges::U].lift)?;

        // The commitments a parent endoscales, in `unified` order.
        let last_interstitial = stages
            .points
            .interstitials
            .last()
            .expect("every walk has at least one interstitial");
        let held = [
            &stages.preamble.native_preamble,
            &stages.inner_error.native_inner_error,
            &stages.outer_error.native_outer_error,
            &stages.query.native_query,
            &stages.eval.native_eval,
            &stages.ab.a,
            &stages.ab.b,
            &stages.query.registry_xy,
            last_interstitial,
            &stages.preamble.native_points_binding,
            &stages.preamble.native_points_children,
            &stages.s_prime.native_points_registry_wx,
            &stages.ab.native_points_ab,
            &stages.f.native_points_f,
        ];
        let exported = unified.exported.receive(dr, allocator)?;
        for (instance, stage) in exported.iter().zip(held) {
            instance.enforce_equal(dr, stage)?;
        }

        let lifts = &stages.challenges.pairs;

        // Evaluate the children's instance copies at this step's challenge
        // stage y_n, which is also bound to the public copy above.
        let y = &lifts[challenges::Y].lift;
        let left_unified = stages.preamble.left.nested_instance().ky(dr, y)?;
        let right_unified = stages.preamble.right.nested_instance().ky(dr, y)?;
        // The binding circuit's k(y): the k(y) of the children's native
        // extension stages it names, as the bridge preamble holds them. A
        // profile without a binding computes nothing here.
        let binding = P::nested_extension().binding;
        let left_binding = ky::binding_ky(
            dr,
            y,
            &ky::bound(binding.as_ref(), |j| {
                stages.preamble.left.extension_stages[j as usize].clone()
            }),
        )?;
        let right_binding = ky::binding_ky(
            dr,
            y,
            &ky::bound(binding.as_ref(), |j| {
                stages.preamble.right.extension_stages[j as usize].clone()
            }),
        )?;
        let ky = TwoProofKySource::new(
            dr,
            stages.preamble.left.nested.c.clone(),
            stages.preamble.right.nested.c.clone(),
            left_unified,
            right_unified,
            left_binding,
            right_binding,
        );
        let mut ky = ky_values::<P, _>(&ky);

        // Layer 1: each group's fold must be the collapsed value witnessed.
        let fold = fold_revdot::ClaimFolder::new(&lifts[challenges::MU].lift);
        for (error_terms, collapsed) in stages
            .inner_error
            .error_terms
            .iter()
            .zip(stages.outer_error.collapsed.iter())
        {
            let ky = FixedVec::from_fn(|_| ky.next().expect("ky_values is infinite"));
            fold.fold_inner::<RevdotParameters<P>>(dr, error_terms, &ky)?
                .enforce_equal(dr, collapsed)?;
        }

        // Layer 2: the fold of the collapsed values is c_n, outside the base
        // case.
        let fold = fold_revdot::ClaimFolder::new(&lifts[challenges::MU_PRIME].lift);
        let computed_c = fold.fold_outer::<RevdotParameters<P>>(
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
