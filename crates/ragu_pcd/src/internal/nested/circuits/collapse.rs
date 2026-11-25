//! Collapse circuit for the nested section: verifies both layers of the
//! two-layer revdot fold of the children's nested claims.
//!
//! It also pins the nested unified instance's lifted x, y and u to the
//! challenge stage and its exported commitments to their stage copies, and
//! holds the endoscaling walk to the transcript. The walk reads its points
//! from the points stage, which is committed after the challenge the walk
//! folds under, so two things are enforced here:
//!
//! - **The walked points.** Every input of the points stage, and its initial
//!   point, equals the copy a bridge stage holds, and the transcript absorbed
//!   that bridge stage before the challenge (see
//!   [The walked points](#the-walked-points)).
//! - **The stage contracts.** Every point of the points stage lies on the
//!   curve, and the endoscalar stage's
//!   [`HoistedEndoscalar`](ragu_primitives::HoistedEndoscalar) holds boolean
//!   bits and the products of those bits.
//!
//! A profile can cut its walk into groups
//! ([`Profile::NESTED_WALK_GROUP`]),
//! each in its own points stage polynomial, and then no one circuit can
//! load every point. Each group's [`group_check`](super::group_check)
//! circuit enforces the walked points and the points' curve membership for
//! its group and holds the group to the links stage. This circuit then
//! holds the first link to the commitment of $f$, reads the walk's result
//! off the last link, and keeps the endoscalar stage's contract.
//!
//! `compute_v` ties that endoscalar's lift to the challenge stage's beta
//! lift and computes v_n.
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
//! for each mask claim. The current instance's $y_n$ is equated with
//! that stage value here.
//!
//! ## The walked points
//!
//! The walk's inputs are the native batch's commitments, in the order
//! `compute_p` (`_10_p`) accumulates them. Each one is enforced equal to the
//! copy a bridge stage holds:
//!
//! - each child's native rx commitments, $a$, $b$, `registry_xy` and $p$,
//!   from the `preamble` stage;
//! - the step's own commitments, from the `preamble`, `s_prime`,
//!   `inner_error`, `ab`, `query` and `f` stages;
//! - the online slots, the children's and then the step's own, from the
//!   `preamble` stage;
//! - the step's native online points, from the `preamble`, `s_prime`, `ab`
//!   and `query` stages.
//!
//! The walk's initial point is enforced equal to the `f` stage's copy of
//! the commitment of $f$. Each equality is two linear constraints, one for
//! each coordinate, so the equalities add no gates to this circuit.
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
//! [`ClaimFolder::fold_inner`]: revdot::ClaimFolder::fold_inner
//! [`ClaimFolder::fold_outer`]: revdot::ClaimFolder::fold_outer
//! [`TwoProofKySource`]: crate::internal::nested::claims::TwoProofKySource
//! [`build`]: crate::internal::nested::claims::build
//! [`ChildOutput::nested_instance`]: stages::preamble::ChildOutput::nested_instance

use alloc::vec::Vec;
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
    Element, GadgetExt as _, Point, allocator::Standard, consistent::Consistent, vec::FixedVec,
};
use udon::curve::EndomorphismAffine as Affine;

use super::common;
use crate::{
    header::NUM_ONLINE_FP_POLYS,
    internal::{
        ky,
        native::RxIndex,
        nested::{
            Points, RevdotParameters,
            claims::{TwoProofKySource, ky_values},
            stages::{self, challenges},
            unified,
        },
        revdot,
    },
    profile::Profile,
};

/// The copy a bridge stage holds of every input of the walk, in the order
/// `compute_p` (`_10_p`) accumulates the points.
///
/// The transcript absorbs the bridge stages before the challenge the walk
/// folds under, and commits the points stages after it. An input held
/// equal to its copy here is fixed before that challenge.
pub(super) fn held_inputs<'a, 'dr, D, C, P>(
    stages: &'a common::Loaded<'dr, D, C, P>,
) -> Vec<&'a Point<'dr, D, C>>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    P: Profile,
{
    let common::Loaded {
        preamble,
        s_prime,
        inner_error,
        ab,
        query,
        f,
        ..
    } = stages;
    let mut held: Vec<&Point<'dr, D, C>> = Vec::new();
    for child in [&preamble.left, &preamble.right] {
        held.extend(RxIndex::all::<P>().into_iter().map(|id| &child[id]));
        held.extend([
            &child.stashed_ab_a,
            &child.stashed_ab_b,
            &child.stashed_registry_xy,
            &child.stashed_p,
        ]);
    }
    held.extend([
        &s_prime.registry_wx0,
        &s_prime.registry_wx1,
        &s_prime.native_application,
        &preamble.application_stage,
        &inner_error.registry_wy,
        &ab.a,
        &ab.b,
        &query.registry_xy,
        &s_prime.randomizer_a,
        &s_prime.randomizer_b,
        &f.native_mask,
    ]);
    // The online slots, in slot order: the children's exported polynomials
    // as the left and right slots, then the step's own.
    for child in [&preamble.left, &preamble.right] {
        held.extend(child.stashed_online_commitments.iter());
    }
    held.extend(preamble.online_commitments.iter());
    held.extend(
        preamble
            .online_points
            .iter()
            .chain(s_prime.online_points.iter())
            .chain(ab.online_points.iter())
            .chain(query.online_points.iter()),
    );
    held
}

/// Enforces every input of the points stage of a walk in one stage, and its
/// initial point, equal to the copy a bridge stage holds.
///
/// The transcript absorbs the bridge stages before the challenge the walk
/// folds under, and commits the points stage after it. These equalities are
/// what fixes the walked points before that challenge.
fn enforce_walked_points<'dr, D, C, P>(
    dr: &mut D,
    stages: &common::Loaded<'dr, D, C, P>,
    points: &Points<'dr, D, C, P>,
) -> Result<()>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    P: Profile,
{
    let held = held_inputs(stages);
    assert_eq!(
        held.len(),
        points.inputs.len(),
        "a bridge stage holds a copy of every input of the points stage"
    );
    for (input, held) in points.inputs.iter().zip(held) {
        input.enforce_equal(dr, held)?;
    }

    // The walk starts from the commitment of f.
    points.initial.enforce_equal(dr, &stages.f.native_f)
}

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
        let (dr, stages) = common::load_all(dr, &witness, common::whole_walk::<P>())?;

        // The walk's contracts: points on the curve, and the endoscalar
        // stage's bit wires bits with its product wires the products of those
        // bits, each gadget re-emitted on the stage's wires. A grouped
        // walk's check circuits hold each group's points to the curve.
        if let Some(points) = &stages.points {
            points.enforce_consistent(dr)?;
        }
        stages.endoscalar.enforce_consistent(dr)?;

        // The walked points: each one is the copy a bridge stage holds. A
        // grouped walk's check circuits hold each group's inputs, and the
        // walk's initial point is the first link.
        let result = match &stages.points {
            Some(points) => {
                enforce_walked_points(dr, &stages, points)?;
                points
                    .interstitials
                    .last()
                    .expect("every walk has at least one interstitial")
            }
            None => {
                let links = &stages.links.states;
                links
                    .first()
                    .expect("a grouped walk has links")
                    .enforce_equal(dr, &stages.f.native_f)?;
                links.last().expect("a grouped walk has links")
            }
        };

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
        let last_interstitial = result;
        let held = [
            &stages.s_prime.native_preamble,
            &stages.inner_error.native_inner_error,
            &stages.outer_error.native_outer_error,
            &stages.query.native_query,
            &stages.eval.native_eval,
            &stages.ab.a,
            &stages.ab.b,
            &stages.query.registry_xy,
            last_interstitial,
            &stages.preamble.native_points_binding,
            &stages.preamble.native_points_preamble,
            &stages.s_prime.native_points_registry_wx,
            &stages.ab.native_points_ab,
            &stages.f.native_points_f,
            &stages.preamble.online_commitments[0],
            &stages.preamble.online_commitments[1],
        ];
        // The bridge-hash stage holds the step's own last online commitment,
        // the one the preamble holds and w absorbed.
        stages.bridge_hash.o1.enforce_equal(
            dr,
            &stages.preamble.online_commitments[NUM_ONLINE_FP_POLYS - 1],
        )?;

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
        // extension stages it names, then of their own online slots it
        // names, as the bridge preamble holds them. A profile without a
        // binding computes nothing here.
        let left_binding = ky::binding_ky(dr, y, &stages.preamble.left.bound())?;
        let right_binding = ky::binding_ky(dr, y, &stages.preamble.right.bound())?;
        // The children's `compute_v` claims take the online helper's
        // values and the online batch's commitments after the unified
        // instance. A profile that exports none of them keeps the unified
        // k(y).
        let (left_compute_v, left_online_helper) = ky::nested_online_ky::<_, _, P>(
            dr,
            y,
            &stages.preamble.left.nested_instance(),
            &left_unified,
            &stages.preamble.left.online_values,
            &ky::native_online_stages::<P, _>(|index| stages.preamble.left[index].clone()),
            &stages.preamble.left.online_points,
            &stages.preamble.left.mesh,
        )?;
        let (right_compute_v, right_online_helper) = ky::nested_online_ky::<_, _, P>(
            dr,
            y,
            &stages.preamble.right.nested_instance(),
            &right_unified,
            &stages.preamble.right.online_values,
            &ky::native_online_stages::<P, _>(|index| stages.preamble.right[index].clone()),
            &stages.preamble.right.online_points,
            &stages.preamble.right.mesh,
        )?;
        let ky = TwoProofKySource::new(
            dr,
            stages.preamble.left.nested.c.clone(),
            stages.preamble.right.nested.c.clone(),
            left_unified,
            right_unified,
            left_compute_v,
            right_compute_v,
            left_online_helper,
            right_online_helper,
            left_binding,
            right_binding,
        );
        // The grid holds the claims' targets with the fold randomizer's.
        let zero = Element::zero(dr);
        let mut ky = revdot::randomized::<_, RevdotParameters<P>>(
            ky_values::<P, _>(&ky),
            zero.clone(),
            stages.inner_error.randomizer_c.clone(),
            zero,
        );

        // Layer 1: each group's fold must be the collapsed value witnessed.
        let fold = revdot::ClaimFolder::new(&lifts[challenges::MU].lift);
        for (error_terms, collapsed) in stages
            .inner_error
            .error_terms
            .iter()
            .zip(stages.outer_error.collapsed.iter())
        {
            let ky = FixedVec::from_fn(|_| ky.next().expect("the grid holds every node"));
            fold.fold_inner::<RevdotParameters<P>>(dr, error_terms, &ky)?
                .enforce_equal(dr, collapsed)?;
        }

        // Layer 2: the fold of the collapsed values is c_n, outside the base
        // case.
        let fold = revdot::ClaimFolder::new(&lifts[challenges::MU_PRIME].lift);
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
