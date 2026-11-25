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
//! [`ClaimFolder::fold_inner`]: revdot::ClaimFolder::fold_inner
//! [`ClaimFolder::fold_outer`]: revdot::ClaimFolder::fold_outer
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
    Element, GadgetExt as _,
    allocator::{Allocator, Standard},
    consistent::Consistent,
    vec::FixedVec,
};
use udon::curve::EndomorphismAffine as Affine;

use super::common;
use crate::{
    header::NUM_ONLINE_FP_POLYS,
    internal::{
        ky,
        nested::{
            RevdotParameters,
            claims::{TwoProofKySource, ky_values},
            stages::{self, challenges},
            unified,
        },
        revdot,
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

        let allocator = &mut Standard::new();
        let mut unified = unified::OutputBuilder::new(witness.map(|w| w.instance));
        bind(dr, allocator, &mut unified, &stages)?;

        let lifts = &stages.challenges.pairs;
        let ky = source(dr, &stages)?;
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

/// What `collapse` holds besides the fold: the walk's contracts, the
/// instance's lifted challenges against the challenge stage, and its
/// exported commitments against their stage copies.
fn bind<'dr, D, C, P, A>(
    dr: &mut D,
    allocator: &mut A,
    unified: &mut unified::OutputBuilder<'dr, D, A, C>,
    stages: &common::Loaded<'dr, D, C, P>,
) -> Result<()>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    P: Profile,
    A: Allocator<'dr, D>,
{
    // The walk's contracts: points on the curve, and the endoscalar
    // stage's bit wires bits with its product wires the products of those
    // bits, each gadget re-emitted on the stage's wires. A walk of
    // several segments has a polynomial of the points stage per segment
    // and this circuit loads the last one alone, so there each step
    // holds its own points to the curve instead.
    let walk = crate::internal::nested::segments::<P>();
    if !walk.is_split() {
        stages.points.enforce_consistent(dr)?;
    }
    stages.endoscalar.enforce_consistent(dr)?;

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

    // The commitments a parent endoscales, in `unified` order. The
    // walk's result is the interstitial of its last step, which the
    // polynomial of the walk's last segment holds.
    let last_interstitial = &stages.points.interstitials[walk.last_local_step()];
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

    Ok(())
}

/// The nested fold's targets that are not constants: the children's $c$
/// values and the $k(y_n)$ of their nested unified instances, `compute_v`
/// claims, online helpers and binding circuits, each computed from the
/// preamble bridge stage's copies at the challenge stage's $y_n$.
fn source<'dr, D, C, P>(
    dr: &mut D,
    stages: &common::Loaded<'dr, D, C, P>,
) -> Result<TwoProofKySource<'dr, D>>
where
    D: Driver<'dr, F = C::Base>,
    C: Affine,
    P: Profile,
{
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
    let left_binding = ky::binding_ky(
        dr,
        y,
        &stages.preamble.left.bound(),
        &stages.preamble.left.online_fq_openings,
    )?;
    let right_binding = ky::binding_ky(
        dr,
        y,
        &stages.preamble.right.bound(),
        &stages.preamble.right.online_fq_openings,
    )?;
    // The children's `compute_v` claims take the same exported
    // openings after the unified instance, so the opening a child's
    // binding circuit exposes is the one its `compute_v` folded, then
    // the online helper's values and the online batch's commitments. A
    // profile that exports none of them keeps the unified k(y).
    let (left_compute_v, left_online_helper) = ky::nested_online_ky::<_, _, P>(
        dr,
        y,
        &stages.preamble.left.nested_instance(),
        &left_unified,
        &stages.preamble.left.online_fq_openings,
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
        &stages.preamble.right.online_fq_openings,
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
    Ok(ky)
}

/// The left and the right child's target of one circuit, which a profile
/// has for both children or for neither.
fn pair<T: Clone>(left: &Option<T>, right: &Option<T>) -> Option<[T; 2]> {
    match (left, right) {
        (Some(left), Some(right)) => Some([left.clone(), right.clone()]),
        (None, None) => None,
        _ => unreachable!("a profile's circuit has a target for each child"),
    }
}

/// The circuit a profile whose nested fold is verified in chunks registers
/// in `collapse`'s place (see [`Chunking`](crate::profile::Chunking)).
///
/// It holds everything `collapse` holds besides the fold and computes the
/// same targets, and then, instead of folding them, enforces each target it
/// computed equal to the value the [`targets`](stages::targets) stage
/// holds, where the [`fold_inner`](super::fold_inner) circuits read it. The
/// two layers are those circuits' and [`fold_outer`](super::fold_outer)'s,
/// and the instance's $c_n$ is the latter's to cover.
pub struct Targets<C: Affine, R: Rank, P: Profile> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> Targets<C, R, P> {
    /// Creates the circuit.
    ///
    /// # Panics
    ///
    /// Panics if the profile's `collapse` verifies the fold whole.
    pub fn new() -> Self {
        assert!(
            crate::internal::nested::is_fold_chunked::<P>(),
            "a fold verified whole is `collapse`'s"
        );
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Profile> MultiStageCircuit<C::Base, R> for Targets<C, R, P> {
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

        let allocator = &mut Standard::new();
        let mut unified = unified::OutputBuilder::new(witness.map(|w| w.instance));
        bind(dr, allocator, &mut unified, &stages)?;

        // The targets this circuit computed are the ones the chunks fold.
        let ky = source(dr, &stages)?;
        let computed = stages::targets::Targets {
            unified: [ky.left_unified.clone(), ky.right_unified.clone()],
            compute_v: [ky.left_compute_v.clone(), ky.right_compute_v.clone()],
            online_helper: pair(&ky.left_online_helper, &ky.right_online_helper),
            binding: pair(&ky.left_binding, &ky.right_binding),
        }
        .into_values();
        assert_eq!(
            computed.len(),
            stages.targets.len(),
            "the targets stage holds every target the circuit computes"
        );
        for (computed, staged) in computed.iter().zip(stages.targets.iter()) {
            computed.enforce_equal(dr, staged)?;
        }

        let (output, instance) = unified.finish(dr, allocator)?;
        Ok(WithAux::new(output, instance))
    }
}
