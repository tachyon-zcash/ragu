//! The circuits of a grouped native endoscaling walk
//! ([`Profile::NATIVE_WALK_GROUP`](crate::profile::Profile::NATIVE_WALK_GROUP)).
//!
//! The standard profile's [endoscaling step](super::endoscaling_step) reads
//! each point from the stage the transcript commits it in, so it reserves
//! every points stage. A profile with a large nested batch has no room
//! left in a step for its endoscalings. Its walk is cut into groups
//! ([`paging::Grouping`]) with the stages laid in this order after the
//! binding stage:
//!
//! ```text
//! │binding│walk: endoscalar│group│links│preamble│registry_wx│ab│f│
//! ```
//!
//! - **[`Step`]** loads the endoscalar and its group's points stage, a copy
//!   of the group's entry point and inputs with the group's interstitials,
//!   and runs one page of the group's walk. It reserves the binding stage
//!   and nothing after its group.
//! - **[`Check`]**, one per group, loads the group and every stage after
//!   it. It holds the group's points to the curve, each of its inputs to
//!   the point of the stage the transcript commits it in, and the group to
//!   the links stage.
//! - **[`Bind`]**, in the place of [`bind_endoscalar`](super::bind_endoscalar),
//!   holds the endoscalar's bits to `pre_beta`, the first link to $F_n$
//!   and the instance's $P_n$ to the last link, and exports what that
//!   circuit exports.
//!
//! The transcript commits the same points stages with the same points in
//! them. The group stages are committed after $\beta$, as the walk stage
//! is, and a group's inputs are fixed before the challenges by the
//! equalities of its check circuit.
//!
//! # What holds the walk together
//!
//! As for any grouped walk (see [`paging`](crate::internal::paging#groups)):
//! every step and every check circuit is a registered circuit whose claim
//! is folded; all of them read one links polynomial and one polynomial per
//! group; a group's check holds its entry point to its link and its last
//! interstitial to the next link. [`Bind`] holds the two ends.
//!
//! The curve membership of the points the transcript commits follows from
//! the checks: every such point is the walk's initial point or one of its
//! inputs, so it equals a point of a group that its check holds to the
//! curve. The one point that is not walked, the nested online input
//! stage's commitment in the binding stage, [`Bind`] holds to the curve.

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget as _, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Endoscalar, EndoscalarChallenge, GadgetExt as _, HoistedEndoscalar, WithSuffix,
    allocator::Standard,
    consistent::Consistent,
    vec::{CollectFixed, Len as _},
};

use super::{
    super::{
        NumSteps,
        stages::points::{
            AbStage, BindingStage, FStage, GroupStage, GroupedWalk, Inputs, LinksStage,
            PreambleStage, RegistryWxStage, WalkInputs, WalkStage, WalkWitness, walk_grouping,
        },
        unified::{self, OutputBuilder},
    },
    bind_endoscalar::Output,
};
use crate::{
    internal::{endoscalar, paging},
    profile::ProfiledCycle,
};

/// Witness of a circuit of the grouped walk: the points stages the
/// transcript commits, the walk stage and the walk's groups and links.
pub struct Witness<'a, C: ProfiledCycle> {
    pub inputs: &'a Inputs<C::NestedCurve, C::Profile>,
    pub walk: &'a WalkWitness<C::NestedCurve, C::Profile>,
    pub grouped: &'a GroupedWalk<C::NestedCurve, C::Profile>,
}

impl<C: ProfiledCycle> Clone for Witness<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: ProfiledCycle> Copy for Witness<'_, C> {}

/// One step of a grouped native walk.
///
/// Like the [endoscaling step](super::endoscaling_step) of a walk that is
/// not grouped, a step exposes nothing and its public output is the zero
/// suffix every internal circuit carries.
#[derive(Clone)]
pub struct Step<C: Cycle, R: Rank> {
    step: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank> Step<C, R> {
    /// Creates step `step`.
    ///
    /// # Panics
    ///
    /// Panics if `step` is not a step of the walk.
    pub fn new(step: usize) -> MultiStage<C::CircuitField, R, Self> {
        let num_steps = NumSteps::<C::Profile>::len();
        assert!(
            step < num_steps,
            "step {step} exceeds available steps ({num_steps})"
        );
        MultiStage::new(Self {
            step,
            _marker: PhantomData,
        })
    }
}

impl<C: ProfiledCycle, R: Rank> MultiStageCircuit<C::CircuitField, R> for Step<C, R> {
    type Last = GroupStage<C::NestedCurve, C::Profile>;
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
        let (group, _) = walk_grouping::<C::Profile>().locate(self.step);

        let dr = dr.skip_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let (walk, dr) = dr.add_stage_beside::<WalkStage<C::NestedCurve, C::Profile>>()?;
        let (points, dr) = dr.add_stage::<GroupStage<C::NestedCurve, C::Profile>>()?;
        let dr = dr.finish();

        // The stages are loaded unenforced: `Bind` holds the endoscalar's
        // bits and the group's check circuit its points.
        let walk = walk.unenforced(dr, witness.as_ref().map(|w| w.walk))?;
        let points = points.unenforced(dr, witness.as_ref().map(|w| &w.grouped.groups[group]))?;
        endoscalar::step_page(dr, &walk.endoscalar, &points, self.step)?;

        Ok(WithAux::new(
            WithSuffix::new((), Element::zero(dr)),
            D::unit(),
        ))
    }
}

/// The check circuit of one group of a grouped native walk.
#[derive(Clone)]
pub struct Check<C: Cycle, R: Rank> {
    group: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank> Check<C, R> {
    /// Creates the check circuit of group `group`.
    ///
    /// # Panics
    ///
    /// Panics if the profile's walk is not grouped or has no such group.
    pub fn new(group: usize) -> MultiStage<C::CircuitField, R, Self> {
        let grouping = walk_grouping::<C::Profile>();
        assert!(grouping.is_grouped(), "the profile's walk is not grouped");
        assert!(group < grouping.groups(), "the walk has no group {group}");
        MultiStage::new(Self {
            group,
            _marker: PhantomData,
        })
    }
}

impl<C: ProfiledCycle, R: Rank> MultiStageCircuit<C::CircuitField, R> for Check<C, R> {
    type Last = FStage<C::NestedCurve, C::Profile>;
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
        let (binding, dr) = dr.add_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let dr = dr.skip_stage_beside::<WalkStage<C::NestedCurve, C::Profile>>()?;
        let (points, dr) = dr.add_stage::<GroupStage<C::NestedCurve, C::Profile>>()?;
        let (links, dr) = dr.add_stage::<LinksStage<C::NestedCurve, C::Profile>>()?;
        let (preamble, dr) = dr.add_stage_beside::<PreambleStage<C::NestedCurve, C::Profile>>()?;
        let (registry_wx, dr) = dr.add_stage::<RegistryWxStage<C::NestedCurve, C::Profile>>()?;
        let (ab, dr) = dr.add_stage::<AbStage<C::NestedCurve, C::Profile>>()?;
        let (f, dr) = dr.add_stage::<FStage<C::NestedCurve, C::Profile>>()?;
        let dr = dr.finish();

        let inputs = witness.as_ref().map(|w| w.inputs);
        let binding = binding.unenforced(dr, inputs.as_ref().map(|i| &i.binding))?;
        let preamble = preamble.unenforced(dr, inputs.as_ref().map(|i| &i.preamble))?;
        let registry_wx = registry_wx.unenforced(dr, inputs.as_ref().map(|i| &i.registry_wx))?;
        let ab = ab.unenforced(dr, inputs.as_ref().map(|i| &i.ab))?;
        let f = f.unenforced(dr, inputs.as_ref().map(|i| &i.f))?;
        let group = self.group;
        let points = points.unenforced(dr, witness.as_ref().map(|w| &w.grouped.groups[group]))?;
        let links = links.unenforced(dr, witness.as_ref().map(|w| &w.grouped.links))?;

        // The stage contracts: the group's points on the curve, the unused
        // slots of a short last group among them.
        points.enforce_consistent(dr)?;

        // The walked points: each input of the group is the point of the
        // stage the transcript commits it in.
        let held = WalkInputs {
            binding: &binding,
            preamble: &preamble,
            registry_wx: &registry_wx,
            ab: &ab,
            f: &f,
        };
        let grouping = walk_grouping::<C::Profile>();
        for (local, index) in grouping.inputs_of(group).enumerate() {
            points.inputs[local].enforce_equal(dr, held.input(index))?;
        }

        // The chain: the group starts from its link and ends at the next.
        let exit = &points.interstitials[grouping.pages_of(group) - 1];
        paging::link(dr, &links.states, group, &points.initial, exit)?;

        Ok(WithAux::new(
            WithSuffix::new((), Element::zero(dr)),
            D::unit(),
        ))
    }
}

/// Circuit binding a grouped native walk at both ends, in the place of
/// [`bind_endoscalar`](super::bind_endoscalar): the walk stage's
/// endoscalar bits to `pre_beta`, the first link to $F_n$, the last link
/// to the instance's $P_n$, and the persistent polynomial commitments to
/// the unified instance.
///
/// Its public output is that circuit's ([`Output`]), so a parent computes
/// the claim's $k(y)$ the same way.
pub struct Bind<C: Cycle, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank> Bind<C, R> {
    pub fn new() -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Bind {
            _marker: PhantomData,
        })
    }
}

/// Witness of [`Bind`]: the unified instance and the walk's.
pub struct BindWitness<'a, C: ProfiledCycle> {
    pub unified: unified::Instance<C>,
    pub walk: Witness<'a, C>,
}

impl<C: ProfiledCycle, R: Rank> MultiStageCircuit<C::CircuitField, R> for Bind<C, R> {
    type Last = FStage<C::NestedCurve, C::Profile>;
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = BindWitness<'source, C>;
    type Output = Kind![C::CircuitField; WithSuffix<'_, _, Output<'_, _, C>>];
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (binding, builder) = builder.add_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let (walk, builder) =
            builder.add_stage_beside::<WalkStage<C::NestedCurve, C::Profile>>()?;
        let builder = builder.skip_stage::<GroupStage<C::NestedCurve, C::Profile>>()?;
        let (links, builder) = builder.add_stage::<LinksStage<C::NestedCurve, C::Profile>>()?;
        let (preamble, builder) =
            builder.add_stage_beside::<PreambleStage<C::NestedCurve, C::Profile>>()?;
        let (registry_wx, builder) =
            builder.add_stage::<RegistryWxStage<C::NestedCurve, C::Profile>>()?;
        let (ab, builder) = builder.add_stage::<AbStage<C::NestedCurve, C::Profile>>()?;
        let (f, builder) = builder.add_stage::<FStage<C::NestedCurve, C::Profile>>()?;
        let dr = builder.finish();

        // The input stages are loaded unenforced: every point of them the
        // walk consumes equals a point of a group, which the group's check
        // circuit holds to the curve.
        let stages = witness.as_ref().map(|w| w.walk);
        let inputs = stages.as_ref().map(|w| w.inputs);
        let binding = binding.unenforced(dr, inputs.as_ref().map(|i| &i.binding))?;
        let preamble = preamble.unenforced(dr, inputs.as_ref().map(|i| &i.preamble))?;
        let registry_wx = registry_wx.unenforced(dr, inputs.as_ref().map(|i| &i.registry_wx))?;
        let ab = ab.unenforced(dr, inputs.as_ref().map(|i| &i.ab))?;
        let f = f.unenforced(dr, inputs.as_ref().map(|i| &i.f))?;
        let walk = walk.unenforced(dr, stages.as_ref().map(|w| w.walk))?;
        let links = links.unenforced(dr, stages.as_ref().map(|w| &w.grouped.links))?;

        // The binding stage's one point that is not walked.
        for point in binding.online_input.iter() {
            point.enforce_consistent(dr)?;
        }

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        // The walk stage's contracts: its bits are the canonical extraction
        // of `pre_beta` and its products are the products of those bits.
        // Hoisting the extracted endoscalar derives the products, and the
        // conservative equality transfers both to the stage's wires.
        let pre_beta = unified_output.pre_beta.read(dr, allocator)?;
        let pre_beta = EndoscalarChallenge::from_element(dr, allocator, pre_beta)?;
        let extracted = HoistedEndoscalar::hoist(dr, Endoscalar::extract(pre_beta))?;
        extracted.enforce_conservative_equal(dr, &walk.endoscalar)?;

        // The walk starts from F_n, and its last link is P_n: pin it to the
        // instance, where a parent reads it.
        let states = &links.states;
        states
            .first()
            .expect("a grouped walk has links")
            .enforce_equal(dr, &f.f)?;
        let p = unified_output.nested_p_commitment.receive(dr, allocator)?;
        states
            .last()
            .expect("a grouped walk has links")
            .enforce_equal(dr, &p)?;

        let a = unified_output.nested_a_commitment.receive(dr, allocator)?;
        ab.a.enforce_equal(dr, &a)?;
        let b = unified_output.nested_b_commitment.receive(dr, allocator)?;
        ab.b.enforce_equal(dr, &b)?;
        let registry_xy = unified_output
            .nested_registry_xy_commitment
            .receive(dr, allocator)?;
        f.registry_xy.enforce_equal(dr, &registry_xy)?;

        // The nested online commitments, as the walk takes them.
        let online_points = preamble
            .online_points
            .iter()
            .chain(registry_wx.online_points.iter())
            .chain(ab.online_points.iter())
            .chain(f.online_points.iter())
            .cloned()
            .collect_fixed()?;
        let (output, aux) = unified_output.finish_with(dr, allocator, |unified| Output {
            unified,
            online_points,
        })?;
        Ok(WithAux::new(output, aux))
    }
}
