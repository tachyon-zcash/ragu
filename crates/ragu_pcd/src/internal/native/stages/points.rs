//! The native points stages: the nested-curve commitments the nested batch
//! folds into $P_n$, split by the challenge each must be fixed before, and
//! the walk's endoscalar and interstitials.
//!
//! The nested side keeps its points in one stage committed after $\beta$ and
//! binds that stage to the transcript-absorbed bridge stages with a loading
//! circuit. Here the points *are* the transcript-bound stages: each input
//! stage is committed at the point of the fuse where its points exist, its
//! host-curve commitment rides in the bridge stage absorbed next, and the
//! endoscaling steps read the points where they were committed. So the
//! nested batch's commitments are fixed before the challenges the nested
//! openings are at, exactly as the native batch's are:
//!
//! - [`BindingStage`] holds the children's bridge and challenge-stage
//!   commitments, $A_n$, $B_n$, `registry_xy`, $P_n$ and the nested
//!   extension stages, fixed before $w$ and carried by the `preamble`
//!   bridge.
//! - [`PreambleStage`] holds the rest of the children's nested commitments
//!   and the step's own online Fq commitments, fixed before $w$ and carried
//!   by the `preamble` bridge.
//! - [`RegistryWxStage`] holds $m_n(w_n, x_{i,n}, Y)$, fixed before $y$ and
//!   carried by the `s_prime` bridge.
//! - [`AbStage`] holds $m_n(w_n, X, y_n)$, $A_n$ and $B_n$, fixed before $x$
//!   and carried by the `ab` bridge.
//! - [`FStage`] holds $m_n(W, x_n, y_n)$ and $F_n$, fixed before $u$ and
//!   carried by the `f` bridge.
//!
//! Every point is fixed before the random point it is opened at: the
//! `registry_wy` restriction is opened at $x_n$, and the `registry_xy`
//! restriction is pinned to the registry by the parent's opening at its own
//! $w$, so neither needs a stage of its own before the batching challenge.
//!
//! [`BindingStage`] is the root of the whole native stage tree, so the
//! circuits on the preamble chain reserve it too: that is what lets
//! [`bind_beta`](super::super::circuits::bind_beta) hold the points it
//! walks against what the children exported through their unified
//! instances: their bridge commitments, completed challenge bindings and
//! persistent polynomial commitments; and what lets
//! [`collapse`](super::super::circuits::collapse) take the
//! children's nested extension stage commitments, which it holds the
//! children's binding circuits to through their claims' $k(y)$ (see
//! [`Binding`](crate::profile::Binding)). [`WalkStage`], committed after
//! $\beta$, holds the endoscalar's
//! bits and the walk's interstitials and closes the steps' chain; its last
//! interstitial is this step's $P_n$, which
//! [`bind_endoscalar`](super::super::circuits::bind_endoscalar) pins to the
//! step's own [`nested_p_commitment`] slot. That circuit also exports the
//! $A_n$, $B_n$ and `registry_xy` points for the next parent and the decider.
//! Every points stage's curve membership is enforced once, by `bind_endoscalar`.
//!
//! # A walk of several segments
//!
//! A step reserves every stage on its chain, a gate per point they hold, so
//! a walk whose steps read the points where they were committed is bounded
//! by the rank's gate budget. A profile whose walk is longer cuts it into
//! segments ([`Walk`](super::super::Walk)), and three more stages sit
//! between [`BindingStage`] and [`PreambleStage`], each committed after
//! $\beta$ and each holding nothing for a walk of one segment:
//!
//! - [`BitsStage`] holds the endoscalar's bits, which [`WalkStage`] then
//!   does not.
//! - [`SegmentStage`] holds one segment as a walk of its own: the point it
//!   starts from, copies of the inputs it folds and its steps' outputs. A
//!   proof carries a polynomial of it per segment, and a step reserves the
//!   chain up to it and reads its own segment's alone.
//! - [`BoundariesStage`] holds the output every segment but the last hands
//!   to the next.
//!
//! The copies are held to the stages that committed the points by a
//! [`walk_loading`](super::super::circuits::walk_loading) bonding per
//! segment, which reserves the whole chain: it enforces each input the
//! segment holds equal to its source, the segment's initial point equal to
//! $F_n$ or to the boundary before it, and its last output equal to its own
//! boundary. A step reads no stage in which every point is on the curve by
//! `bind_endoscalar`'s check, so it holds the points it reads and writes to
//! the curve itself, and `bind_endoscalar` holds only the points the walk
//! does not fold.
//!
//! [`nested_p_commitment`]: super::super::unified::Output::nested_p_commitment

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    ENDOSCALAR_BITS, ENDOSCALAR_PRODUCTS, HoistedEndoscalar, Point, Uendo,
    consistent::Consistent,
    vec::{ConstLen, FixedVec, Len},
};
use udon::curve::EndomorphismAffine as Affine;

pub use super::super::NumSteps;
use super::super::{Endoscalings, NumPoints, Split, segments};
use crate::{
    internal::{
        Side,
        endoscalar::{InputsLen, PointsWitness},
        nested::{
            self,
            online::{BoundCommitmentsLen, FqEarlyPointsLen, FqPointsLen},
            pcs::NUM_CURRENT_POINTS,
        },
    },
    profile::{
        Profile,
        online::{
            Phase,
            stages::{Nested, PhaseLen, Present, phase_points},
        },
    },
};

/// Length type for the walk's inputs, the initial point aside.
pub type NumInputs<P> = InputsLen<NumPoints<P>>;

/// The number of points a child contributes to the walk in profile `P`:
/// every nested rx commitment, then $a_n$, $b_n$, `registry_xy` and $P_n$.
pub fn num_child_points<P: Profile>() -> usize {
    nested::pcs::num_child_points(nested::RxIndex::num::<P>())
}

/// Length type for a child's bridge commitments, in transcript order.
pub type BridgesLen = ConstLen<{ nested::RxIndex::BRIDGES.len() }>;

/// The points of [`BindingStage`] per child in profile `P`: its bridge and
/// challenge commitments and its four persistent polynomial commitments,
/// tied to its unified instance, and its nested extension stages, tied to
/// its binding circuit. The stages a nested walk of several segments adds
/// to that extension are not among them: no binding names one, so they are
/// walked from [`PreambleStage`] with the rest.
pub fn num_child_bindings<P: Profile>() -> usize {
    nested::RxIndex::BRIDGES.len() + 5 + nested::NumDeclaredStages::<P>::len()
}

/// The child points of [`PreambleStage`] in profile `P`: each child's points in
/// walk order, except the ones [`BindingStage`] holds.
pub fn num_children_points<P: Profile>() -> usize {
    2 * (num_child_points::<P>() - num_child_bindings::<P>())
}

/// Length type for the child points in [`PreambleStage`].
pub struct ChildrenLen<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for ChildrenLen<P> {
    fn len() -> usize {
        num_children_points::<P>()
    }
}

/// The position of a child's $P_n$ among its points: the last, as
/// [`nested::pcs::child_commitments`] orders them.
fn child_p<P: Profile>() -> usize {
    num_child_points::<P>() - 1
}

/// The position of a child's challenge-stage commitment among its points.
fn child_challenges<P: Profile>() -> usize {
    nested::RxIndex::ChallengeStage.position::<P>()
}

/// Where an input of the walk lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputSource {
    /// A child's bridge commitment, in transcript absorption order.
    Bridge(Side, usize),
    /// A child's challenge-stage commitment, in [`BindingStage`].
    Challenges(Side),
    /// A child's $P_n$, in [`BindingStage`].
    P(Side),
    /// A child's persistent $A_n$ commitment.
    ChildA(Side),
    /// A child's persistent $B_n$ commitment.
    ChildB(Side),
    /// A child's persistent registry restriction commitment.
    ChildRegistryXy(Side),
    /// A child's nested extension stage commitment, by stage, in
    /// [`BindingStage`].
    Extension(Side, usize),
    /// A child commitment in [`PreambleStage`], by position.
    Children(usize),
    /// One of the two points of [`RegistryWxStage`].
    RegistryWx(usize),
    /// The `registry_wy` point of [`AbStage`].
    RegistryWy,
    /// $A_n$, in [`AbStage`].
    AbA,
    /// $B_n$, in [`AbStage`].
    AbB,
    /// The `registry_xy` point of [`FStage`].
    RegistryXy,
    /// The step's own nested fold randomizer $a_r$, in [`RegistryWxStage`].
    RandomizerA,
    /// The step's own nested fold randomizer $b_r$, in [`RegistryWxStage`].
    RandomizerB,
    /// The step's own nested batch randomizer, in [`FStage`].
    Mask,
    /// The step's own online Fq commitment, by index, in [`PreambleStage`].
    OnlineFq(usize),
    /// An online auxiliary in its later commitment phase, at a phase-local index.
    Auxiliary(Phase, usize),
}

/// The source of the walk's `i`-th input (the initial $F_n$ aside), in the
/// order [`nested::pcs::Batch::commitments`] fixes: for each child its
/// nested rx commitments in [`nested::RxIndex::all`] order, then its $a_n$,
/// $b_n$, `registry_xy` and $P_n$; then the current step's two
/// `registry_wx`, `registry_wy`, $A_n$, $B_n$, `registry_xy`, its two fold
/// randomizers and its batch randomizer; then the step's own online Fq
/// commitments (see [`online`](crate::internal::nested::online)).
///
/// # Panics
///
/// Panics if `i` is not an input index.
pub fn input_source<P: Profile>(i: usize) -> InputSource {
    let num_child_points = num_child_points::<P>();
    if i < 2 * num_child_points {
        let side = if i < num_child_points {
            Side::Left
        } else {
            Side::Right
        };
        let k = i % num_child_points;
        let challenges = child_challenges::<P>();
        if k == challenges {
            return InputSource::Challenges(side);
        }
        if k == child_p::<P>() {
            return InputSource::P(side);
        }
        let nested_rx = nested::RxIndex::num::<P>();
        if k >= nested_rx {
            return match k - nested_rx {
                0 => InputSource::ChildA(side),
                1 => InputSource::ChildB(side),
                2 => InputSource::ChildRegistryXy(side),
                _ => unreachable!("P_n was handled above"),
            };
        }
        let all = nested::RxIndex::all::<P>();
        let id = all[k];
        if let Some(i) = nested::RxIndex::BRIDGES
            .iter()
            .position(|&bridge| bridge == id)
        {
            return InputSource::Bridge(side, i);
        }
        // The extension's declared stages; the nested walk's own follow
        // them and are walked from the preamble stage.
        let declared = nested::NumDeclaredStages::<P>::len();
        let declared_stage = |id: nested::RxIndex| matches!(id, nested::RxIndex::ExtensionStage(j) if (j as usize) < declared);
        if let nested::RxIndex::ExtensionStage(j) = id
            && declared_stage(id)
        {
            return InputSource::Extension(side, j as usize);
        }
        let bound = |id: nested::RxIndex| {
            id == nested::RxIndex::ChallengeStage
                || nested::RxIndex::BRIDGES.contains(&id)
                || declared_stage(id)
        };
        let offset = all[..k].iter().filter(|&&id| !bound(id)).count();
        let base = match side {
            Side::Left => 0,
            Side::Right => num_child_points - num_child_bindings::<P>(),
        };
        return InputSource::Children(base + offset);
    }
    // The current step's points, in the order of
    // `nested::pcs::CurrentCommitments::into_array`.
    const CURRENT: [InputSource; NUM_CURRENT_POINTS] = [
        InputSource::RegistryWx(0),
        InputSource::RegistryWx(1),
        InputSource::RegistryWy,
        InputSource::AbA,
        InputSource::AbB,
        InputSource::RegistryXy,
        InputSource::RandomizerA,
        InputSource::RandomizerB,
        InputSource::Mask,
    ];
    match i - 2 * num_child_points {
        j if j < NUM_CURRENT_POINTS => CURRENT[j],
        j if j - NUM_CURRENT_POINTS < FqPointsLen::<P>::len() => {
            let index = j - NUM_CURRENT_POINTS;
            if index < FqEarlyPointsLen::<P>::len() {
                InputSource::OnlineFq(index)
            } else {
                let index = index - P::ONLINE_FQ_POLYS;
                let phase = P::NESTED_ONLINE.polynomials[index];
                InputSource::Auxiliary(phase, index - P::NESTED_ONLINE.phase_range(phase).start)
            }
        }
        _ => panic!("input {i} is past the walk"),
    }
}

/// A child's points tied to its native unified instance, and its nested
/// extension stages, tied to its binding circuit.
#[derive(Clone)]
pub struct ChildBindingWitness<C: Affine, P: Profile> {
    pub bridges: [C; nested::RxIndex::BRIDGES.len()],
    pub challenges: C,
    pub a: C,
    pub b: C,
    pub registry_xy: C,
    pub p: C,
    /// The child's nested extension stage commitments, by stage: the
    /// stages the extension declares.
    pub extension: FixedVec<C, nested::NumDeclaredStages<P>>,
    /// The commitments of the child's own online Fq polynomials it
    /// exported, tied to its `bind_endoscalar` and binding circuits. The
    /// walk does not fold them: the child's own walk did.
    pub online_fq: FixedVec<C, BoundCommitmentsLen<P>>,
}

/// Witness of [`BindingStage`]: the points tied to each child's instance
/// and binding circuit.
#[derive(Clone)]
pub struct BindingWitness<C: Affine, P: Profile> {
    /// This step's nested online input stage, committed before w.
    pub online_input: FixedVec<C, Present<P, Nested, 1>>,
    pub left: ChildBindingWitness<C, P>,
    pub right: ChildBindingWitness<C, P>,
}

/// Witness of [`PreambleStage`].
#[derive(Clone)]
pub struct PreambleWitness<C: Affine, P: Profile> {
    pub points: FixedVec<C, ChildrenLen<P>>,
    /// The step's own online Fq commitments.
    pub online_fq: FixedVec<C, FqEarlyPointsLen<P>>,
}

/// Witness of [`RegistryWxStage`].
#[derive(Clone)]
pub struct RegistryWxWitness<C: Affine, P: Profile> {
    /// Nested online auxiliaries fixed at this boundary.
    pub online_points: FixedVec<C, PhaseLen<P, Nested, 1>>,
    pub registry_wx0: C,
    pub registry_wx1: C,
    /// The step's own nested fold randomizers, fixed here with the
    /// restrictions, before the fold's challenges.
    pub randomizer_a: C,
    pub randomizer_b: C,
}

/// Witness of [`AbStage`].
#[derive(Clone)]
pub struct AbWitness<C: Affine, P: Profile> {
    /// Nested online auxiliaries fixed at this boundary.
    pub online_points: FixedVec<C, PhaseLen<P, Nested, 2>>,
    pub registry_wy: C,
    pub a: C,
    pub b: C,
}

/// Witness of [`FStage`].
#[derive(Clone)]
pub struct FWitness<C: Affine, P: Profile> {
    /// Nested online auxiliaries fixed at this boundary.
    pub online_points: FixedVec<C, PhaseLen<P, Nested, 3>>,
    pub registry_xy: C,
    pub f: C,
    /// The step's own nested batch randomizer, fixed here with $F_n$.
    pub mask: C,
}

/// Length type that is one for a native walk of one segment in profile `P`
/// and zero for a walk of several.
pub struct Whole<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for Whole<P> {
    fn len() -> usize {
        !segments::<P>().is_split() as usize
    }
}

/// Length type for the interstitials [`WalkStage`] holds in profile `P`:
/// one per step of a walk of one segment, and none of a walk of several,
/// whose segments hold them.
pub struct WalkSteps<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for WalkSteps<P> {
    fn len() -> usize {
        if segments::<P>().is_split() {
            0
        } else {
            NumSteps::<P>::len()
        }
    }
}

/// Length type for the points a segment of profile `P`'s walk is a walk
/// over: its initial point and the inputs of a full segment's steps.
pub struct SegmentPoints<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for SegmentPoints<P> {
    fn len() -> usize {
        segments::<P>().stage_points()
    }
}

/// Length type for the inputs [`SegmentStage`] holds copies of in profile
/// `P`: those of a full segment's steps, and none for a walk of one
/// segment.
pub struct SegmentInputs<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for SegmentInputs<P> {
    fn len() -> usize {
        let walk = segments::<P>();
        if walk.is_split() {
            walk.steps_per_segment() * P::NATIVE_ENDOSCALINGS_PER_STEP
        } else {
            0
        }
    }
}

/// Length type for the interstitials [`SegmentStage`] holds in profile `P`:
/// one per step of a full segment, and none for a walk of one segment.
pub struct SegmentSteps<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for SegmentSteps<P> {
    fn len() -> usize {
        let walk = segments::<P>();
        if walk.is_split() {
            walk.steps_per_segment()
        } else {
            0
        }
    }
}

/// Length type for the points [`BoundariesStage`] holds in profile `P`: one
/// per segment of the walk but the last.
pub struct NumBoundaries<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumBoundaries<P> {
    fn len() -> usize {
        segments::<P>().count() - 1
    }
}

/// Witness of [`SegmentStage`]: one segment of a walk of several, as a walk
/// of its own.
pub type SegmentWitness<C, P> = PointsWitness<C, SegmentPoints<P>, Endoscalings<P>>;

/// Witness of the stages committed after $\beta$: the endoscalar and the
/// walk's outputs.
///
/// A walk of one segment has an interstitial per step, which [`WalkStage`]
/// holds beside the endoscalar's bits. A walk of several has the witness of
/// [`SegmentStage`] for each segment and the points [`BoundariesStage`]
/// holds, and its bits are [`BitsStage`]'s.
#[derive(Clone)]
pub struct WalkWitness<C: Affine, P: Profile> {
    pub endoscalar: Uendo,
    /// The walk's outputs, one per step, for a walk of one segment.
    pub interstitials: FixedVec<C, WalkSteps<P>>,
    /// Each segment's points, in walk order, for a walk of several
    /// segments.
    pub segments: Vec<SegmentWitness<C, P>>,
    /// The last interstitial of every segment but the last, which the next
    /// segment starts from.
    pub boundaries: FixedVec<C, NumBoundaries<P>>,
    /// The walk's result.
    p: C,
}

impl<C: Affine, P: Profile> WalkWitness<C, P> {
    /// Walks `points`, the initial $F_n$ first, under `endoscalar`.
    ///
    /// # Panics
    ///
    /// Panics if `points` are not the walk's [`NumPoints`].
    pub fn new(endoscalar: Uendo, points: &[C]) -> Self {
        let walk = segments::<P>();
        assert_eq!(
            points.len(),
            NumPoints::<P>::len(),
            "the walk is over the nested batch's points"
        );
        if !walk.is_split() {
            let whole = PointsWitness::<C, NumPoints<P>, Endoscalings<P>>::new(endoscalar, points);
            return Self {
                endoscalar,
                p: *whole
                    .interstitials
                    .last()
                    .expect("every walk has at least one interstitial"),
                interstitials: FixedVec::from_fn(|step| whole.interstitials[step]),
                segments: Vec::new(),
                boundaries: FixedVec::from_fn(|_| unreachable!("one segment has no boundary")),
            };
        }
        let inputs = &points[1..];
        let mut initial = points[0];
        let mut witnesses = Vec::with_capacity(walk.count());
        for segment in 0..walk.count() {
            let witness = SegmentWitness::<C, P>::segment(
                endoscalar,
                initial,
                &inputs[walk.inputs_of(segment)],
            );
            initial = witness.interstitials[walk.steps_of(segment) - 1];
            witnesses.push(witness);
        }
        Self {
            endoscalar,
            p: initial,
            interstitials: FixedVec::from_fn(|_| {
                unreachable!("the segments hold a split walk's interstitials")
            }),
            boundaries: FixedVec::from_fn(|segment| {
                witnesses[segment].interstitials[walk.steps_per_segment() - 1]
            }),
            segments: witnesses,
        }
    }

    /// The walk's result: $P_n$.
    pub fn p(&self) -> C {
        self.p
    }

    /// The witness of the segment that step `step` of a walk of several
    /// segments belongs to.
    ///
    /// # Panics
    ///
    /// Panics if the walk is one segment or `step` is not a step of it.
    pub fn segment_of(&self, step: usize) -> &SegmentWitness<C, P> {
        &self.segments[segments::<P>().locate(step).0]
    }

    /// The witness of the segment a walk of several segments ends in.
    ///
    /// # Panics
    ///
    /// Panics if the walk is one segment.
    pub fn last_segment(&self) -> &SegmentWitness<C, P> {
        self.segments
            .last()
            .expect("a walk of several segments has a last one")
    }
}

/// Splits the two children's points, each in the order
/// [`nested::pcs::child_commitments`] fixes, into the binding and preamble
/// stages' witnesses. The binding stage also holds `exported`, the online
/// Fq commitments the left and the right child exported, and the preamble
/// stage `online_fq`, the step's own online Fq commitments.
///
/// # Panics
///
/// Panics if either child has other than [`num_child_points`] points or
/// other than the profile's exported commitments, or if `online_fq` has
/// other than [`FqEarlyPointsLen`] points.
pub fn preamble_witnesses<C: Affine, P: Profile>(
    left: &[C],
    right: &[C],
    exported: [&[C]; 2],
    online_fq: &[C],
    online_input: FixedVec<C, Present<P, Nested, 1>>,
) -> (BindingWitness<C, P>, PreambleWitness<C, P>) {
    let num_child_points = num_child_points::<P>();
    let nested_rx = nested::RxIndex::num::<P>();
    assert_eq!(left.len(), num_child_points);
    assert_eq!(right.len(), num_child_points);
    let bound = |points: &[C], exported: &[C]| ChildBindingWitness {
        bridges: core::array::from_fn(|i| points[nested::RxIndex::BRIDGES[i].position::<P>()]),
        challenges: points[child_challenges::<P>()],
        a: points[nested_rx],
        b: points[nested_rx + 1],
        registry_xy: points[nested_rx + 2],
        p: points[child_p::<P>()],
        extension: FixedVec::from_fn(|j| {
            points[nested::RxIndex::ExtensionStage(j as u32).position::<P>()]
        }),
        online_fq: FixedVec::new(exported.to_vec()).expect("the exported online Fq commitments"),
    };
    let rest = |points: &[C]| {
        points
            .iter()
            .enumerate()
            .filter(|&(k, _)| matches!(input_source::<P>(k), InputSource::Children(_)))
            .map(|(_, &point)| point)
            .collect::<Vec<_>>()
    };
    let mut points = rest(left);
    points.extend(rest(right));
    (
        BindingWitness {
            online_input,
            left: bound(left, exported[0]),
            right: bound(right, exported[1]),
        },
        PreambleWitness {
            points: FixedVec::new(points).expect("num_children_points points"),
            online_fq: FixedVec::new(online_fq.to_vec()).expect("ONLINE_FQ_POLYS points"),
        },
    )
}

/// The witnesses of every input stage: the walk's inputs, in the stages
/// that commit them.
#[derive(Clone)]
pub struct Inputs<C: Affine, P: Profile> {
    pub binding: BindingWitness<C, P>,
    pub preamble: PreambleWitness<C, P>,
    pub registry_wx: RegistryWxWitness<C, P>,
    pub ab: AbWitness<C, P>,
    pub f: FWitness<C, P>,
}

impl<C: Affine, P: Profile> Inputs<C, P> {
    /// Splits the walk's points, the initial $F_n$ first, into the stages,
    /// with `exported`, the online Fq commitments the left and the right
    /// child exported, which the binding stage holds and the walk does not
    /// fold.
    ///
    /// # Panics
    ///
    /// Panics if `points.len() != NumPoints::<P>::len()`.
    pub fn from_walk(
        points: &[C],
        exported: [&[C]; 2],
        online_input: FixedVec<C, Present<P, Nested, 1>>,
    ) -> Self {
        let num_child_points = num_child_points::<P>();
        assert_eq!(points.len(), NumPoints::<P>::len());
        let current = &points[1 + 2 * num_child_points..];
        let (binding, preamble) = preamble_witnesses::<C, P>(
            &points[1..1 + num_child_points],
            &points[1 + num_child_points..1 + 2 * num_child_points],
            exported,
            &current[NUM_CURRENT_POINTS..NUM_CURRENT_POINTS + FqEarlyPointsLen::<P>::len()],
            online_input,
        );
        Self {
            binding,
            preamble,
            registry_wx: RegistryWxWitness {
                online_points: phase_points::<P, Nested, 1, _>(
                    &current[NUM_CURRENT_POINTS + P::ONLINE_FQ_POLYS..],
                ),
                registry_wx0: current[0],
                registry_wx1: current[1],
                randomizer_a: current[6],
                randomizer_b: current[7],
            },
            ab: AbWitness {
                online_points: phase_points::<P, Nested, 2, _>(
                    &current[NUM_CURRENT_POINTS + P::ONLINE_FQ_POLYS..],
                ),
                registry_wy: current[2],
                a: current[3],
                b: current[4],
            },
            f: FWitness {
                online_points: phase_points::<P, Nested, 3, _>(
                    &current[NUM_CURRENT_POINTS + P::ONLINE_FQ_POLYS..],
                ),
                registry_xy: current[5],
                f: points[0],
                mask: current[8],
            },
        }
    }

    /// The walk's `i`-th input.
    pub fn input(&self, i: usize) -> C {
        let child = |side| match side {
            Side::Left => &self.binding.left,
            Side::Right => &self.binding.right,
        };
        match input_source::<P>(i) {
            InputSource::Bridge(side, i) => child(side).bridges[i],
            InputSource::Challenges(side) => child(side).challenges,
            InputSource::P(side) => child(side).p,
            InputSource::ChildA(side) => child(side).a,
            InputSource::ChildB(side) => child(side).b,
            InputSource::ChildRegistryXy(side) => child(side).registry_xy,
            InputSource::Extension(side, j) => child(side).extension[j],
            InputSource::Children(k) => self.preamble.points[k],
            InputSource::RegistryWx(0) => self.registry_wx.registry_wx0,
            InputSource::RegistryWx(_) => self.registry_wx.registry_wx1,
            InputSource::RegistryWy => self.ab.registry_wy,
            InputSource::AbA => self.ab.a,
            InputSource::AbB => self.ab.b,
            InputSource::RegistryXy => self.f.registry_xy,
            InputSource::RandomizerA => self.registry_wx.randomizer_a,
            InputSource::RandomizerB => self.registry_wx.randomizer_b,
            InputSource::Mask => self.f.mask,
            InputSource::OnlineFq(j) => self.preamble.online_fq[j],
            InputSource::Auxiliary(phase, j) => match phase {
                Phase::BeforeW => unreachable!("early points use OnlineFq"),
                Phase::BeforeY => self.registry_wx.online_points[j],
                Phase::BeforeX => self.ab.online_points[j],
                Phase::BeforeAlpha => self.f.online_points[j],
            },
        }
    }

    /// The walk's points, the initial $F_n$ first.
    pub fn walk(&self) -> Vec<C> {
        core::iter::once(self.f.f)
            .chain((0..NumInputs::<P>::len()).map(|i| self.input(i)))
            .collect()
    }
}

/// A child's walked points that must match its native unified instance,
/// and its nested extension stages, which must match its binding circuit's
/// output.
#[derive(Gadget, Consistent)]
pub struct ChildBinding<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    #[ragu(gadget)]
    pub bridges: FixedVec<Point<'dr, D, C>, BridgesLen>,
    #[ragu(gadget)]
    pub challenges: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub a: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub b: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_xy: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub p: Point<'dr, D, C>,
    /// The child's nested extension stage commitments, by stage: the
    /// stages the extension declares.
    #[ragu(gadget)]
    pub extension: FixedVec<Point<'dr, D, C>, nested::NumDeclaredStages<P>>,
    /// The commitments of the child's own online Fq polynomials it
    /// exported.
    #[ragu(gadget)]
    pub online_fq: FixedVec<Point<'dr, D, C>, BoundCommitmentsLen<P>>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> ChildBinding<'dr, D, C, P> {
    fn alloc(dr: &mut D, witness: DriverValue<D, &ChildBindingWitness<C, P>>) -> Result<Self> {
        Ok(Self {
            bridges: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.bridges[i]))
            })?,
            challenges: Point::alloc(dr, witness.as_ref().map(|w| w.challenges))?,
            a: Point::alloc(dr, witness.as_ref().map(|w| w.a))?,
            b: Point::alloc(dr, witness.as_ref().map(|w| w.b))?,
            registry_xy: Point::alloc(dr, witness.as_ref().map(|w| w.registry_xy))?,
            p: Point::alloc(dr, witness.as_ref().map(|w| w.p))?,
            extension: FixedVec::try_from_fn(|j| {
                Point::alloc(dr, witness.as_ref().map(|w| w.extension[j]))
            })?,
            online_fq: FixedVec::try_from_fn(|j| {
                Point::alloc(dr, witness.as_ref().map(|w| w.online_fq[j]))
            })?,
        })
    }
}

/// Output gadget of [`BindingStage`].
#[derive(Gadget, Consistent)]
pub struct Binding<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    /// The nested online input-stage commitment absorbed before w.
    #[ragu(gadget)]
    pub online_input: FixedVec<Point<'dr, D, C>, Present<P, Nested, 1>>,
    #[ragu(gadget)]
    pub left: ChildBinding<'dr, D, C, P>,
    #[ragu(gadget)]
    pub right: ChildBinding<'dr, D, C, P>,
}

/// Output gadget of [`PreambleStage`].
#[derive(Gadget, Consistent)]
pub struct Preamble<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    #[ragu(gadget)]
    pub points: FixedVec<Point<'dr, D, C>, ChildrenLen<P>>,
    /// The step's own online Fq commitments.
    #[ragu(gadget)]
    pub online_fq: FixedVec<Point<'dr, D, C>, FqEarlyPointsLen<P>>,
}

/// Output gadget of [`RegistryWxStage`].
#[derive(Gadget, Consistent)]
pub struct RegistryWx<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    /// Nested online auxiliaries fixed at this boundary.
    #[ragu(gadget)]
    pub online_points: FixedVec<Point<'dr, D, C>, PhaseLen<P, Nested, 1>>,
    #[ragu(gadget)]
    pub registry_wx0: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_wx1: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub randomizer_a: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub randomizer_b: Point<'dr, D, C>,
}

/// Output gadget of [`AbStage`].
#[derive(Gadget, Consistent)]
pub struct Ab<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    /// Nested online auxiliaries fixed at this boundary.
    #[ragu(gadget)]
    pub online_points: FixedVec<Point<'dr, D, C>, PhaseLen<P, Nested, 2>>,
    #[ragu(gadget)]
    pub registry_wy: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub a: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub b: Point<'dr, D, C>,
}

/// Output gadget of [`FStage`].
#[derive(Gadget, Consistent)]
pub struct F<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    /// Nested online auxiliaries fixed at this boundary.
    #[ragu(gadget)]
    pub online_points: FixedVec<Point<'dr, D, C>, PhaseLen<P, Nested, 3>>,
    #[ragu(gadget)]
    pub registry_xy: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub f: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub mask: Point<'dr, D, C>,
}

/// Output gadget of [`WalkStage`]: the endoscalar and an interstitial per
/// step for a walk of one segment, and nothing for a walk of several.
#[derive(Gadget)]
pub struct Walk<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    #[ragu(gadget)]
    pub endoscalar: FixedVec<HoistedEndoscalar<'dr, D>, Whole<P>>,
    #[ragu(gadget)]
    pub interstitials: FixedVec<Point<'dr, D, C>, WalkSteps<P>>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> Walk<'dr, D, C, P> {
    /// The walk's last interstitial: $P_n$.
    ///
    /// # Panics
    ///
    /// Panics for a walk of several segments, whose last segment holds it.
    pub fn p(&self) -> &Point<'dr, D, C> {
        self.interstitials
            .last()
            .expect("a walk of one segment has at least one interstitial")
    }
}

/// Output gadget of [`SegmentStage`]: a segment of a walk of several, as a
/// walk of its own, and nothing for a walk of one segment.
#[derive(Gadget)]
pub struct Segment<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    /// The point the segment starts from.
    #[ragu(gadget)]
    pub initial: FixedVec<Point<'dr, D, C>, Split<P>>,
    /// Copies of the walk's inputs the segment folds.
    #[ragu(gadget)]
    pub inputs: FixedVec<Point<'dr, D, C>, SegmentInputs<P>>,
    /// The segment's outputs, one per step.
    #[ragu(gadget)]
    pub interstitials: FixedVec<Point<'dr, D, C>, SegmentSteps<P>>,
}

/// The loaded input stages, viewed as the walk's inputs.
pub struct WalkInputs<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    pub binding: &'a Binding<'dr, D, C, P>,
    pub preamble: &'a Preamble<'dr, D, C, P>,
    pub registry_wx: &'a RegistryWx<'dr, D, C, P>,
    pub ab: &'a Ab<'dr, D, C, P>,
    pub f: &'a F<'dr, D, C, P>,
}

impl<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> WalkInputs<'a, 'dr, D, C, P> {
    /// The walk's initial point, $F_n$.
    pub fn initial(&self) -> &'a Point<'dr, D, C> {
        &self.f.f
    }

    /// The walk's `i`-th input.
    pub fn input(&self, i: usize) -> &'a Point<'dr, D, C> {
        let child = |side| match side {
            Side::Left => &self.binding.left,
            Side::Right => &self.binding.right,
        };
        match input_source::<P>(i) {
            InputSource::Bridge(side, i) => &child(side).bridges[i],
            InputSource::Challenges(side) => &child(side).challenges,
            InputSource::P(side) => &child(side).p,
            InputSource::ChildA(side) => &child(side).a,
            InputSource::ChildB(side) => &child(side).b,
            InputSource::ChildRegistryXy(side) => &child(side).registry_xy,
            InputSource::Extension(side, j) => &child(side).extension[j],
            InputSource::Children(k) => &self.preamble.points[k],
            InputSource::RegistryWx(0) => &self.registry_wx.registry_wx0,
            InputSource::RegistryWx(_) => &self.registry_wx.registry_wx1,
            InputSource::RegistryWy => &self.ab.registry_wy,
            InputSource::AbA => &self.ab.a,
            InputSource::AbB => &self.ab.b,
            InputSource::RegistryXy => &self.f.registry_xy,
            InputSource::RandomizerA => &self.registry_wx.randomizer_a,
            InputSource::RandomizerB => &self.registry_wx.randomizer_b,
            InputSource::Mask => &self.f.mask,
            InputSource::OnlineFq(j) => &self.preamble.online_fq[j],
            InputSource::Auxiliary(phase, j) => match phase {
                Phase::BeforeW => unreachable!("early points use OnlineFq"),
                Phase::BeforeY => &self.registry_wx.online_points[j],
                Phase::BeforeX => &self.ab.online_points[j],
                Phase::BeforeAlpha => &self.f.online_points[j],
            },
        }
    }
}

/// Defines a stage holding curve points, with a `Point` output field per
/// witness field.
macro_rules! points_stage {
    (
        $(#[$meta:meta])*
        $Stage:ident, parent = $Parent:ty, witness = $Witness:ident, output = $Output:ident, phase = $phase:literal,
        { $($field:ident),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Default)]
        pub struct $Stage<C: Affine, P: Profile>(PhantomData<(C, P)>);

        impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for $Stage<C, P> {
            type Parent = $Parent;
            type Witness<'source> = &'source $Witness<C,P>;
            type OutputKind = Kind![C::Base; $Output<'_, _, C,P>];

            fn values() -> usize {
                // (x, y) per point.
                2 * ([$(stringify!($field)),+].len() + PhaseLen::<P,Nested,$phase>::len())
            }

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<Bound<'dr, D, Self::OutputKind>>
            where
                Self: 'dr,
            {
                Ok($Output {
                    online_points: FixedVec::try_from_fn(|i| Point::alloc(dr,witness.as_ref().map(|w|w.online_points[i])))?,
                    $( $field: Point::alloc(dr, witness.as_ref().map(|w| w.$field))?, )+
                })
            }
        }
    };
}

/// The root of the native stage tree: the children's walked commitments
/// tied to their native unified instances and to their binding circuits,
/// committed before $w$.
#[derive(Default)]
pub struct BindingStage<C: Affine, P: Profile>(PhantomData<(C, P)>);

impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for BindingStage<C, P> {
    type Parent = ();
    type Witness<'source> = &'source BindingWitness<C, P>;
    type OutputKind = Kind![C::Base; Binding<'_, _, C, P>];

    fn values() -> usize {
        // (x, y) per point, of each child: the walked points and the
        // exported online Fq commitments; then this step's nested online
        // input stage.
        4 * (num_child_bindings::<P>() + BoundCommitmentsLen::<P>::len())
            + 2 * Present::<P, Nested, 1>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Binding {
            online_input: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.online_input[i]))
            })?,
            left: ChildBinding::alloc(dr, witness.as_ref().map(|w| &w.left))?,
            right: ChildBinding::alloc(dr, witness.as_ref().map(|w| &w.right))?,
        })
    }
}

/// The endoscalar's bits of a walk of several segments, bound to `pre_beta`
/// by `bind_endoscalar`; committed after $\beta$. Nothing for a walk of one
/// segment, whose bits [`WalkStage`] holds.
#[derive(Default)]
pub struct BitsStage<C: Affine, P: Profile>(PhantomData<(C, P)>);

impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for BitsStage<C, P> {
    type Parent = BindingStage<C, P>;
    type Witness<'source> = &'source WalkWitness<C, P>;
    type OutputKind = Kind![C::Base; FixedVec<HoistedEndoscalar<'_, _>, Split<P>>];

    fn values() -> usize {
        // The endoscalar's bits and hoisted products.
        Split::<P>::len() * (ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        FixedVec::try_from_fn(|_| {
            HoistedEndoscalar::alloc(dr, witness.as_ref().map(|w| w.endoscalar))
        })
    }
}

/// One segment of a walk of several segments: the point it starts from,
/// copies of the inputs it folds and its steps' outputs; committed after
/// $\beta$, a polynomial per segment. Nothing for a walk of one segment.
#[derive(Default)]
pub struct SegmentStage<C: Affine, P: Profile>(PhantomData<(C, P)>);

impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for SegmentStage<C, P> {
    type Parent = BitsStage<C, P>;
    type Witness<'source> = &'source SegmentWitness<C, P>;
    type OutputKind = Kind![C::Base; Segment<'_, _, C, P>];

    fn values() -> usize {
        // (x, y) per point.
        2 * (Split::<P>::len() + SegmentInputs::<P>::len() + SegmentSteps::<P>::len())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Segment {
            initial: FixedVec::try_from_fn(|_| {
                Point::alloc(dr, witness.as_ref().map(|w| w.initial))
            })?,
            inputs: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.inputs[i]))
            })?,
            interstitials: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.interstitials[i]))
            })?,
        })
    }
}

/// The output every segment of a walk of several segments but the last
/// hands to the next, in walk order; committed after $\beta$. Nothing for a
/// walk of one segment.
#[derive(Default)]
pub struct BoundariesStage<C: Affine, P: Profile>(PhantomData<(C, P)>);

impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for BoundariesStage<C, P> {
    type Parent = SegmentStage<C, P>;
    type Witness<'source> = &'source WalkWitness<C, P>;
    type OutputKind = Kind![C::Base; FixedVec<Point<'_, _, C>, NumBoundaries<P>>];

    fn values() -> usize {
        // (x, y) per point.
        2 * NumBoundaries::<P>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        FixedVec::try_from_fn(|i| Point::alloc(dr, witness.as_ref().map(|w| w.boundaries[i])))
    }
}

/// The rest of the children's nested commitments and the step's own online
/// Fq commitments, committed before $w$.
#[derive(Default)]
pub struct PreambleStage<C: Affine, P: Profile>(PhantomData<(C, P)>);

impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for PreambleStage<C, P> {
    // The stages of a walk of several segments sit before the input
    // stages, so that a step reserves none of those; they hold nothing for
    // a walk of one segment, whose chain is the input stages'.
    type Parent = BoundariesStage<C, P>;
    type Witness<'source> = &'source PreambleWitness<C, P>;
    type OutputKind = Kind![C::Base; Preamble<'_, _, C, P>];

    fn values() -> usize {
        2 * (num_children_points::<P>() + FqEarlyPointsLen::<P>::len())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Preamble {
            points: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.points[i]))
            })?,
            online_fq: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.online_fq[i]))
            })?,
        })
    }
}

points_stage!(
    /// The nested registry's $m_n(w_n, x_{i,n}, Y)$ commitments and the
    /// step's own nested fold randomizers, committed before $y$.
    RegistryWxStage, parent = PreambleStage<C, P>, witness = RegistryWxWitness, output = RegistryWx, phase = 1,
    { registry_wx0, registry_wx1, randomizer_a, randomizer_b }
);

points_stage!(
    /// The nested registry's $m_n(w_n, X, y_n)$ commitment and the nested
    /// accumulator's $A_n$ and $B_n$, committed before $x$.
    AbStage, parent = RegistryWxStage<C, P>, witness = AbWitness, output = Ab, phase = 2,
    { registry_wy, a, b }
);

points_stage!(
    /// The nested registry's $m_n(W, x_n, y_n)$ commitment, the nested
    /// quotient's $F_n$, the walk's initial point, and the step's own nested
    /// batch randomizer, committed before $u$.
    FStage, parent = AbStage<C, P>, witness = FWitness, output = F, phase = 3,
    { registry_xy, f, mask }
);

/// The walk's stage: $\beta$'s bits, bound to `pre_beta` by
/// `bind_endoscalar`, and the walk's outputs, one per step, the last of
/// which is $P_n$; committed after $\beta$. Nothing for a walk of several
/// segments, whose bits [`BitsStage`] holds and whose outputs its
/// segments do.
#[derive(Default)]
pub struct WalkStage<C: Affine, P: Profile>(PhantomData<(C, P)>);

impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for WalkStage<C, P> {
    type Parent = FStage<C, P>;
    type Witness<'source> = &'source WalkWitness<C, P>;
    type OutputKind = Kind![C::Base; Walk<'_, _, C, P>];

    fn values() -> usize {
        // The endoscalar's bits and hoisted products, then (x, y) of one
        // interstitial per step.
        Whole::<P>::len() * (ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS) + 2 * WalkSteps::<P>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Walk {
            endoscalar: FixedVec::try_from_fn(|_| {
                HoistedEndoscalar::alloc(dr, witness.as_ref().map(|w| w.endoscalar))
            })?,
            interstitials: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.interstitials[i]))
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::{EpAffine, Pasta};

    use super::*;
    use crate::{
        internal::tests::{R, assert_stage_values},
        profile::{
            Standard,
            testing::{Opening, Proving, Segmented},
        },
    };

    type C = <Pasta as ragu_core::Cycle>::NestedCurve;

    /// Each stage's declared values are its wires, in profile `P`.
    fn stage_values_match_wire_counts_in<P: Profile>() {
        assert_stage_values::<_, R, _>(&BindingStage::<C, P>::default());
        assert_stage_values::<_, R, _>(&BitsStage::<C, P>::default());
        assert_stage_values::<_, R, _>(&SegmentStage::<C, P>::default());
        assert_stage_values::<_, R, _>(&BoundariesStage::<C, P>::default());
        assert_stage_values::<_, R, _>(&PreambleStage::<C, P>::default());
        assert_stage_values::<_, R, _>(&RegistryWxStage::<C, P>::default());
        assert_stage_values::<_, R, _>(&AbStage::<C, P>::default());
        assert_stage_values::<_, R, _>(&FStage::<C, P>::default());
        assert_stage_values::<_, R, _>(&WalkStage::<C, P>::default());
    }

    #[test]
    fn stage_values_match_wire_counts() {
        let _: PhantomData<EpAffine> = PhantomData::<C>;
        stage_values_match_wire_counts_in::<Standard>();
        // With the step's own online Fq commitment in the preamble stage,
        // alone and beside an extension.
        stage_values_match_wire_counts_in::<Opening>();
        stage_values_match_wire_counts_in::<Proving>();
        // With both walks cut into segments.
        stage_values_match_wire_counts_in::<Segmented>();
    }

    /// The stages of a walk of several segments hold nothing for a walk of
    /// one, so the input stages sit where they did, and the walk stage
    /// holds nothing for a walk of several.
    #[test]
    fn the_segment_stages_are_empty_for_a_walk_of_one_segment() {
        use staging::{Stage, StageExt};

        assert_eq!(<BitsStage<C, Standard> as Stage<_, R>>::values(), 0);
        assert_eq!(<SegmentStage<C, Standard> as Stage<_, R>>::values(), 0);
        assert_eq!(<BoundariesStage<C, Standard> as Stage<_, R>>::values(), 0);
        assert_eq!(
            <PreambleStage<C, Standard> as Stage<_, R>>::skip_gates(),
            <BindingStage<C, Standard> as Stage<_, R>>::skip_gates()
                + <BindingStage<C, Standard> as StageExt<_, R>>::num_gates()
        );

        let walk = segments::<Segmented>();
        assert!(walk.is_split());
        assert_eq!(
            <BitsStage<C, Segmented> as Stage<_, R>>::values(),
            ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS
        );
        assert_eq!(
            <SegmentStage<C, Segmented> as Stage<_, R>>::values(),
            2 * (walk.stage_points() + walk.steps_per_segment())
        );
        assert_eq!(
            <BoundariesStage<C, Segmented> as Stage<_, R>>::values(),
            2 * (walk.count() - 1)
        );
        assert_eq!(<WalkStage<C, Segmented> as Stage<_, R>>::values(), 0);
    }

    /// The segments of a walk of several are one walk: each starts where
    /// the one before ended, the boundaries are the points handed over, and
    /// the last segment ends in the result of the walk held in one stage.
    #[test]
    fn a_segmented_walk_is_the_whole_walk() {
        use rand::{Rng, SeedableRng, rngs::StdRng};
        use udon::{curve::Projective, field::Field};

        type P = Segmented;
        let mut rng = StdRng::seed_from_u64(11);
        let points: Vec<C> = (0..NumPoints::<P>::len())
            .map(|_| {
                (ragu_core::pasta::Ep::generator()
                    * ragu_core::pasta::Fq::random(|bytes| rng.fill_bytes(bytes)))
                .to_affine()
            })
            .collect();
        let endoscalar = Uendo::from(0x1234_5678_9abc_def0_0fed_cba9_8765_4321_u128);
        let walk = segments::<P>();
        let witness = WalkWitness::<C, P>::new(endoscalar, &points);
        let whole = PointsWitness::<C, NumPoints<P>, Endoscalings<P>>::new(endoscalar, &points);

        assert_eq!(witness.segments.len(), walk.count());
        assert_eq!(witness.interstitials.len(), 0);
        assert_eq!(witness.segments[0].initial, points[0]);
        for step in 0..walk.steps() {
            let (segment, local) = walk.locate(step);
            assert_eq!(
                witness.segments[segment].interstitials[local], whole.interstitials[step],
                "step {step}"
            );
            assert!(core::ptr::eq(
                witness.segment_of(step),
                &witness.segments[segment]
            ));
        }
        for segment in 1..walk.count() {
            assert_eq!(
                witness.segments[segment].initial,
                witness.boundaries[segment - 1]
            );
            assert_eq!(
                witness.boundaries[segment - 1],
                whole.interstitials[segment * walk.steps_per_segment() - 1]
            );
        }
        for (i, &input) in points[1..].iter().enumerate() {
            let segment = i / (walk.steps_per_segment() * P::NATIVE_ENDOSCALINGS_PER_STEP);
            let slot = i - walk.inputs_of(segment).start;
            assert_eq!(witness.segments[segment].inputs[slot], input, "input {i}");
        }
        assert_eq!(
            witness.p(),
            *whole.interstitials.last().expect("a walk has a step")
        );
        assert_eq!(
            witness.last_segment().interstitials[walk.last_local_step()],
            witness.p()
        );

        // A walk of one segment keeps every interstitial in the walk stage.
        let points: Vec<C> = points[..NumPoints::<Standard>::len()].to_vec();
        let witness = WalkWitness::<C, Standard>::new(endoscalar, &points);
        assert!(witness.segments.is_empty());
        assert_eq!(witness.interstitials.len(), NumSteps::<Standard>::len());
        assert_eq!(
            witness.p(),
            *witness.interstitials.last().expect("a walk has a step")
        );
    }

    /// Every input has exactly one source, and splitting the walk into the
    /// stages and reading it back is the identity, in profile `P`. The
    /// step's own online Fq commitments are the walk's last inputs, in slot
    /// order, read from the preamble stage.
    fn walk_round_trips_through_the_stages_in<P: Profile>() {
        use rand::{Rng, SeedableRng, rngs::StdRng};
        use udon::{curve::Projective, field::Field};
        let mut rng = StdRng::seed_from_u64(7);
        let points: Vec<C> = (0..NumPoints::<P>::len())
            .map(|_| {
                (ragu_core::pasta::Ep::generator()
                    * ragu_core::pasta::Fq::random(|bytes| rng.fill_bytes(bytes)))
                .to_affine()
            })
            .collect();
        // The children's exported online Fq commitments are held beside
        // the walk's points and are not among them.
        let exported = alloc::vec![points[0]; BoundCommitmentsLen::<P>::len()];
        let inputs = Inputs::<C, P>::from_walk(
            &points,
            [&exported, &exported],
            FixedVec::from_fn(|_| points[0]),
        );
        assert_eq!(inputs.walk(), points);

        let num_inputs = NumInputs::<P>::len();
        let mut children = alloc::vec![false; num_children_points::<P>()];
        let mut sources = Vec::new();
        let mut bindings = 0;
        let mut online_fq = 0;
        for i in 0..num_inputs {
            let source = input_source::<P>(i);
            assert!(
                !sources.contains(&source),
                "input source {source:?} used twice"
            );
            sources.push(source);
            match source {
                InputSource::Bridge(..)
                | InputSource::Challenges(_)
                | InputSource::P(_)
                | InputSource::ChildA(_)
                | InputSource::ChildB(_)
                | InputSource::ChildRegistryXy(_)
                | InputSource::Extension(..) => bindings += 1,
                InputSource::Children(k) => {
                    assert!(!children[k], "child point {k} sourced twice");
                    children[k] = true;
                }
                InputSource::OnlineFq(j) => {
                    assert_eq!(j, online_fq, "online Fq commitments out of slot order");
                    assert_eq!(i, num_inputs - FqPointsLen::<P>::len() + j);
                    // Input `i` is point `1 + i`: the initial point is first.
                    assert_eq!(inputs.preamble.online_fq[j], points[1 + i]);
                    online_fq += 1;
                }
                _ => {}
            }
        }
        assert_eq!(bindings, 2 * num_child_bindings::<P>());
        assert!(children.iter().all(|&c| c));
        assert_eq!(online_fq, FqPointsLen::<P>::len());
    }

    #[test]
    fn walk_round_trips_through_the_stages() {
        walk_round_trips_through_the_stages_in::<Standard>();
        // With the step's own online Fq commitment at the walk's tail,
        // alone and beside an extension.
        walk_round_trips_through_the_stages_in::<Opening>();
        walk_round_trips_through_the_stages_in::<Proving>();
        // With the stages a nested walk of several segments adds to the
        // nested extension, which the preamble stage holds: no binding
        // names one.
        walk_round_trips_through_the_stages_in::<Segmented>();
    }

    /// A child's $P_n$ is the last of its points, where
    /// [`nested::pcs::child_commitments`] puts it.
    #[test]
    fn child_p_is_the_last_child_point() {
        let child_p = child_p::<Standard>();
        assert_eq!(
            input_source::<Standard>(child_p),
            InputSource::P(Side::Left)
        );
        assert_eq!(
            input_source::<Standard>(num_child_points::<Standard>() + child_p),
            InputSource::P(Side::Right)
        );
        assert!(child_challenges::<Standard>() < child_p);
    }
}
