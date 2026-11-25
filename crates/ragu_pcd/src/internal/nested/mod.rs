//! Nested field circuits for the scalar field.
//!
//! Contains these circuits:
//!
//! - **Endoscaling**: verifies that the commitment accumulation
//!   in `compute_p` was computed correctly via Horner's rule.
//! - **Loading**: enforces consistency between [`PointsStage`]
//!   inputs and the bridge stage commitments for the current step.
//! - **Collapse**: pins the nested [`unified`] instance to its stages and
//!   verifies both layers of the children's nested fold.
//! - **Compute v**: recomputes the nested batch evaluation $v_n$, the mirror
//!   of the native `compute_v`.
//!
//! The collapse and compute-v circuits share the [`unified`]
//! instance as their public input, each constraining the slots it owns.
//!
//! [`PointsStage`]: crate::internal::endoscalar::PointsStage

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::{MultiStage, StageExt},
};
use ragu_core::{Cycle, Result};
use ragu_primitives::{
    Uendo, extract_endoscalar, lift_endoscalar,
    vec::{ConstLen, FixedVec, Len},
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

pub mod circuits {
    pub mod collapse;
    pub mod common;
    pub mod compute_v;
    pub mod fold_inner;
    pub mod fold_outer;
    pub mod loading;
}

use crate::{
    internal::{endoscalar, revdot::Parameters},
    profile::{BondingSlot, CircuitSlot, Profile, ProfiledCycle, Shape},
};

/// The number of curve points the nested walk folds for a native batch of
/// `native_rx` rx polynomials: `f`'s commitment, then for each child its
/// native rx commitments, $a$, $b$, `registry_xy` and $p$, then the current
/// step's two `registry_wx`, its application trace and application stage,
/// `registry_wy`, $a$, $b$ and `registry_xy`, its two fold randomizers and
/// its batch randomizer, then the step's native online slots (see
/// [`online`](super::native::online)).
pub const fn num_endoscaling_points(native_rx: usize) -> usize {
    1 + 2 * (native_rx + 4) + 11 + super::native::online::NUM_ONLINE_FP_QUERIES
}

/// Number of curve points accumulated during `compute_p` for nested field
/// endoscaling verification: the native batch's commitments, per
/// [`num_endoscaling_points`]. See `_10_p` for the canonical accumulation
/// order.
///
/// The endoscaling circuits process these points across
/// [`NUM_ENDOSCALING_STEPS`] steps.
pub const NUM_ENDOSCALING_POINTS: usize =
    num_endoscaling_points(crate::internal::native::RxIndex::NUM);

/// Length type for the curve points the nested walk folds in profile `P`:
/// the profile's [`nested_points`](Shape::nested_points), which the standard
/// profile has as [`NUM_ENDOSCALING_POINTS`].
///
/// The endoscaling circuits process these points across [`NumSteps`] steps.
pub struct NumPoints<P: Profile>(PhantomData<P>);

impl<P: Profile> NumPoints<P> {
    /// The count, evaluated once per profile.
    pub const LEN: usize = Shape::of::<P>().nested_points;
}

impl<P: Profile> Len for NumPoints<P> {
    fn len() -> usize {
        Self::LEN
    }
}

/// The endoscalings a nested step performs in the standard profile: what
/// fits a step beside the stages it reserves, which hold every point the
/// walk consumes, at the wallet rank. A profile sets its own
/// ([`Profile::NESTED_ENDOSCALINGS_PER_STEP`]).
pub const ENDOSCALINGS_PER_STEP: usize = 4;

/// Length type for the endoscalings a nested step performs in profile `P`.
pub struct Endoscalings<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for Endoscalings<P> {
    fn len() -> usize {
        P::NESTED_ENDOSCALINGS_PER_STEP
    }
}

/// Number of endoscaling steps, derived from [`NUM_ENDOSCALING_POINTS`] via
/// [`endoscalar::num_steps`].
pub(crate) const NUM_ENDOSCALING_STEPS: usize =
    endoscalar::num_steps(ENDOSCALINGS_PER_STEP, NUM_ENDOSCALING_POINTS);

/// Length type for the nested endoscaling steps in profile `P`, derived from
/// [`NumPoints`] via [`endoscalar::num_steps`]. The standard profile's is
/// [`NUM_ENDOSCALING_STEPS`].
pub type NumSteps<P> = endoscalar::NumStepsLen<NumPoints<P>, Endoscalings<P>>;

/// Length type for the circuits of the profile's nested extension.
pub struct NumExtensionCircuits<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumExtensionCircuits<P> {
    fn len() -> usize {
        crate::profile::extension_lengths::<P>(true).circuits
    }
}

/// Length type for the stages of the profile's nested extension.
pub struct NumExtensionStages<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumExtensionStages<P> {
    fn len() -> usize {
        crate::profile::extension_lengths::<P>(true).stages
    }
}

/// Length type for the stages the profile and the online batch declare in
/// the nested extension: the extension's stages but the ones a nested walk
/// of several segments adds after them (see [`num_walk_stages`]), which no
/// binding names.
pub struct NumDeclaredStages<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumDeclaredStages<P> {
    fn len() -> usize {
        walk_stage_offset::<P>()
    }
}

/// Length type for the nested rx polynomials, [`RxIndex::num`].
pub struct NumRx<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumRx<P> {
    fn len() -> usize {
        RxIndex::num::<P>()
    }
}

/// Length type for the nested internal circuits, [`InternalCircuitIndex::num`].
pub struct NumInternal<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumInternal<P> {
    fn len() -> usize {
        InternalCircuitIndex::num::<P>()
    }
}

/// How the nested walk of profile `P` is cut into segments: one, the whole
/// walk, unless the profile sets
/// [`NESTED_STEPS_PER_SEGMENT`](Profile::NESTED_STEPS_PER_SEGMENT) below
/// the walk's steps.
pub struct Walk<P: Profile>(PhantomData<P>);

impl<P: Profile> Walk<P> {
    /// The segments, evaluated once per profile.
    pub const SEGMENTS: endoscalar::Segments = endoscalar::Segments::new(
        NumPoints::<P>::LEN,
        P::NESTED_ENDOSCALINGS_PER_STEP,
        P::NESTED_STEPS_PER_SEGMENT,
    );
}

/// The segments of profile `P`'s nested walk (see [`Walk`]).
pub const fn segments<P: Profile>() -> endoscalar::Segments {
    Walk::<P>::SEGMENTS
}

/// The stage polynomials a nested walk of `segments` segments adds to a
/// proof beyond the points stage's first: one more of the points stage per
/// further segment, then the boundaries stage's
/// ([`stages::boundaries`]). None for a walk of one segment.
///
/// A proof carries them as the last stages of its nested extension (see
/// `profile::nested_extension`), so the native walk folds their commitments
/// with the extension's.
pub const fn num_walk_stages(segments: usize) -> usize {
    if segments > 1 { segments } else { 0 }
}

/// The rx polynomial of segment `segment` of profile `P`'s nested walk: the
/// points stage's own for the first segment, and for each further one a
/// stage of the nested extension, after the stages the profile and the
/// online batch declare.
///
/// # Panics
///
/// Panics if the walk has no such segment.
pub fn segment_rx<P: Profile>(segment: usize) -> RxIndex {
    assert!(segment < segments::<P>().count(), "no such segment");
    match segment {
        0 => RxIndex::PointsStage,
        segment => RxIndex::ExtensionStage((walk_stage_offset::<P>() + segment - 1) as u32),
    }
}

/// The rx polynomial of the boundaries stage of profile `P`'s nested walk,
/// for a walk of several segments.
///
/// # Panics
///
/// Panics if the walk is one segment, which has no boundary.
pub fn boundaries_rx<P: Profile>() -> RxIndex {
    let walk = segments::<P>();
    assert!(walk.is_split(), "a walk of one segment has no boundary");
    RxIndex::ExtensionStage((walk_stage_offset::<P>() + walk.count() - 1) as u32)
}

/// The polynomials a nested fold cut into `chunks` first-layer chunk
/// circuits adds to a proof: the chunk circuits', the second layer's
/// circuit's and the targets stage's. None for a fold `collapse` verifies
/// whole.
pub const fn num_fold_polynomials(chunks: usize) -> usize {
    if chunks > 0 { chunks + 2 } else { 0 }
}

/// The circuits that verify the first layer of profile `P`'s nested fold:
/// none when `collapse` verifies the fold whole (see
/// [`Chunking`](crate::profile::Chunking)).
pub fn fold_chunks<P: Profile>() -> usize {
    P::CHUNKING.nested_fold
}

/// Whether profile `P` cuts the nested fold's verification into chunks.
pub fn is_fold_chunked<P: Profile>() -> bool {
    fold_chunks::<P>() > 0
}

/// The groups of profile `P`'s nested fold that first-layer chunk `chunk`
/// verifies: the chunks share the groups evenly, in order.
///
/// # Panics
///
/// Panics if the fold has no such chunk.
pub fn fold_groups<P: Profile>(chunk: usize) -> core::ops::Range<usize> {
    let chunks = fold_chunks::<P>();
    assert!(chunk < chunks, "no such fold chunk");
    let groups = NumFoldGroups::<P>::len();
    chunk * groups / chunks..(chunk + 1) * groups / chunks
}

/// A stage of the fuse that a proof carries among its nested extension's
/// stages, after the ones the profile and the online batch declare, in the
/// order of [`builtin_stage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinStage {
    /// The points stage of a further segment of a walk of several
    /// segments, by segment: the first segment's is the points stage's own
    /// polynomial.
    WalkSegment(usize),
    /// The boundaries stage of a walk of several segments.
    WalkBoundaries,
    /// The targets stage of a fold verified in chunks.
    FoldTargets,
}

/// The stages the fuse adds to profile `P`'s nested extension: those of a
/// walk of several segments, then the targets stage of a fold verified in
/// chunks.
pub fn num_builtin_stages<P: Profile>() -> usize {
    num_walk_stages(segments::<P>().count()) + is_fold_chunked::<P>() as usize
}

/// The fuse's stage at index `stage` of profile `P`'s nested extension's
/// stages, or `None` for a stage the profile or the online batch declares.
///
/// # Panics
///
/// Panics if the extension has no such stage.
pub fn builtin_stage<P: Profile>(stage: usize) -> Option<BuiltinStage> {
    let index = stage.checked_sub(walk_stage_offset::<P>())?;
    let walk = num_walk_stages(segments::<P>().count());
    if index < walk {
        return Some(if index + 1 == walk {
            BuiltinStage::WalkBoundaries
        } else {
            BuiltinStage::WalkSegment(index + 1)
        });
    }
    assert!(
        index - walk < is_fold_chunked::<P>() as usize,
        "no such extension stage"
    );
    Some(BuiltinStage::FoldTargets)
}

/// The rx polynomial of the targets stage of profile `P`'s nested fold,
/// for a fold verified in chunks.
///
/// # Panics
///
/// Panics if `collapse` verifies the fold whole.
pub fn fold_targets_rx<P: Profile>() -> RxIndex {
    assert!(
        is_fold_chunked::<P>(),
        "a fold verified whole has no targets stage"
    );
    RxIndex::ExtensionStage(
        (walk_stage_offset::<P>() + num_walk_stages(segments::<P>().count())) as u32,
    )
}

/// A circuit of the fuse that a proof carries among its nested extension's
/// circuits, after the ones the profile and the online batch declare, in
/// the order of [`builtin_circuit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinCircuit {
    /// A first-layer chunk of a fold verified in chunks.
    FoldInner(usize),
    /// The second layer's circuit of a fold verified in chunks.
    FoldOuter,
}

/// The circuits the fuse adds to profile `P`'s nested extension: the
/// chunks of a fold verified in chunks and its second layer's circuit.
pub fn num_builtin_circuits<P: Profile>() -> usize {
    match fold_chunks::<P>() {
        0 => 0,
        chunks => chunks + 1,
    }
}

/// The index, among the nested extension's circuits, of the first circuit
/// the fuse adds: the circuits the profile and the online batch declare
/// come before.
pub(crate) fn builtin_circuit_offset<P: Profile>() -> usize {
    crate::profile::online::stages::layout::<P, crate::profile::online::stages::Nested>()
        .circuits
        .len()
}

/// The fuse's circuit at index `circuit` of profile `P`'s nested
/// extension's circuits, or `None` for a circuit the profile or the online
/// batch declares.
///
/// # Panics
///
/// Panics if the extension has no such circuit.
pub fn builtin_circuit<P: Profile>(circuit: usize) -> Option<BuiltinCircuit> {
    let index = circuit.checked_sub(builtin_circuit_offset::<P>())?;
    let chunks = fold_chunks::<P>();
    assert!(
        index < num_builtin_circuits::<P>(),
        "no such extension circuit"
    );
    Some(if index < chunks {
        BuiltinCircuit::FoldInner(index)
    } else {
        BuiltinCircuit::FoldOuter
    })
}

/// First-layer chunk `chunk` of profile `P`'s nested fold, among the
/// nested extension's circuits: the index of its circuit and of its rx
/// polynomial.
///
/// # Panics
///
/// Panics if the fold has no such chunk.
pub fn fold_inner<P: Profile>(chunk: usize) -> u32 {
    assert!(chunk < fold_chunks::<P>(), "no such fold chunk");
    (builtin_circuit_offset::<P>() + chunk) as u32
}

/// The second layer's circuit of profile `P`'s nested fold, for a fold
/// verified in chunks, among the nested extension's circuits: the index of
/// its circuit and of its rx polynomial.
///
/// # Panics
///
/// Panics if `collapse` verifies the fold whole.
pub fn fold_outer<P: Profile>() -> u32 {
    assert!(
        is_fold_chunked::<P>(),
        "a fold verified whole has no second-layer circuit"
    );
    (builtin_circuit_offset::<P>() + fold_chunks::<P>()) as u32
}

/// The index, among the nested extension's stages, of the first stage the
/// nested walk adds: the stages the profile and the online batch declare
/// come before.
pub(crate) fn walk_stage_offset<P: Profile>() -> usize {
    crate::profile::online::stages::layout::<P, crate::profile::online::stages::Nested>().stages
}

/// Length type for the points the nested points stage holds in profile
/// `P`: every point of a walk of one segment, and otherwise one segment's,
/// its initial point and the inputs of its steps.
pub struct SegmentPoints<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for SegmentPoints<P> {
    fn len() -> usize {
        segments::<P>().stage_points()
    }
}

/// Length type for the points the boundaries stage holds in profile `P`:
/// one per segment of the nested walk but the last.
pub struct NumBoundaries<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumBoundaries<P> {
    fn len() -> usize {
        segments::<P>().count() - 1
    }
}

/// The nested points stage, over the native batch's commitments, for host
/// curve `C` in profile `P`: the whole walk's points, or one segment's (see
/// [`Walk`]).
pub type PointsStage<C, P> =
    endoscalar::PointsStage<C, SegmentPoints<P>, Endoscalings<P>, stages::bridge_hash::Stage<C>>;

/// The nested points stage's witness: one segment's points.
pub type PointsWitness<C, P> = endoscalar::PointsWitness<C, SegmentPoints<P>, Endoscalings<P>>;

/// The nested points stage's output gadget.
pub type Points<'dr, D, C, P> = endoscalar::Points<'dr, D, C, SegmentPoints<P>, Endoscalings<P>>;

/// A nested endoscaling step.
pub type EndoscalingStep<C, R, P> = endoscalar::EndoscalingStep<
    C,
    R,
    SegmentPoints<P>,
    Endoscalings<P>,
    stages::bridge_hash::Stage<C>,
>;

/// A nested endoscaling step's witness.
pub type EndoscalingStepWitness<'source, C, P> =
    endoscalar::EndoscalingStepWitness<'source, C, SegmentPoints<P>, Endoscalings<P>>;

/// The circuit of step `step` of profile `P`'s nested walk: a step over the
/// whole walk's points, or, for a walk of several segments, the step of
/// its segment, over that segment's points (see
/// [`EndoscalingStep::in_segment`](endoscalar::EndoscalingStep::in_segment)).
///
/// # Panics
///
/// Panics if `step` is not a step of the walk.
pub fn endoscaling_step<C: Affine, R: Rank, P: Profile>(step: usize) -> EndoscalingStep<C, R, P> {
    let walk = segments::<P>();
    assert!(step < walk.steps(), "step {step} is past the walk");
    if !walk.is_split() {
        return EndoscalingStep::<C, R, P>::new(step);
    }
    let (segment, local) = walk.locate(step);
    EndoscalingStep::<C, R, P>::in_segment(local, walk.inputs_of(segment).len())
}

/// The witnesses of profile `P`'s nested walk: the points stage's witness
/// for each segment, and the boundaries stage's.
pub struct WalkWitness<C: Affine, P: Profile> {
    /// Each segment's points, in walk order: one for a walk of one segment.
    pub segments: Vec<PointsWitness<C, P>>,
    /// The last interstitial of every segment but the last, which the next
    /// segment starts from.
    pub boundaries: FixedVec<C, NumBoundaries<P>>,
}

impl<C: Affine, P: Profile> WalkWitness<C, P> {
    /// Walks `points`, the initial point first, under `endoscalar`.
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
            return WalkWitness {
                segments: alloc::vec![PointsWitness::<C, P>::new(endoscalar, points)],
                boundaries: FixedVec::from_fn(|_| unreachable!("one segment has no boundary")),
            };
        }
        let inputs = &points[1..];
        let mut initial = points[0];
        let mut segments = Vec::with_capacity(walk.count());
        for segment in 0..walk.count() {
            let witness = PointsWitness::<C, P>::segment(
                endoscalar,
                initial,
                &inputs[walk.inputs_of(segment)],
            );
            initial = witness.interstitials[walk.steps_of(segment) - 1];
            segments.push(witness);
        }
        let boundaries = FixedVec::from_fn(|segment| {
            segments[segment].interstitials[walk.steps_per_segment() - 1]
        });
        WalkWitness {
            segments,
            boundaries,
        }
    }

    /// The witness of the segment the walk ends in, whose polynomial the
    /// instance circuits load.
    pub fn last(&self) -> &PointsWitness<C, P> {
        self.segments
            .last()
            .expect("a walk has at least one segment")
    }

    /// The witness of the segment walk step `step` belongs to.
    pub fn of_step(&self, step: usize) -> &PointsWitness<C, P> {
        &self.segments[segments::<P>().locate(step).0]
    }

    /// The walk's result: the interstitial of its last step.
    pub fn result(&self) -> C {
        self.last().interstitials[segments::<P>().last_local_step()]
    }
}

/// The number of circuits whose public input is the nested [`unified`]
/// instance: collapse and compute-v.
pub const NUM_INSTANCE_CIRCUITS: usize = 2;

/// The nested rx polynomials that are not endoscaling steps: the instance
/// circuits', the endoscalar and points stages', the nine bridge stages'
/// and the challenge stage's.
pub const NUM_FIXED_RX: usize = NUM_INSTANCE_CIRCUITS + 12;

/// The nested internal circuits that are not endoscaling steps: the rx
/// polynomials' circuits and stages, the two final stage masks and the
/// loading circuit.
pub const NUM_FIXED_INTERNAL: usize = NUM_FIXED_RX + 3;

/// The minimum groups for the nested quotient fold: eleven groups with
/// eight claims each provide room for 88 claims, and the twelfth holds the
/// randomizer's half-claim (see
/// [`revdot`](crate::internal::revdot#the-randomizer)). Larger
/// profiles grow the group count.
pub const NUM_FOLD_GROUPS: usize = 12;

/// The nodes of a nested fold group: eight claims and the randomizer's.
pub const FOLD_GROUP_SIZE: usize = 9;

/// The nested revdot claims of profile `P` the fuse folds: two children's
/// raw claims, each internal circuit's claim per child, and each bonding's
/// claim across both, the loading circuit of every further segment of the
/// walk among them.
pub fn num_claims<P: Profile>() -> usize {
    let extension = crate::profile::extension_lengths::<P>(true);
    let circuits = 2 + NumSteps::<P>::len() + extension.circuits;
    let bondings = 15 + extension.bondings + segments::<P>().count() - 1;
    2 + 2 * circuits + bondings
}

/// Length type for the nested fold's groups in profile `P`: the standard
/// profile's [`NUM_FOLD_GROUPS`], or as many groups of
/// [`FOLD_GROUP_SIZE`] as the profile's [`num_claims`] need beside the
/// randomizer's (see
/// [`revdot::num_groups`](crate::internal::revdot::num_groups)),
/// whichever is more.
pub struct NumFoldGroups<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumFoldGroups<P> {
    fn len() -> usize {
        NUM_FOLD_GROUPS.max(crate::internal::revdot::num_groups(
            num_claims::<P>(),
            FOLD_GROUP_SIZE,
        ))
    }
}

/// Parameters for folding the children's nested revdot claims in profile
/// `P`: [`NumFoldGroups`] groups of
/// [`FOLD_GROUP_SIZE`] nodes.
pub struct RevdotParameters<P: Profile>(PhantomData<P>);

impl<P: Profile> Clone for RevdotParameters<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: Profile> Copy for RevdotParameters<P> {}

impl<P: Profile> Default for RevdotParameters<P> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<P: Profile> Parameters for RevdotParameters<P> {
    type NumGroups = NumFoldGroups<P>;
    type GroupSize = ConstLen<FOLD_GROUP_SIZE>;
}

/// Derives the nested-field counterpart of a native Fiat-Shamir challenge.
///
/// The nested side squeezes nothing itself: every challenge it consumes is the
/// endoscalar lift, in the scalar field, of the low `ENDOSCALAR_BITS` bits of the
/// corresponding native challenge, the derivation `compute_p` already applies
/// to `pre_beta`.
///
/// This helper performs only the scalar conversion. The native points
/// stages bind the nested commitments into the native transcript before
/// each challenge (see [`native::stages::points`]), and the consuming
/// circuits read the lifted values from the challenge stage, which a parent
/// binds to the transcript (see [`stages::challenges`]).
///
/// # Errors
///
/// Fails when the native challenge lies at or above $2^{\mathtt{CAPACITY}}$,
/// a $2^{-129}$ event for a transcript output.
///
/// [`native::stages::points`]: crate::internal::native::stages::points
pub fn challenge<C: Cycle>(native: C::CircuitField) -> Result<C::ScalarField> {
    Ok(lift_endoscalar(extract_endoscalar(native)?))
}

/// The native challenges the nested side consumes, in the order the
/// challenge stage holds their lifts (see [`stages::challenges`]), with
/// `pre_beta` last.
#[derive(Clone, Copy)]
pub struct Challenges<F> {
    pub w: F,
    pub y: F,
    pub z: F,
    pub mu: F,
    pub mu_prime: F,
    pub x: F,
    pub alpha: F,
    pub u: F,
    pub pre_beta: F,
}

impl<F: Copy> Challenges<F> {
    /// The challenges in stage order, `pre_beta` last.
    pub fn in_order(&self) -> [F; stages::challenges::NUM + 1] {
        [
            self.w,
            self.y,
            self.z,
            self.mu,
            self.mu_prime,
            self.x,
            self.alpha,
            self.u,
            self.pre_beta,
        ]
    }
}

impl<F: Copy> Challenges<F> {
    /// The lifts of these challenges, in stage order, `pre_beta`'s last.
    pub fn lifts<C: Cycle<CircuitField = F>>(
        &self,
    ) -> Result<[C::ScalarField; stages::challenges::NUM + 1]> {
        let native = self.in_order();
        let mut out = [C::ScalarField::ZERO; stages::challenges::NUM + 1];
        for (out, native) in out.iter_mut().zip(native) {
            *out = challenge::<C>(native)?;
        }
        Ok(out)
    }
}

/// Index of internal nested circuits registered into the registry.
///
/// These correspond to the wiring objects registered in [`register_all`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCircuitIndex {
    /// `EndoscalingStep` circuit at given step.
    EndoscalingStep(u32),
    /// Circuit binding the nested instance and verifying the children's nested fold.
    Collapse,
    /// Circuit computing the nested batch evaluation $v_n$.
    ComputeV,
    /// A circuit of the profile's nested extension (see
    /// [`Extension`](crate::profile::Extension)).
    ExtensionCircuit(u32),
    /// `EndoscalarStage` stage mask.
    EndoscalarStage,
    /// `PointsStage` stage mask.
    PointsStage,
    /// `PointsStage` final staged mask.
    PointsFinalStaged,
    /// Bridge `preamble` stage mask.
    BridgePreamble,
    /// Bridge-hash stage mask.
    BridgeHash,
    /// Bridge `s_prime` stage mask.
    BridgeSPrime,
    /// Bridge `inner_error` stage mask.
    BridgeInnerError,
    /// Bridge `outer_error` stage mask.
    BridgeOuterError,
    /// Bridge `ab` stage mask.
    BridgeAB,
    /// Bridge `query` stage mask.
    BridgeQuery,
    /// Bridge `f` stage mask.
    BridgeF,
    /// Bridge `eval` stage mask.
    BridgeEval,
    /// Challenge stage mask.
    ChallengeStage,
    /// Final staged mask of the circuits whose last stage is the challenge
    /// stage.
    ChallengeFinalStaged,
    /// Loading circuit over all nested stages: of the walk's first segment,
    /// or of the whole walk when it is one segment.
    Loading,
    /// A bonding of the profile's nested extension, a stage's mask or a
    /// final mask, in [`Extension::bondings`](crate::profile::Extension::bondings)
    /// order. For a nested walk of several segments, the masks of the
    /// stages that hold its further segments and its boundaries follow the
    /// masks of the stages the profile and the online batch declare.
    ExtensionBonding(u32),
    /// The loading circuit of a further segment of a nested walk of several
    /// segments, by segment, from one (see [`Walk`]).
    LoadingSegment(u32),
}

impl InternalCircuitIndex {
    /// The number of internal circuits registered by [`register_all`],
    /// equal to the number of entries in [`InternalCircuitIndex::ALL`].
    pub const NUM: usize = NUM_ENDOSCALING_STEPS + NUM_FIXED_INTERNAL;

    /// The circuits whose public input is the nested [`unified`] instance,
    /// in claim order.
    pub const INSTANCE: [Self; NUM_INSTANCE_CIRCUITS] = [Self::Collapse, Self::ComputeV];

    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before masks), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this array. This is the standard
    /// profile's list; [`all`](Self::all) resizes its walk and adds the
    /// extension for any other.
    pub const ALL: [Self; Self::NUM] = super::const_fns::unwrap_all(Self::all_slots());

    const fn all_slots() -> [Option<Self>; Self::NUM] {
        use super::const_fns::push;

        let mut slots = [None; Self::NUM];
        let mut c = 0;
        {
            let mut step = 0;
            while step < NUM_ENDOSCALING_STEPS {
                push(&mut slots, &mut c, Self::EndoscalingStep(step as u32));
                step += 1;
            }
        }
        push(&mut slots, &mut c, Self::Collapse);
        push(&mut slots, &mut c, Self::ComputeV);
        push(&mut slots, &mut c, Self::EndoscalarStage);
        push(&mut slots, &mut c, Self::PointsStage);
        push(&mut slots, &mut c, Self::PointsFinalStaged);
        push(&mut slots, &mut c, Self::BridgePreamble);
        push(&mut slots, &mut c, Self::BridgeHash);
        push(&mut slots, &mut c, Self::BridgeSPrime);
        push(&mut slots, &mut c, Self::BridgeInnerError);
        push(&mut slots, &mut c, Self::BridgeOuterError);
        push(&mut slots, &mut c, Self::BridgeAB);
        push(&mut slots, &mut c, Self::BridgeQuery);
        push(&mut slots, &mut c, Self::BridgeF);
        push(&mut slots, &mut c, Self::BridgeEval);
        push(&mut slots, &mut c, Self::ChallengeStage);
        push(&mut slots, &mut c, Self::ChallengeFinalStaged);
        push(&mut slots, &mut c, Self::Loading);
        assert!(c == Self::NUM);
        slots
    }

    /// The number of internal circuits registered by [`register_all`] in
    /// profile `P`, equal to the length of [`all`](Self::all).
    pub fn num<P: Profile>() -> usize {
        NumSteps::<P>::len()
            + NUM_FIXED_INTERNAL
            + crate::profile::nested_extension::<P>().internal()
            + segments::<P>().count()
            - 1
    }

    /// All variants in canonical iteration order, for profile `P`:
    /// [`ALL`](Self::ALL) with the walk resized to the profile's steps, the
    /// profile's extension circuits after the instance circuits, its
    /// bondings after the fuse's, and the loading circuits of the walk's
    /// further segments last.
    /// The index tests compare this order with [`Self::circuit_index`].
    pub fn all<P: Profile>() -> Vec<Self> {
        let num_steps = NumSteps::<P>::len();
        let extension = crate::profile::nested_extension::<P>();
        let mut all = Vec::with_capacity(Self::num::<P>());
        for &id in &Self::ALL {
            match id {
                Self::EndoscalingStep(0) => {
                    all.extend((0..num_steps as u32).map(Self::EndoscalingStep))
                }
                Self::EndoscalingStep(_) => {}
                Self::ComputeV => {
                    all.push(id);
                    all.extend((0..extension.circuits.len() as u32).map(Self::ExtensionCircuit));
                }
                id => all.push(id),
            }
        }
        all.extend((0..extension.bondings() as u32).map(Self::ExtensionBonding));
        all.extend((1..segments::<P>().count() as u32).map(Self::LoadingSegment));
        assert_eq!(all.len(), Self::num::<P>());
        all
    }

    /// Convert to a [`CircuitIndex`] for registry lookup, in profile `P`.
    ///
    /// Circuit indices follow the `RegistryBuilder::finalize()` concatenation
    /// order: internal circuits first, then internal masks.
    pub fn circuit_index<P: Profile>(self) -> CircuitIndex {
        use InternalCircuitIndex::*;
        let steps = NumSteps::<P>::len();
        let extension = crate::profile::extension_lengths::<P>(true);
        let bonding = steps + 2 + extension.circuits;
        let pos = match self {
            EndoscalingStep(i) => super::checked_index(i, steps),
            Collapse => steps,
            ComputeV => steps + 1,
            ExtensionCircuit(i) => steps + 2 + super::checked_index(i, extension.circuits),
            EndoscalarStage => bonding,
            PointsStage => bonding + 1,
            PointsFinalStaged => bonding + 2,
            BridgePreamble => bonding + 3,
            BridgeHash => bonding + 4,
            BridgeSPrime => bonding + 5,
            BridgeInnerError => bonding + 6,
            BridgeOuterError => bonding + 7,
            BridgeAB => bonding + 8,
            BridgeQuery => bonding + 9,
            BridgeF => bonding + 10,
            BridgeEval => bonding + 11,
            ChallengeStage => bonding + 12,
            ChallengeFinalStaged => bonding + 13,
            Loading => bonding + 14,
            ExtensionBonding(i) => bonding + 15 + super::checked_index(i, extension.bondings),
            // Segment zero's loading circuit is `Loading`.
            LoadingSegment(i) => {
                assert!(i > 0, "the first segment's loading circuit is `Loading`");
                bonding
                    + 15
                    + extension.bondings
                    + super::checked_index(i - 1, segments::<P>().count() - 1)
            }
        };
        CircuitIndex::new(pos)
    }

    /// Whether `self` is registered as a bonding, a stage's mask, a final
    /// mask or the loading circuit's, rather than as a circuit.
    #[cfg(test)]
    pub fn is_bonding(self) -> bool {
        use InternalCircuitIndex::*;
        match self {
            EndoscalingStep(_) | Collapse | ComputeV | ExtensionCircuit(_) => false,
            EndoscalarStage | PointsStage | PointsFinalStaged | BridgePreamble | BridgeHash
            | BridgeSPrime | BridgeInnerError | BridgeOuterError | BridgeAB | BridgeQuery
            | BridgeF | BridgeEval | ChallengeStage | ChallengeFinalStaged | Loading
            | ExtensionBonding(_) | LoadingSegment(_) => true,
        }
    }
}

/// Enum identifying which nested field rx polynomial to retrieve from a proof.
///
/// Analogous to [`native::RxIndex`](super::native::RxIndex) for the scalar
/// field. Each variant maps to a polynomial in the proof's nested-field
/// polynomial storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxIndex {
    /// EndoscalingStep circuit rx polynomial (indexed by step number).
    EndoscalingStep(u32),
    /// Collapse circuit rx polynomial.
    Collapse,
    /// Compute-v circuit rx polynomial.
    ComputeV,
    /// The rx polynomial of a circuit of the profile's nested extension.
    ExtensionCircuit(u32),
    /// EndoscalarStage rx polynomial.
    EndoscalarStage,
    /// PointsStage rx polynomial.
    PointsStage,
    /// Bridge `preamble` rx polynomial.
    BridgePreamble,
    /// Bridge-hash stage rx polynomial: the step's own `O1`, with a zero alpha.
    BridgeHash,
    /// Bridge `s_prime` rx polynomial.
    BridgeSPrime,
    /// Bridge `inner_error` rx polynomial.
    BridgeInnerError,
    /// Bridge `outer_error` rx polynomial.
    BridgeOuterError,
    /// Bridge `ab` rx polynomial.
    BridgeAB,
    /// Bridge `query` rx polynomial.
    BridgeQuery,
    /// Bridge `f` rx polynomial.
    BridgeF,
    /// Bridge `eval` rx polynomial.
    BridgeEval,
    /// Challenge stage rx polynomial.
    ChallengeStage,
    /// The rx polynomial of a stage of the profile's nested extension.
    ExtensionStage(u32),
}

impl RxIndex {
    /// The number of rx components in the nested field,
    /// equal to the number of entries in [`RxIndex::ALL`].
    pub const NUM: usize = NUM_ENDOSCALING_STEPS + NUM_FIXED_RX;

    /// The rx polynomials of the instance circuits, in
    /// [`InternalCircuitIndex::INSTANCE`] order.
    pub const INSTANCE: [Self; NUM_INSTANCE_CIRCUITS] = [Self::Collapse, Self::ComputeV];

    /// The bridge stages, in the unified instance's order: the stages whose
    /// commitments the unified instance carries, which the parent binds to
    /// the stages it folds. All but the bridge-hash stage are absorbed into
    /// the transcript, in this order.
    pub const BRIDGES: [Self; 9] = [
        Self::BridgePreamble,
        Self::BridgeHash,
        Self::BridgeSPrime,
        Self::BridgeInnerError,
        Self::BridgeOuterError,
        Self::BridgeAB,
        Self::BridgeQuery,
        Self::BridgeF,
        Self::BridgeEval,
    ];

    /// All variants in canonical order (circuits, then stages).
    ///
    /// Must maintain the same ordering convention as
    /// [`native::RxIndex::ALL`](super::native::RxIndex::ALL). This is the
    /// standard profile's list; [`all`](Self::all) resizes its walk and adds
    /// the extension for any other.
    pub const ALL: [Self; Self::NUM] = super::const_fns::unwrap_all(Self::all_slots());

    const fn all_slots() -> [Option<Self>; Self::NUM] {
        use super::const_fns::push;

        let mut slots = [None; Self::NUM];
        let mut c = 0;
        {
            let mut step = 0;
            while step < NUM_ENDOSCALING_STEPS {
                push(&mut slots, &mut c, Self::EndoscalingStep(step as u32));
                step += 1;
            }
        }
        push(&mut slots, &mut c, Self::Collapse);
        push(&mut slots, &mut c, Self::ComputeV);
        push(&mut slots, &mut c, Self::EndoscalarStage);
        push(&mut slots, &mut c, Self::PointsStage);
        push(&mut slots, &mut c, Self::BridgePreamble);
        push(&mut slots, &mut c, Self::BridgeHash);
        push(&mut slots, &mut c, Self::BridgeSPrime);
        push(&mut slots, &mut c, Self::BridgeInnerError);
        push(&mut slots, &mut c, Self::BridgeOuterError);
        push(&mut slots, &mut c, Self::BridgeAB);
        push(&mut slots, &mut c, Self::BridgeQuery);
        push(&mut slots, &mut c, Self::BridgeF);
        push(&mut slots, &mut c, Self::BridgeEval);
        push(&mut slots, &mut c, Self::ChallengeStage);
        assert!(c == Self::NUM);
        slots
    }

    /// The number of rx components in the nested field in profile `P`,
    /// equal to the length of [`all`](Self::all).
    pub fn num<P: Profile>() -> usize {
        Shape::of::<P>().nested_rx
    }

    /// All variants in canonical order (circuits, then stages), for profile
    /// `P`: [`ALL`](Self::ALL) with the walk resized to the profile's steps,
    /// then the profile's extension circuits' and stages' polynomials.
    /// The index tests compare this order with [`Self::position`].
    pub fn all<P: Profile>() -> Vec<Self> {
        let num_steps = NumSteps::<P>::len();
        let extension = crate::profile::nested_extension::<P>();
        let mut all = Vec::with_capacity(Self::num::<P>());
        for &id in &Self::ALL {
            match id {
                Self::EndoscalingStep(0) => {
                    all.extend((0..num_steps as u32).map(Self::EndoscalingStep))
                }
                Self::EndoscalingStep(_) => {}
                id => all.push(id),
            }
        }
        all.extend((0..extension.circuits.len() as u32).map(Self::ExtensionCircuit));
        all.extend((0..extension.stages as u32).map(Self::ExtensionStage));
        assert_eq!(all.len(), Self::num::<P>());
        all
    }

    /// The position of `self` in [`all`](Self::all), for profile `P`.
    pub fn position<P: Profile>(self) -> usize {
        use RxIndex::*;
        let steps = NumSteps::<P>::len();
        match self {
            EndoscalingStep(i) => super::checked_index(i, steps),
            Collapse => steps,
            ComputeV => steps + 1,
            EndoscalarStage => steps + 2,
            PointsStage => steps + 3,
            BridgePreamble => steps + 4,
            BridgeHash => steps + 5,
            BridgeSPrime => steps + 6,
            BridgeInnerError => steps + 7,
            BridgeOuterError => steps + 8,
            BridgeAB => steps + 9,
            BridgeQuery => steps + 10,
            BridgeF => steps + 11,
            BridgeEval => steps + 12,
            ChallengeStage => steps + 13,
            ExtensionCircuit(i) => {
                steps
                    + 14
                    + super::checked_index(i, crate::profile::extension_lengths::<P>(true).circuits)
            }
            ExtensionStage(i) => {
                steps
                    + 14
                    + crate::profile::extension_lengths::<P>(true).circuits
                    + super::checked_index(i, crate::profile::extension_lengths::<P>(true).stages)
            }
        }
    }
}

/// Identifies a nested-field polynomial within a proof: either one of the
/// two accumulator polynomials (which are not rx polynomials) or one of the
/// rx polynomials addressed by [`RxIndex`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxComponent {
    /// The `a` polynomial of the nested accumulator (raw revdot claim).
    AbA,
    /// The `b` polynomial of the nested accumulator (raw revdot claim).
    AbB,
    /// An rx polynomial component indexed by [`RxIndex`].
    Rx(RxIndex),
}

pub mod claims;
pub mod online;
pub mod pcs;
pub mod unified;

pub mod stages {
    pub mod ab;
    pub mod boundaries;
    pub mod bridge_hash;
    pub mod challenges;
    pub mod eval;
    pub mod f;
    pub mod inner_error;
    pub mod outer_error;
    pub mod preamble;
    pub mod query;
    pub mod s_prime;
    pub mod targets;
}

/// Registers internal nested circuits into the provided registry.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: ProfiledCycle, R: Rank>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
    params: &'params C::Params,
    source_tag: Option<C::ScalarField>,
    source_domain: Option<u32>,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    C::Profile::check()?;
    let initial_internal_circuits = registry.num_internal_circuits();

    let extension = crate::profile::nested_extension::<C::Profile>();
    let mut extension_circuits = alloc::vec::Vec::with_capacity(extension.circuits.len());
    let mut extension_bondings = alloc::vec::Vec::with_capacity(extension.bondings());
    // Circuits first, then masks — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    for id in InternalCircuitIndex::all::<C::Profile>() {
        use InternalCircuitIndex::*;
        registry = match id {
            EndoscalingStep(step) => {
                let step_circuit = endoscaling_step::<C::HostCurve, R, C::Profile>(step as usize);
                let staged = MultiStage::new(step_circuit);
                registry.register_internal_circuit(staged)?
            }
            Collapse if is_fold_chunked::<C::Profile>() => {
                let circuit = circuits::collapse::Targets::<C::HostCurve, R, C::Profile>::new();
                registry.register_internal_circuit(MultiStage::new(circuit))?
            }
            Collapse => {
                let circuit = circuits::collapse::Circuit::<C::HostCurve, R, C::Profile>::new();
                registry.register_internal_circuit(MultiStage::new(circuit))?
            }
            ComputeV => {
                let circuit = circuits::compute_v::Circuit::<C::HostCurve, R, C::Profile>::new();
                registry.register_internal_circuit(MultiStage::new(circuit))?
            }
            EndoscalarStage => registry.register_bonding(endoscalar::EndoscalarStage::mask()?),
            PointsStage => {
                registry.register_bonding(self::PointsStage::<C::HostCurve, C::Profile>::mask()?)
            }
            PointsFinalStaged => registry
                .register_bonding(self::PointsStage::<C::HostCurve, C::Profile>::final_mask()?),
            BridgePreamble => {
                registry.register_bonding(
                    stages::preamble::Stage::<C::HostCurve, R, C::Profile>::mask()?,
                )
            }
            BridgeHash => {
                registry.register_bonding(stages::bridge_hash::Stage::<C::HostCurve>::mask()?)
            }
            BridgeSPrime => registry.register_bonding(stages::s_prime::Stage::<
                C::HostCurve,
                R,
                C::Profile,
            >::mask()?),
            BridgeInnerError => {
                registry.register_bonding(
                    stages::inner_error::Stage::<C::HostCurve, R, C::Profile>::mask()?,
                )
            }
            BridgeOuterError => {
                registry.register_bonding(
                    stages::outer_error::Stage::<C::HostCurve, R, C::Profile>::mask()?,
                )
            }
            BridgeAB => {
                registry.register_bonding(stages::ab::Stage::<C::HostCurve, R, C::Profile>::mask()?)
            }
            BridgeQuery => {
                registry
                    .register_bonding(stages::query::Stage::<C::HostCurve, R, C::Profile>::mask()?)
            }
            BridgeF => {
                registry.register_bonding(stages::f::Stage::<C::HostCurve, R, C::Profile>::mask()?)
            }
            BridgeEval => {
                registry
                    .register_bonding(stages::eval::Stage::<C::HostCurve, R, C::Profile>::mask()?)
            }
            ChallengeStage => {
                registry.register_bonding(
                    stages::challenges::Stage::<C::HostCurve, R, C::Profile>::mask()?,
                )
            }
            ChallengeFinalStaged => {
                registry.register_bonding(
                    stages::challenges::Stage::<C::HostCurve, R, C::Profile>::final_mask()?,
                )
            }
            Loading => {
                let circuit = circuits::loading::Circuit::<C::HostCurve, R, C::Profile>::new();
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
            LoadingSegment(segment) => {
                let circuit = circuits::loading::Circuit::<C::HostCurve, R, C::Profile>::segment(
                    segment as usize,
                );
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
            ExtensionCircuit(k) if builtin_circuit::<C::Profile>(k as usize).is_some() => {
                // A circuit of the fuse's own: it outputs the nested
                // unified instance, as the instance circuits do, and loads
                // no stage of the extension.
                extension_circuits.push(crate::profile::Registration::Circuit);
                match builtin_circuit::<C::Profile>(k as usize).expect("checked above") {
                    BuiltinCircuit::FoldInner(chunk) => {
                        let circuit =
                            circuits::fold_inner::Circuit::<C::HostCurve, R, C::Profile>::new(
                                chunk,
                            );
                        registry.register_internal_circuit(MultiStage::new(circuit))?
                    }
                    BuiltinCircuit::FoldOuter => {
                        let circuit =
                            circuits::fold_outer::Circuit::<C::HostCurve, R, C::Profile>::new();
                        registry.register_internal_circuit(MultiStage::new(circuit))?
                    }
                }
            }
            ExtensionCircuit(k) => {
                use crate::profile::online::stages::{self as extension, Nested};
                let slot = CircuitSlot::new(registry);
                let (registry, registration) =
                    if Some(k) == extension::helper::<C::Profile, Nested>() {
                        extension::register_circuit::<_, R, C::Profile, Nested>(
                            slot,
                            source_tag,
                            source_domain,
                        )?
                    } else {
                        C::Profile::register_nested_circuit::<C::Base, R>(k as usize, slot, params)?
                    }
                    .into_parts();
                extension_circuits.push(registration);
                registry
            }
            ExtensionBonding(j) => {
                use crate::profile::online::stages::{self as extension, Nested};
                let slot = BondingSlot::new(registry);
                // The fuse's own stages follow the stages the profile and
                // the online batch declare, so their masks sit between
                // those stages' masks and the final masks (see
                // `builtin_stage`).
                let declared = walk_stage_offset::<C::Profile>();
                let builtin = num_builtin_stages::<C::Profile>();
                let j = j as usize;
                let registered = if (declared..declared + builtin).contains(&j) {
                    match builtin_stage::<C::Profile>(j).expect("a stage the fuse adds") {
                        BuiltinStage::WalkSegment(_) => {
                            slot.register_mask::<self::PointsStage<C::HostCurve, C::Profile>>()?
                        }
                        BuiltinStage::WalkBoundaries => slot
                            .register_mask::<stages::boundaries::Stage<C::HostCurve, C::Profile>>(
                            )?,
                        BuiltinStage::FoldTargets => slot
                            .register_mask::<stages::targets::Stage<C::HostCurve, C::Profile>>()?,
                    }
                } else {
                    let index = if j < declared { j } else { j - builtin };
                    match extension::bonding::<C::Profile, Nested>(index)? {
                        extension::Bonding::Online(bonding) => {
                            bonding.register::<_, R, C::Profile, Nested>(slot)?
                        }
                        extension::Bonding::User(index) => {
                            C::Profile::register_nested_bonding::<C::Base, R>(index, slot, params)?
                        }
                    }
                };
                let (registry, registration) = registered.into_parts();
                extension_bondings.push(registration);
                registry
            }
        };
    }
    extension.check_registered("nested", &extension_circuits, &extension_bondings)?;

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + InternalCircuitIndex::num::<C::Profile>(),
        "internal circuit count mismatch"
    );

    Ok(registry)
}

#[cfg(test)]
mod index_positions {
    use super::*;
    use crate::profile::Standard;

    fn check<P: Profile>() {
        let all = InternalCircuitIndex::all::<P>();
        let circuits = all.iter().filter(|id| !id.is_bonding()).count();
        assert_eq!(num_claims::<P>(), 2 + 2 * circuits + all.len() - circuits);
        for (expected, id) in InternalCircuitIndex::all::<P>().into_iter().enumerate() {
            assert_eq!(usize::from(id.circuit_index::<P>()), expected, "{id:?}");
        }
        for (expected, id) in RxIndex::all::<P>().into_iter().enumerate() {
            assert_eq!(id.position::<P>(), expected, "{id:?}");
        }
    }

    #[test]
    fn arithmetic_positions_match_canonical_lists() {
        check::<Standard>();
        check::<crate::profile::testing::Wider>();
        check::<crate::profile::Aggregator<4>>();
        // A nested walk of several segments: its further segments' and its
        // boundaries stage's polynomials are the extension's stages, and a
        // loading circuit per further segment comes last.
        check::<crate::profile::testing::Segmented>();
        // A fold verified in chunks: its circuits and its targets stage
        // are the extension's last.
        check::<crate::profile::testing::Chunked>();
    }

    /// A fold verified in chunks names its circuits and its stage as the
    /// last of the nested extension's, and its chunks share the fold's
    /// groups in order, each taking some.
    #[test]
    fn a_chunked_fold_names_its_polynomials() {
        type P = crate::profile::testing::Chunked;
        let chunks = fold_chunks::<P>();
        assert!(is_fold_chunked::<P>() && chunks > 1);
        assert_eq!(num_builtin_circuits::<P>(), chunks + 1);
        assert_eq!(num_builtin_stages::<P>(), 1);
        assert_eq!(num_fold_polynomials(chunks), chunks + 2);

        let circuits = NumExtensionCircuits::<P>::len();
        assert_eq!(circuits, builtin_circuit_offset::<P>() + chunks + 1);
        for chunk in 0..chunks {
            assert_eq!(
                builtin_circuit::<P>(fold_inner::<P>(chunk) as usize),
                Some(BuiltinCircuit::FoldInner(chunk))
            );
        }
        assert_eq!(fold_outer::<P>() as usize, circuits - 1);
        assert_eq!(
            builtin_circuit::<P>(circuits - 1),
            Some(BuiltinCircuit::FoldOuter)
        );
        let stages = NumExtensionStages::<P>::len();
        assert_eq!(
            fold_targets_rx::<P>(),
            RxIndex::ExtensionStage(stages as u32 - 1)
        );
        assert_eq!(
            builtin_stage::<P>(stages - 1),
            Some(BuiltinStage::FoldTargets)
        );

        // The chunks' groups partition the fold's, in order.
        let groups = NumFoldGroups::<P>::len();
        let mut next = 0;
        for chunk in 0..chunks {
            let share = fold_groups::<P>(chunk);
            assert_eq!(share.start, next);
            assert!(!share.is_empty());
            next = share.end;
        }
        assert_eq!(next, groups);

        // A fold `collapse` verifies whole adds none of them.
        assert!(!is_fold_chunked::<Standard>());
        assert_eq!(num_builtin_circuits::<Standard>(), 0);
        assert_eq!(num_builtin_stages::<Standard>(), 0);

        // A walk of several segments keeps its stages before the fold's:
        // its further segments, then its boundaries stage.
        type S = crate::profile::testing::Segmented;
        let stages = NumExtensionStages::<S>::len();
        assert_eq!(
            builtin_stage::<S>(stages - 1),
            Some(BuiltinStage::WalkBoundaries)
        );
        assert_eq!(
            builtin_stage::<S>(walk_stage_offset::<S>()),
            Some(BuiltinStage::WalkSegment(1))
        );
    }

    /// A walk of several segments names each segment's polynomial once, the
    /// boundaries stage's after them, and gives every step its segment's.
    #[test]
    fn a_segmented_walk_names_its_polynomials() {
        type P = crate::profile::testing::Segmented;
        let walk = segments::<P>();
        assert!(walk.is_split());
        let all = RxIndex::all::<P>();
        let mut named: Vec<RxIndex> = (0..walk.count()).map(segment_rx::<P>).collect();
        named.push(boundaries_rx::<P>());
        for (i, id) in named.iter().enumerate() {
            assert!(all.contains(id), "{id:?} is one of the proof's polynomials");
            assert!(!named[..i].contains(id), "{id:?} is named once");
        }
        let loadings = InternalCircuitIndex::all::<P>()
            .into_iter()
            .filter(|id| matches!(id, InternalCircuitIndex::LoadingSegment(_)))
            .count();
        assert_eq!(loadings, walk.count() - 1);
        // Every step is a step of its own segment, within the stage.
        for step in 0..walk.steps() {
            let (segment, local) = walk.locate(step);
            assert!(segment < walk.count() && local < walk.steps_of(segment));
            let _ =
                endoscaling_step::<ragu_core::pasta::EqAffine, crate::internal::tests::R, P>(step);
        }
    }
}
