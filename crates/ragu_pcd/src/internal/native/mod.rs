//! Native curve circuits for recursive verification.
//!
//! Besides the circuits that verify the native fold and batch, the native
//! side walks the nested batch's commitments: the endoscaling steps of
//! [`circuits::endoscaling_step`] fold the [`NUM_ENDOSCALING_POINTS`]
//! nested-curve points of [`stages::points`] into $P_n$ by Horner's rule
//! under $\beta$'s endoscalar, which [`circuits::bind_endoscalar`] ties to
//! `pre_beta`. The points are committed in stages the transcript absorbs
//! before the challenges the nested openings are at (see
//! [`stages::points`]). This mirrors the nested side's walk over the native
//! batch.
//!
//! [`circuits::bind_endoscalar`] emits the bit and curve contracts the steps
//! share, and pins the walk's endpoint and this step's persistent points to
//! the unified instance. [`circuits::bind_beta`] holds the children's walked
//! points against the children's unified instances.

use alloc::vec::Vec;
use core::marker::PhantomData;

pub use circuits::bind_challenges::NUM_BINDERS;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::{MultiStage, StageExt},
};
use ragu_core::Result;
use ragu_primitives::vec::{ConstLen, FixedVec, Len};

use crate::{
    internal::{endoscalar, nested, revdot::Parameters},
    profile::{BondingSlot, CircuitSlot, Profile, ProfiledCycle, Shape},
    step,
};

/// The nested-curve points the native endoscaling walks into $P_n$ in the
/// standard profile: the nested batch's commitments, in
/// [`nested::pcs::Batch::evaluated`] order after $f_n$'s.
pub const NUM_ENDOSCALING_POINTS: usize = nested::pcs::NUM_BATCHED_POINTS;

/// Length type for the nested-curve points the native endoscaling walks into
/// $P_n$ in profile `P`: the profile's
/// [`native_points`](Shape::native_points), which the standard profile has as
/// [`NUM_ENDOSCALING_POINTS`].
pub struct NumPoints<P: Profile>(PhantomData<P>);

impl<P: Profile> NumPoints<P> {
    /// The count, evaluated once per profile.
    pub const LEN: usize = Shape::of::<P>().native_points;
}

impl<P: Profile> Len for NumPoints<P> {
    fn len() -> usize {
        Self::LEN
    }
}

/// The endoscalings a native step performs in the standard profile: what
/// fits a step beside the stages it reserves at the wallet rank. A
/// profile sets its own ([`Profile::NATIVE_ENDOSCALINGS_PER_STEP`]).
pub const ENDOSCALINGS_PER_STEP: usize = 4;

/// Length type for the endoscalings a native step performs in profile `P`.
pub struct Endoscalings<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for Endoscalings<P> {
    fn len() -> usize {
        P::NATIVE_ENDOSCALINGS_PER_STEP
    }
}

/// The number of native endoscaling steps: the standard profile's pin.
///
/// Pinned rather than derived: each side's step polynomials are opened by
/// the other side's batch, so the two step counts determine each other's
/// batch sizes, and one of them has to be fixed to break the cycle. The
/// assertion below checks the pin is the fixed point, so a change to either
/// batch that moves it fails to build here. The profile's shape rederives
/// the whole cycle (see [`Shape`]).
pub const NUM_ENDOSCALING_STEPS: usize = 27;

const _: () = assert!(
    endoscalar::num_steps(ENDOSCALINGS_PER_STEP, NUM_ENDOSCALING_POINTS) == NUM_ENDOSCALING_STEPS,
    "NUM_ENDOSCALING_STEPS is not the number of steps over the nested batch; re-pin it"
);

/// Length type for the native endoscaling steps in profile `P`.
///
/// Each side's step polynomials are opened by the other side's batch, so the
/// two step counts determine each other's batch sizes; the profile's
/// [`Shape`] solves that cycle to its fixed point, and this is the walk over
/// the batch that fixed point gives. The standard profile's is
/// [`NUM_ENDOSCALING_STEPS`].
pub type NumSteps<P> = endoscalar::NumStepsLen<NumPoints<P>, Endoscalings<P>>;

/// How the native walk of profile `P` is cut into segments: one, the whole
/// walk, unless the profile sets
/// [`NATIVE_STEPS_PER_SEGMENT`](Profile::NATIVE_STEPS_PER_SEGMENT) below
/// the walk's steps.
///
/// The steps of a walk of one segment read every point from the stage that
/// committed it and write the walk stage's interstitials. The steps of a
/// walk of several read their segment's polynomial of
/// [`SegmentStage`](stages::points::SegmentStage) instead, which holds
/// copies of the points the segment folds and its steps' outputs, and the
/// endoscalar's bits from [`BitsStage`](stages::points::BitsStage); a
/// [`walk_loading`](circuits::walk_loading) bonding per segment holds the
/// copies to the stages that committed the points and ties the segment to
/// its neighbours through
/// [`BoundariesStage`](stages::points::BoundariesStage).
pub struct Walk<P: Profile>(PhantomData<P>);

impl<P: Profile> Walk<P> {
    /// The segments, evaluated once per profile.
    pub const SEGMENTS: endoscalar::Segments = endoscalar::Segments::new(
        NumPoints::<P>::LEN,
        P::NATIVE_ENDOSCALINGS_PER_STEP,
        P::NATIVE_STEPS_PER_SEGMENT,
    );
}

/// The segments of profile `P`'s native walk (see [`Walk`]).
pub const fn segments<P: Profile>() -> endoscalar::Segments {
    Walk::<P>::SEGMENTS
}

/// The stage polynomials a native walk of `segments` segments adds to a
/// proof: the bits stage's, one of the segment stage per segment, then the
/// boundaries stage's. None for a walk of one segment.
///
/// A proof carries them as the last stages of its native extension (see
/// `profile::native_extension`), so the nested walk folds their commitments
/// with the extension's.
pub const fn num_walk_stages(segments: usize) -> usize {
    if segments > 1 { segments + 2 } else { 0 }
}

/// The bondings a native walk of `segments` segments adds beyond its
/// stages' masks: a loading per segment and the final mask of its steps.
/// None for a walk of one segment.
pub const fn num_walk_bondings(segments: usize) -> usize {
    if segments > 1 { segments + 1 } else { 0 }
}

/// The index, among the native extension's stages, of the first stage the
/// native walk adds: the stages the profile and the online batch declare
/// come before.
pub(crate) fn walk_stage_offset<P: Profile>() -> usize {
    crate::profile::online::stages::layout::<P, crate::profile::online::stages::Native>().stages
}

/// The rx polynomial of the bits stage of profile `P`'s native walk, for a
/// walk of several segments.
///
/// # Panics
///
/// Panics if the walk is one segment, whose bits the walk stage holds.
pub fn walk_bits_rx<P: Profile>() -> RxIndex {
    assert!(
        segments::<P>().is_split(),
        "a walk of one segment keeps its bits in the walk stage"
    );
    RxIndex::ExtensionStage(walk_stage_offset::<P>() as u32)
}

/// The rx polynomial of segment `segment` of profile `P`'s native walk, for
/// a walk of several segments.
///
/// # Panics
///
/// Panics if the walk is one segment or has no such segment.
pub fn segment_rx<P: Profile>(segment: usize) -> RxIndex {
    let walk = segments::<P>();
    assert!(
        walk.is_split(),
        "a walk of one segment has no segment stage"
    );
    assert!(segment < walk.count(), "no such segment");
    RxIndex::ExtensionStage((walk_stage_offset::<P>() + 1 + segment) as u32)
}

/// The rx polynomial of the boundaries stage of profile `P`'s native walk,
/// for a walk of several segments.
///
/// # Panics
///
/// Panics if the walk is one segment, which has no boundary.
pub fn boundaries_rx<P: Profile>() -> RxIndex {
    let walk = segments::<P>();
    assert!(walk.is_split(), "a walk of one segment has no boundary");
    RxIndex::ExtensionStage((walk_stage_offset::<P>() + 1 + walk.count()) as u32)
}

/// The polynomials a native fold cut into `chunks` first-layer chunk
/// circuits adds to a proof: the chunk circuits', the second layer's
/// circuit's and the targets stage's. None for a fold `collapse` verifies
/// whole.
pub const fn num_fold_polynomials(chunks: usize) -> usize {
    if chunks > 0 { chunks + 2 } else { 0 }
}

/// The circuits that verify the first layer of profile `P`'s native fold:
/// none when `collapse` verifies the fold whole (see
/// [`Chunking`](crate::profile::Chunking)).
pub fn fold_chunks<P: Profile>() -> usize {
    P::CHUNKING.native_fold
}

/// Whether profile `P` cuts the native fold's verification into chunks.
pub fn is_fold_chunked<P: Profile>() -> bool {
    fold_chunks::<P>() > 0
}

/// The groups of profile `P`'s native fold that first-layer chunk `chunk`
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

/// A stage of the fuse that a proof carries among its native extension's
/// stages, after the ones the profile and the online batch declare, in the
/// order of [`builtin_stage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinStage {
    /// The bits stage of a walk of several segments.
    WalkBits,
    /// The segment stage of a walk of several segments, one per segment.
    WalkSegment(usize),
    /// The boundaries stage of a walk of several segments.
    WalkBoundaries,
    /// The targets stage of a fold verified in chunks.
    FoldTargets,
    /// The carry stage of an opening program run in chunks.
    OpenCarry,
    /// The band stage of an opening program run in chunks, one per band: a
    /// chunk's by its index, then `compute_v`'s own.
    OpenBand(usize),
}

/// The stages the fuse adds to profile `P`'s native extension: those of a
/// walk of several segments, then the targets stage of a fold verified in
/// chunks, then the carry stage and the bands of an opening program run in
/// chunks.
pub fn num_builtin_stages<P: Profile>() -> usize {
    num_walk_stages(segments::<P>().count())
        + is_fold_chunked::<P>() as usize
        + num_opening_stages(opening_chunks::<P>())
}

/// The circuits that run profile `P`'s opening program: none when
/// `compute_v` runs it whole (see [`Chunking`](crate::profile::Chunking)).
pub fn opening_chunks<P: Profile>() -> usize {
    P::CHUNKING.native_openings
}

/// Whether profile `P` runs its opening program in chunks.
pub fn is_opening_chunked<P: Profile>() -> bool {
    opening_chunks::<P>() > 0
}

/// The stage polynomials an opening program run in `chunks` chunks adds to
/// a proof: the carry stage's and a band's per chunk and for `compute_v`.
pub const fn num_opening_stages(chunks: usize) -> usize {
    if chunks > 0 { chunks + 2 } else { 0 }
}

/// The polynomials an opening program run in `chunks` chunks adds to a
/// proof: the chunk circuits' and the stages' ([`num_opening_stages`]).
pub const fn num_opening_polynomials(chunks: usize) -> usize {
    if chunks > 0 {
        chunks + num_opening_stages(chunks)
    } else {
        0
    }
}

/// The bondings an opening program run in `chunks` chunks adds beyond its
/// stages' masks: a loading per band and the final mask of the circuits
/// that end on the band stage.
pub const fn num_opening_bondings(chunks: usize) -> usize {
    if chunks > 0 { chunks + 2 } else { 0 }
}

/// Length type for the bands of profile `P`'s opening program: one per
/// chunk and one for `compute_v`, none for a program run whole.
pub struct NumOpenBands<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumOpenBands<P> {
    fn len() -> usize {
        match opening_chunks::<P>() {
            0 => 0,
            chunks => chunks + 1,
        }
    }
}

/// Length type that is one for a profile whose opening program runs in
/// chunks and zero otherwise.
pub struct Opened<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for Opened<P> {
    fn len() -> usize {
        is_opening_chunked::<P>() as usize
    }
}

/// Length type for the values a band of profile `P`'s opening program
/// holds: the profile's [`native_band`](crate::profile::Chunking), and
/// none for a program run whole.
pub struct OpenBandLen<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for OpenBandLen<P> {
    fn len() -> usize {
        if is_opening_chunked::<P>() {
            P::CHUNKING.native_band
        } else {
            0
        }
    }
}

/// The rx polynomial of the carry stage of profile `P`'s opening program.
///
/// # Panics
///
/// Panics if `compute_v` runs the program whole.
pub fn open_carry_rx<P: Profile>() -> RxIndex {
    assert!(
        is_opening_chunked::<P>(),
        "a program run whole has no carry stage"
    );
    RxIndex::ExtensionStage(
        (walk_stage_offset::<P>()
            + num_walk_stages(segments::<P>().count())
            + is_fold_chunked::<P>() as usize) as u32,
    )
}

/// The rx polynomial of band `band` of profile `P`'s opening program: a
/// chunk's by its index, and `compute_v`'s own after the chunks'.
///
/// # Panics
///
/// Panics if the program has no such band.
pub fn open_band_rx<P: Profile>(band: usize) -> RxIndex {
    assert!(band < NumOpenBands::<P>::len(), "no such band");
    let RxIndex::ExtensionStage(carry) = open_carry_rx::<P>() else {
        unreachable!("the carry stage is a stage of the extension")
    };
    RxIndex::ExtensionStage(carry + 1 + band as u32)
}

/// The fuse's stage at index `stage` of profile `P`'s native extension's
/// stages, or `None` for a stage the profile or the online batch declares.
///
/// # Panics
///
/// Panics if the extension has no such stage.
pub fn builtin_stage<P: Profile>(stage: usize) -> Option<BuiltinStage> {
    let declared = walk_stage_offset::<P>();
    let index = stage.checked_sub(declared)?;
    let walk = num_walk_stages(segments::<P>().count());
    if index < walk {
        return Some(match index {
            0 => BuiltinStage::WalkBits,
            index if index + 1 == walk => BuiltinStage::WalkBoundaries,
            index => BuiltinStage::WalkSegment(index - 1),
        });
    }
    let index = index - walk;
    let fold = is_fold_chunked::<P>() as usize;
    if index < fold {
        return Some(BuiltinStage::FoldTargets);
    }
    let index = index - fold;
    assert!(
        index < num_opening_stages(opening_chunks::<P>()),
        "no such extension stage"
    );
    Some(match index {
        0 => BuiltinStage::OpenCarry,
        index => BuiltinStage::OpenBand(index - 1),
    })
}

/// The rx polynomial of the targets stage of profile `P`'s native fold,
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

/// A circuit of the fuse that a proof carries among its native extension's
/// circuits, after the ones the profile and the online batch declare, in
/// the order of [`builtin_circuit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinCircuit {
    /// A first-layer chunk of a fold verified in chunks.
    FoldInner(usize),
    /// The second layer's circuit of a fold verified in chunks.
    FoldOuter,
    /// A chunk of an opening program run in chunks.
    Open(usize),
}

/// The circuits a fold verified in chunks adds: its chunks and its second
/// layer's circuit.
fn num_fold_circuits<P: Profile>() -> usize {
    match fold_chunks::<P>() {
        0 => 0,
        chunks => chunks + 1,
    }
}

/// The circuits the fuse adds to profile `P`'s native extension: the
/// chunks of a fold verified in chunks and its second layer's circuit,
/// then the chunks of an opening program run in chunks.
pub fn num_builtin_circuits<P: Profile>() -> usize {
    num_fold_circuits::<P>() + opening_chunks::<P>()
}

/// The index, among the native extension's circuits, of the first circuit
/// the fuse adds: the circuits the profile and the online batch declare
/// come before.
pub(crate) fn builtin_circuit_offset<P: Profile>() -> usize {
    crate::profile::online::stages::layout::<P, crate::profile::online::stages::Native>()
        .circuits
        .len()
}

/// The fuse's circuit at index `circuit` of profile `P`'s native
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
    let fold = num_fold_circuits::<P>();
    Some(if index >= fold {
        BuiltinCircuit::Open(index - fold)
    } else if index < chunks {
        BuiltinCircuit::FoldInner(index)
    } else {
        BuiltinCircuit::FoldOuter
    })
}

/// Chunk `chunk` of profile `P`'s opening program, among the native
/// extension's circuits: the index of its circuit and of its rx
/// polynomial.
///
/// # Panics
///
/// Panics if the program has no such chunk.
pub fn open_chunk<P: Profile>(chunk: usize) -> u32 {
    assert!(chunk < opening_chunks::<P>(), "no such opening chunk");
    (builtin_circuit_offset::<P>() + num_fold_circuits::<P>() + chunk) as u32
}

/// First-layer chunk `chunk` of profile `P`'s native fold, among the
/// native extension's circuits: the index of its circuit and of its rx
/// polynomial.
///
/// # Panics
///
/// Panics if the fold has no such chunk.
pub fn fold_inner<P: Profile>(chunk: usize) -> u32 {
    assert!(chunk < fold_chunks::<P>(), "no such fold chunk");
    (builtin_circuit_offset::<P>() + chunk) as u32
}

/// The second layer's circuit of profile `P`'s native fold, for a fold
/// verified in chunks, among the native extension's circuits: the index of
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

/// Length type that is one for a native walk of several segments in profile
/// `P` and zero for a walk of one.
pub struct Split<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for Split<P> {
    fn len() -> usize {
        segments::<P>().is_split() as usize
    }
}

/// Length type for the loading bondings of profile `P`'s native walk: one
/// per segment of a walk of several, none for a walk of one.
pub struct NumWalkLoadings<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumWalkLoadings<P> {
    fn len() -> usize {
        let walk = segments::<P>();
        if walk.is_split() { walk.count() } else { 0 }
    }
}

/// Length type for the circuits of the profile's native extension.
pub struct NumExtensionCircuits<P: Profile>(core::marker::PhantomData<P>);

impl<P: Profile> Len for NumExtensionCircuits<P> {
    fn len() -> usize {
        crate::profile::extension_lengths::<P>(false).circuits
    }
}

/// Length type for the stages of the profile's native extension.
pub struct NumExtensionStages<P: Profile>(core::marker::PhantomData<P>);

impl<P: Profile> Len for NumExtensionStages<P> {
    fn len() -> usize {
        crate::profile::extension_lengths::<P>(false).stages
    }
}

/// Length type for the bondings of the profile's native extension.
pub struct NumExtensionBondings<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumExtensionBondings<P> {
    fn len() -> usize {
        crate::profile::extension_lengths::<P>(false).bondings
    }
}

// Unlike `FixedVec::try_from_fn`, these value containers also propagate errors
// other than `ragu_core::Error`. The index range fixes the length before `f` runs.
fn try_fixed_vec<T, L: Len, E>(
    f: impl FnMut(usize) -> core::result::Result<T, E>,
) -> core::result::Result<FixedVec<T, L>, E> {
    let values = L::range()
        .map(f)
        .collect::<core::result::Result<Vec<_>, _>>()?;
    Ok(FixedVec::new(values).expect("the index range fixes the vector length"))
}

/// The native rx polynomials that are not endoscaling steps: the four
/// hashing, collapse and compute-v circuits', the binders', bind-beta's,
/// bind-endoscalar's and the eleven stages'.
///
/// The application's rx and its stage's are not among them: a step folds
/// its own application claim and opens both polynomials itself, so a proof
/// does not carry them to its parent.
pub const NUM_FIXED_RX: usize = 17 + NUM_BINDERS;

/// The native internal circuits that are not endoscaling steps: the rx
/// polynomials' circuits and stages, the five final stage masks, and the
/// application stage's mask and final mask.
pub const NUM_FIXED_INTERNAL: usize = NUM_FIXED_RX + 5 + 2;

/// The minimum groups for the native quotient fold: fourteen groups with
/// seven claims each provide room for 98 claims, and the fifteenth holds the
/// randomizer's half-claim (see
/// [`revdot`](crate::internal::revdot#the-randomizer)). Larger
/// profiles grow the group count.
pub const NUM_FOLD_GROUPS: usize = 15;

/// The nodes of a native fold group: seven claims and the randomizer's.
pub const FOLD_GROUP_SIZE: usize = 8;

/// The native revdot claims of profile `P` the fuse folds: the two
/// children's raw claims, the step's own application claim, each internal
/// circuit's claim per child, and each bonding's claim across both.
pub fn num_claims<P: Profile>() -> usize {
    let extension = crate::profile::extension_lengths::<P>(false);
    let circuits = 6 + NUM_BINDERS + NumSteps::<P>::len() + extension.circuits;
    let bondings = 18
        + extension.bondings
        + num_walk_bondings(segments::<P>().count())
        + num_opening_bondings(opening_chunks::<P>());
    2 + 1 + 2 * circuits + bondings
}

/// Length type for the native fold's groups in profile `P`: the standard
/// profile's [`NUM_FOLD_GROUPS`], or as many groups of [`FOLD_GROUP_SIZE`]
/// as the profile's [`num_claims`] need beside the randomizer's (see
/// [`revdot::num_groups`](crate::internal::revdot::num_groups)),
/// whichever is more.
pub struct NumFoldGroups<P: Profile>(core::marker::PhantomData<P>);

impl<P: Profile> Len for NumFoldGroups<P> {
    fn len() -> usize {
        NUM_FOLD_GROUPS.max(crate::internal::revdot::num_groups(
            num_claims::<P>(),
            FOLD_GROUP_SIZE,
        ))
    }
}

/// Parameters for folding the children's native revdot claims in profile
/// `P`: [`NumFoldGroups`] groups of [`FOLD_GROUP_SIZE`] nodes.
pub struct RevdotParameters<P: Profile>(core::marker::PhantomData<P>);

impl<P: Profile> Clone for RevdotParameters<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: Profile> Copy for RevdotParameters<P> {}

impl<P: Profile> Default for RevdotParameters<P> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<P: Profile> Parameters for RevdotParameters<P> {
    type NumGroups = NumFoldGroups<P>;
    type GroupSize = ConstLen<FOLD_GROUP_SIZE>;
}

pub mod stages {
    pub mod eval;
    pub mod inner_error;
    pub mod outer_error;
    pub mod open;
    pub mod points;
    pub mod preamble;
    pub mod query;
    pub mod targets;
}

pub mod circuits {
    pub mod bind_beta;
    pub mod bind_challenges;
    pub mod bind_endoscalar;
    pub mod collapse;
    pub mod compute_v;
    pub mod endoscaling_step;
    pub mod fold_inner;
    pub mod fold_outer;
    pub mod hashes_1;
    pub mod hashes_2;
    pub mod open;
    pub mod open_base;
    pub mod open_loading;
    pub mod segment_step;
    pub mod walk_loading;
}

pub mod claims;
pub mod online;
pub mod open;
pub mod pcs;
pub mod unified;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InternalCircuitIndex {
    // Native circuits
    Hashes1Circuit,
    Hashes2Circuit,
    CollapseCircuit,
    ComputeVCircuit,
    /// Nested challenge binding circuit at the given index (see
    /// [`bind_challenges`](circuits::bind_challenges)).
    BindChallengesCircuit(u32),
    /// The children's nested beta binding circuit (see
    /// [`bind_beta`](circuits::bind_beta)).
    BindBetaCircuit,
    /// The walk stage binding circuit (see
    /// [`bind_endoscalar`](circuits::bind_endoscalar)).
    BindEndoscalarCircuit,
    /// A native endoscaling step (see
    /// [`endoscaling_step`](circuits::endoscaling_step)).
    EndoscalingStep(u32),
    /// A circuit of the profile's native extension (see
    /// [`Extension`](crate::profile::Extension)).
    ExtensionCircuit(u32),
    // Native stages
    PreambleStage,
    InnerErrorStage,
    OuterErrorStage,
    QueryStage,
    EvalStage,
    PointsBindingStage,
    PointsPreambleStage,
    PointsRegistryWxStage,
    PointsAbStage,
    PointsFStage,
    PointsWalkStage,
    // Final stage masks
    InnerErrorFinalStaged,
    OuterErrorFinalStaged,
    EvalFinalStaged,
    PointsWalkFinalStaged,
    /// The preamble's final mask, under which `bind_beta` ends.
    PreambleFinalStaged,
    // Application masks
    /// The mask of the application stage, which every step circuit reserves
    /// after its SYSTEM gate.
    ApplicationStage,
    /// The final mask of the step circuits, whose only stage is the
    /// application stage.
    ApplicationFinalStaged,
    /// A bonding of the profile's native extension, a stage's mask or a
    /// final mask, in [`Extension::bondings`](crate::profile::Extension::bondings)
    /// order.
    ExtensionBonding(u32),
    /// The bonding that holds a segment of a native walk of several
    /// segments to the stages that commit its points (see
    /// [`walk_loading`](circuits::walk_loading)). A walk of one segment has
    /// none.
    WalkLoading(u32),
    /// The final mask of the steps of a native walk of several segments,
    /// whose last stage is the segment's. A walk of one segment has none:
    /// its steps end under the walk stage's.
    WalkSegmentFinalStaged,
    /// The bonding that holds a band of an opening program run in chunks
    /// to the stage values it copies (see
    /// [`open_loading`](circuits::open_loading)): a chunk's band by its
    /// index, then `compute_v`'s own. A program run whole has none.
    OpeningLoading(u32),
    /// The final mask of the circuits of an opening program run in chunks,
    /// which end on the band stage: the chunks and `compute_v`. A program
    /// run whole has none: `compute_v` ends under the eval stage's.
    OpeningFinalStaged,
}

/// Compute the total circuit count and log2 domain size from the number of
/// application-defined steps, in profile `P`.
pub fn total_circuit_counts<P: Profile>(num_application_steps: usize) -> (usize, u32) {
    let total_circuits =
        num_application_steps + step::num_internal_steps::<P>() + InternalCircuitIndex::num::<P>();
    let log2_circuits = total_circuits.next_power_of_two().trailing_zeros();
    (total_circuits, log2_circuits)
}

impl InternalCircuitIndex {
    /// The number of internal circuits registered by [`register_all`],
    /// equal to the number of variants in [`InternalCircuitIndex`].
    pub const NUM: usize = NUM_FIXED_INTERNAL + NUM_ENDOSCALING_STEPS;

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
        push(&mut slots, &mut c, Self::Hashes1Circuit);
        push(&mut slots, &mut c, Self::Hashes2Circuit);
        push(&mut slots, &mut c, Self::CollapseCircuit);
        push(&mut slots, &mut c, Self::ComputeVCircuit);
        {
            let mut k = 0;
            while k < NUM_BINDERS {
                push(&mut slots, &mut c, Self::BindChallengesCircuit(k as u32));
                k += 1;
            }
        }
        push(&mut slots, &mut c, Self::BindBetaCircuit);
        push(&mut slots, &mut c, Self::BindEndoscalarCircuit);
        {
            let mut step = 0;
            while step < NUM_ENDOSCALING_STEPS {
                push(&mut slots, &mut c, Self::EndoscalingStep(step as u32));
                step += 1;
            }
        }
        push(&mut slots, &mut c, Self::PreambleStage);
        push(&mut slots, &mut c, Self::InnerErrorStage);
        push(&mut slots, &mut c, Self::OuterErrorStage);
        push(&mut slots, &mut c, Self::QueryStage);
        push(&mut slots, &mut c, Self::EvalStage);
        push(&mut slots, &mut c, Self::PointsBindingStage);
        push(&mut slots, &mut c, Self::PointsPreambleStage);
        push(&mut slots, &mut c, Self::PointsRegistryWxStage);
        push(&mut slots, &mut c, Self::PointsAbStage);
        push(&mut slots, &mut c, Self::PointsFStage);
        push(&mut slots, &mut c, Self::PointsWalkStage);
        push(&mut slots, &mut c, Self::InnerErrorFinalStaged);
        push(&mut slots, &mut c, Self::OuterErrorFinalStaged);
        push(&mut slots, &mut c, Self::EvalFinalStaged);
        push(&mut slots, &mut c, Self::PointsWalkFinalStaged);
        push(&mut slots, &mut c, Self::PreambleFinalStaged);
        push(&mut slots, &mut c, Self::ApplicationStage);
        push(&mut slots, &mut c, Self::ApplicationFinalStaged);
        assert!(c == Self::NUM);
        slots
    }

    /// The number of internal circuits registered by [`register_all`] in
    /// profile `P`, equal to the length of [`all`](Self::all).
    pub fn num<P: Profile>() -> usize {
        NUM_FIXED_INTERNAL
            + NumSteps::<P>::len()
            + crate::profile::native_extension::<P>().internal()
            + num_walk_bondings(segments::<P>().count())
            + num_opening_bondings(opening_chunks::<P>())
    }

    /// All variants in canonical iteration order, for profile `P`:
    /// [`ALL`](Self::ALL) with the walk resized to the profile's steps, the
    /// profile's extension circuits after the walk and its bondings after
    /// the fuse's masks, then, for a walk of several segments, its loadings
    /// and its steps' final mask.
    /// The index tests compare this order with [`Self::circuit_index`].
    pub fn all<P: Profile>() -> Vec<Self> {
        let extension = crate::profile::native_extension::<P>();
        let mut all = Self::all_with(
            NumSteps::<P>::len(),
            extension.circuits.len(),
            extension.bondings(),
        );
        if segments::<P>().is_split() {
            all.extend((0..NumWalkLoadings::<P>::len() as u32).map(Self::WalkLoading));
            all.push(Self::WalkSegmentFinalStaged);
        }
        if is_opening_chunked::<P>() {
            all.extend((0..NumOpenBands::<P>::len() as u32).map(Self::OpeningLoading));
            all.push(Self::OpeningFinalStaged);
        }
        assert_eq!(all.len(), Self::num::<P>());
        all
    }

    /// [`ALL`](Self::ALL) with the walk resized to `num_steps` steps,
    /// `circuits` extension circuits after it and `bondings` extension
    /// bondings after the fuse's masks.
    pub(crate) fn all_with(num_steps: usize, circuits: usize, bondings: usize) -> Vec<Self> {
        let mut all = Vec::with_capacity(NUM_FIXED_INTERNAL + num_steps + circuits + bondings);
        for &id in &Self::ALL {
            match id {
                Self::EndoscalingStep(0) => {
                    all.extend((0..num_steps as u32).map(Self::EndoscalingStep));
                    all.extend((0..circuits as u32).map(Self::ExtensionCircuit));
                }
                Self::EndoscalingStep(_) => {}
                id => all.push(id),
            }
        }
        all.extend((0..bondings as u32).map(Self::ExtensionBonding));
        all
    }

    /// The registry index of `self` in profile `P`.
    pub fn circuit_index<P: Profile>(self) -> CircuitIndex {
        use InternalCircuitIndex::*;
        let steps = NumSteps::<P>::len();
        let extension = crate::profile::extension_lengths::<P>(false);
        let endoscaling = 6 + NUM_BINDERS;
        let bonding = endoscaling + steps + extension.circuits;
        let pos = match self {
            Hashes1Circuit => 0,
            Hashes2Circuit => 1,
            CollapseCircuit => 2,
            ComputeVCircuit => 3,
            BindChallengesCircuit(i) => 4 + super::checked_index(i, NUM_BINDERS),
            BindBetaCircuit => 4 + NUM_BINDERS,
            BindEndoscalarCircuit => 5 + NUM_BINDERS,
            EndoscalingStep(i) => endoscaling + super::checked_index(i, steps),
            ExtensionCircuit(i) => {
                endoscaling + steps + super::checked_index(i, extension.circuits)
            }
            PreambleStage => bonding,
            InnerErrorStage => bonding + 1,
            OuterErrorStage => bonding + 2,
            QueryStage => bonding + 3,
            EvalStage => bonding + 4,
            PointsBindingStage => bonding + 5,
            PointsPreambleStage => bonding + 6,
            PointsRegistryWxStage => bonding + 7,
            PointsAbStage => bonding + 8,
            PointsFStage => bonding + 9,
            PointsWalkStage => bonding + 10,
            InnerErrorFinalStaged => bonding + 11,
            OuterErrorFinalStaged => bonding + 12,
            EvalFinalStaged => bonding + 13,
            PointsWalkFinalStaged => bonding + 14,
            PreambleFinalStaged => bonding + 15,
            ApplicationStage => bonding + 16,
            ApplicationFinalStaged => bonding + 17,
            ExtensionBonding(i) => bonding + 18 + super::checked_index(i, extension.bondings),
            WalkLoading(i) => {
                bonding
                    + 18
                    + extension.bondings
                    + super::checked_index(i, NumWalkLoadings::<P>::len())
            }
            WalkSegmentFinalStaged => {
                assert!(
                    segments::<P>().is_split(),
                    "a walk of one segment has no segment stage"
                );
                bonding + 18 + extension.bondings + NumWalkLoadings::<P>::len()
            }
            OpeningLoading(i) => {
                bonding
                    + 18
                    + extension.bondings
                    + num_walk_bondings(segments::<P>().count())
                    + super::checked_index(i, NumOpenBands::<P>::len())
            }
            OpeningFinalStaged => {
                assert!(
                    is_opening_chunked::<P>(),
                    "a program run whole has no band stage"
                );
                bonding
                    + 18
                    + extension.bondings
                    + num_walk_bondings(segments::<P>().count())
                    + NumOpenBands::<P>::len()
            }
        };
        CircuitIndex::new(pos)
    }

    /// Whether `self` is registered as a bonding, a stage's mask or a final
    /// mask, rather than as a circuit.
    #[cfg(test)]
    pub fn is_bonding(self) -> bool {
        use InternalCircuitIndex::*;
        match self {
            Hashes1Circuit
            | Hashes2Circuit
            | CollapseCircuit
            | ComputeVCircuit
            | BindChallengesCircuit(_)
            | BindBetaCircuit
            | BindEndoscalarCircuit
            | EndoscalingStep(_)
            | ExtensionCircuit(_) => false,
            PreambleStage
            | InnerErrorStage
            | OuterErrorStage
            | QueryStage
            | EvalStage
            | PointsBindingStage
            | PointsPreambleStage
            | PointsRegistryWxStage
            | PointsAbStage
            | PointsFStage
            | PointsWalkStage
            | InnerErrorFinalStaged
            | OuterErrorFinalStaged
            | EvalFinalStaged
            | PointsWalkFinalStaged
            | PreambleFinalStaged
            | ApplicationStage
            | ApplicationFinalStaged
            | ExtensionBonding(_)
            | WalkLoading(_)
            | WalkSegmentFinalStaged
            | OpeningLoading(_)
            | OpeningFinalStaged => true,
        }
    }
}

/// Per-internal-circuit storage indexed by [`InternalCircuitIndex`].
///
/// Each field corresponds 1:1 to a variant of [`InternalCircuitIndex`].
/// Use [`get`](Self::get) to look up by variant, and
/// [`from_fn`](Self::from_fn) / [`try_from_fn`](Self::try_from_fn) to
/// construct from a closure.
#[derive(Clone)]
pub struct InternalCircuitValues<T, P: Profile> {
    pub hashes_1_circuit: T,
    pub hashes_2_circuit: T,
    pub collapse_circuit: T,
    pub compute_v_circuit: T,
    pub bind_challenges_circuits: [T; NUM_BINDERS],
    pub bind_beta_circuit: T,
    pub bind_endoscalar_circuit: T,
    /// One per endoscaling step of the profile the values were built for.
    pub endoscaling_step_circuits: FixedVec<T, NumSteps<P>>,
    /// One per circuit of the profile's native extension.
    pub extension_circuits: FixedVec<T, NumExtensionCircuits<P>>,
    pub preamble_stage: T,
    pub inner_error_stage: T,
    pub outer_error_stage: T,
    pub query_stage: T,
    pub eval_stage: T,
    pub points_binding_stage: T,
    pub points_preamble_stage: T,
    pub points_registry_wx_stage: T,
    pub points_ab_stage: T,
    pub points_f_stage: T,
    pub points_walk_stage: T,
    pub inner_error_final_staged: T,
    pub outer_error_final_staged: T,
    pub eval_final_staged: T,
    pub points_walk_final_staged: T,
    pub preamble_final_staged: T,
    pub application_stage: T,
    pub application_final_staged: T,
    /// One per bonding of the profile's native extension.
    pub extension_bondings: FixedVec<T, NumExtensionBondings<P>>,
    /// One per segment of a native walk of several segments.
    pub walk_loadings: FixedVec<T, NumWalkLoadings<P>>,
    /// One for a native walk of several segments.
    pub walk_segment_final_staged: FixedVec<T, Split<P>>,
    /// One per band of an opening program run in chunks.
    pub opening_loadings: FixedVec<T, NumOpenBands<P>>,
    /// One for an opening program run in chunks.
    pub opening_final_staged: FixedVec<T, Opened<P>>,
}

impl<T, P: Profile> InternalCircuitValues<T, P> {
    /// Every value with its index, in [`all`](InternalCircuitIndex::all)
    /// order.
    pub fn iter(&self) -> impl Iterator<Item = (InternalCircuitIndex, &T)> {
        InternalCircuitIndex::all::<P>()
            .into_iter()
            .map(move |id| (id, self.get(id)))
    }

    /// Maps every value, in [`all`](InternalCircuitIndex::all) order.
    pub fn try_map<U, E>(
        &self,
        mut f: impl FnMut(InternalCircuitIndex, &T) -> core::result::Result<U, E>,
    ) -> core::result::Result<InternalCircuitValues<U, P>, E> {
        InternalCircuitValues::try_from_fn(|id| f(id, self.get(id)))
    }

    /// Look up the value for the given internal circuit index.
    pub fn get(&self, id: InternalCircuitIndex) -> &T {
        use InternalCircuitIndex::*;
        match id {
            Hashes1Circuit => &self.hashes_1_circuit,
            Hashes2Circuit => &self.hashes_2_circuit,
            CollapseCircuit => &self.collapse_circuit,
            ComputeVCircuit => &self.compute_v_circuit,
            BindChallengesCircuit(k) => &self.bind_challenges_circuits[k as usize],
            BindBetaCircuit => &self.bind_beta_circuit,
            BindEndoscalarCircuit => &self.bind_endoscalar_circuit,
            EndoscalingStep(step) => &self.endoscaling_step_circuits[step as usize],
            ExtensionCircuit(k) => &self.extension_circuits[k as usize],
            PreambleStage => &self.preamble_stage,
            InnerErrorStage => &self.inner_error_stage,
            OuterErrorStage => &self.outer_error_stage,
            QueryStage => &self.query_stage,
            EvalStage => &self.eval_stage,
            PointsBindingStage => &self.points_binding_stage,
            PointsPreambleStage => &self.points_preamble_stage,
            PointsRegistryWxStage => &self.points_registry_wx_stage,
            PointsAbStage => &self.points_ab_stage,
            PointsFStage => &self.points_f_stage,
            PointsWalkStage => &self.points_walk_stage,
            InnerErrorFinalStaged => &self.inner_error_final_staged,
            OuterErrorFinalStaged => &self.outer_error_final_staged,
            EvalFinalStaged => &self.eval_final_staged,
            PointsWalkFinalStaged => &self.points_walk_final_staged,
            PreambleFinalStaged => &self.preamble_final_staged,
            ApplicationStage => &self.application_stage,
            ApplicationFinalStaged => &self.application_final_staged,
            ExtensionBonding(j) => &self.extension_bondings[j as usize],
            WalkLoading(k) => &self.walk_loadings[k as usize],
            WalkSegmentFinalStaged => &self.walk_segment_final_staged[0],
            OpeningLoading(k) => &self.opening_loadings[k as usize],
            OpeningFinalStaged => &self.opening_final_staged[0],
        }
    }

    /// Construct from a closure called once per variant in
    /// [`all`](InternalCircuitIndex::all) order, for profile `P`.
    pub fn from_fn(mut f: impl FnMut(InternalCircuitIndex) -> T) -> Self {
        match Self::try_from_fn(|id| Ok::<_, core::convert::Infallible>(f(id))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`all`](InternalCircuitIndex::all) order, for
    /// profile `P`.
    pub fn try_from_fn<E>(
        mut f: impl FnMut(InternalCircuitIndex) -> core::result::Result<T, E>,
    ) -> core::result::Result<Self, E> {
        use InternalCircuitIndex::*;
        Ok(InternalCircuitValues {
            hashes_1_circuit: f(Hashes1Circuit)?,
            hashes_2_circuit: f(Hashes2Circuit)?,
            collapse_circuit: f(CollapseCircuit)?,
            compute_v_circuit: f(ComputeVCircuit)?,
            bind_challenges_circuits: {
                let mut out = [(); NUM_BINDERS].map(|()| None);
                for (k, slot) in out.iter_mut().enumerate() {
                    *slot = Some(f(BindChallengesCircuit(k as u32))?);
                }
                out.map(|slot| slot.expect("filled"))
            },
            bind_beta_circuit: f(BindBetaCircuit)?,
            bind_endoscalar_circuit: f(BindEndoscalarCircuit)?,
            endoscaling_step_circuits: try_fixed_vec(|step| f(EndoscalingStep(step as u32)))?,
            extension_circuits: try_fixed_vec(|k| f(ExtensionCircuit(k as u32)))?,
            preamble_stage: f(PreambleStage)?,
            inner_error_stage: f(InnerErrorStage)?,
            outer_error_stage: f(OuterErrorStage)?,
            query_stage: f(QueryStage)?,
            eval_stage: f(EvalStage)?,
            points_binding_stage: f(PointsBindingStage)?,
            points_preamble_stage: f(PointsPreambleStage)?,
            points_registry_wx_stage: f(PointsRegistryWxStage)?,
            points_ab_stage: f(PointsAbStage)?,
            points_f_stage: f(PointsFStage)?,
            points_walk_stage: f(PointsWalkStage)?,
            inner_error_final_staged: f(InnerErrorFinalStaged)?,
            outer_error_final_staged: f(OuterErrorFinalStaged)?,
            eval_final_staged: f(EvalFinalStaged)?,
            points_walk_final_staged: f(PointsWalkFinalStaged)?,
            preamble_final_staged: f(PreambleFinalStaged)?,
            application_stage: f(ApplicationStage)?,
            application_final_staged: f(ApplicationFinalStaged)?,
            extension_bondings: try_fixed_vec(|j| f(ExtensionBonding(j as u32)))?,
            walk_loadings: try_fixed_vec(|k| f(WalkLoading(k as u32)))?,
            walk_segment_final_staged: try_fixed_vec(|_| f(WalkSegmentFinalStaged))?,
            opening_loadings: try_fixed_vec(|k| f(OpeningLoading(k as u32)))?,
            opening_final_staged: try_fixed_vec(|_| f(OpeningFinalStaged))?,
        })
    }
}

/// Enum identifying which rx polynomial component to index within [`RxValues`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RxIndex {
    // Circuits
    Hashes1,
    Hashes2,
    Collapse,
    ComputeV,
    /// A nested challenge binding circuit's rx polynomial.
    BindChallenges(u32),
    /// The nested beta binding circuit's rx polynomial.
    BindBeta,
    /// The endoscalar binding circuit's rx polynomial.
    BindEndoscalar,
    /// A native endoscaling step's rx polynomial.
    EndoscalingStep(u32),
    /// The rx polynomial of a circuit of the profile's native extension.
    ExtensionCircuit(u32),
    // Stages
    Preamble,
    InnerError,
    OuterError,
    Query,
    Eval,
    /// The points stage holding the children's commitments that must match
    /// their native unified instances (see [`stages::points`]).
    PointsBinding,
    /// The points stage holding the rest of the children's commitments and
    /// the step's own online Fq commitments.
    PointsPreamble,
    /// The points stage holding the nested `registry_wx` commitments.
    PointsRegistryWx,
    /// The points stage holding the nested `registry_wy` commitment, $A_n$
    /// and $B_n$.
    PointsAb,
    /// The points stage holding the nested `registry_xy` commitment and
    /// $F_n$.
    PointsF,
    /// The walk's stage: the endoscalar's bits and the interstitials.
    PointsWalk,
    /// The rx polynomial of a stage of the profile's native extension.
    ExtensionStage(u32),
}

impl RxIndex {
    /// The number of rx polynomial components.
    pub const NUM: usize = NUM_FIXED_RX + NUM_ENDOSCALING_STEPS;

    /// All variants in canonical order.
    ///
    /// This order matches the evaluation order in `poly_queries` (compute_v.rs)
    /// and `_08_f.rs`, and drives the `Write` impl for `RxValues`. This is the
    /// standard profile's list; [`all`](Self::all) resizes its walk and adds
    /// the extension for any other.
    pub const ALL: [Self; Self::NUM] = super::const_fns::unwrap_all(Self::all_slots());

    const fn all_slots() -> [Option<Self>; Self::NUM] {
        use super::const_fns::push;

        let mut slots = [None; Self::NUM];
        let mut c = 0;
        push(&mut slots, &mut c, Self::Hashes1);
        push(&mut slots, &mut c, Self::Hashes2);
        push(&mut slots, &mut c, Self::Collapse);
        push(&mut slots, &mut c, Self::ComputeV);
        {
            let mut k = 0;
            while k < NUM_BINDERS {
                push(&mut slots, &mut c, Self::BindChallenges(k as u32));
                k += 1;
            }
        }
        push(&mut slots, &mut c, Self::BindBeta);
        push(&mut slots, &mut c, Self::BindEndoscalar);
        {
            let mut step = 0;
            while step < NUM_ENDOSCALING_STEPS {
                push(&mut slots, &mut c, Self::EndoscalingStep(step as u32));
                step += 1;
            }
        }
        push(&mut slots, &mut c, Self::Preamble);
        push(&mut slots, &mut c, Self::InnerError);
        push(&mut slots, &mut c, Self::OuterError);
        push(&mut slots, &mut c, Self::Query);
        push(&mut slots, &mut c, Self::Eval);
        push(&mut slots, &mut c, Self::PointsBinding);
        push(&mut slots, &mut c, Self::PointsPreamble);
        push(&mut slots, &mut c, Self::PointsRegistryWx);
        push(&mut slots, &mut c, Self::PointsAb);
        push(&mut slots, &mut c, Self::PointsF);
        push(&mut slots, &mut c, Self::PointsWalk);
        assert!(c == Self::NUM);
        slots
    }

    /// The number of rx polynomial components in profile `P`.
    pub fn num<P: Profile>() -> usize {
        Shape::of::<P>().native_rx
    }

    /// All variants in canonical order, for profile `P`: [`ALL`](Self::ALL)
    /// with the walk resized to the profile's steps, then the profile's
    /// extension circuits' and stages' polynomials.
    /// The index tests compare this order with [`Self::position`].
    pub fn all<P: Profile>() -> Vec<Self> {
        let extension = crate::profile::native_extension::<P>();
        let all = Self::all_with(
            NumSteps::<P>::len(),
            extension.circuits.len(),
            extension.stages,
        );
        assert_eq!(all.len(), Self::num::<P>());
        all
    }

    /// [`ALL`](Self::ALL) with the walk resized to `num_steps` steps, then
    /// `circuits` extension circuits' and `stages` extension stages'
    /// polynomials.
    pub(crate) fn all_with(num_steps: usize, circuits: usize, stages: usize) -> Vec<Self> {
        let mut all = Vec::with_capacity(NUM_FIXED_RX + num_steps + circuits + stages);
        for &id in &Self::ALL {
            match id {
                Self::EndoscalingStep(0) => {
                    all.extend((0..num_steps as u32).map(Self::EndoscalingStep))
                }
                Self::EndoscalingStep(_) => {}
                id => all.push(id),
            }
        }
        all.extend((0..circuits as u32).map(Self::ExtensionCircuit));
        all.extend((0..stages as u32).map(Self::ExtensionStage));
        all
    }
}

impl RxIndex {
    /// The position of `self` in [`all`](Self::all), for profile `P`.
    pub fn position<P: Profile>(self) -> usize {
        use RxIndex::*;
        let steps = NumSteps::<P>::len();
        let endoscaling = 6 + NUM_BINDERS;
        let stages = endoscaling + steps;
        match self {
            Hashes1 => 0,
            Hashes2 => 1,
            Collapse => 2,
            ComputeV => 3,
            BindChallenges(i) => 4 + super::checked_index(i, NUM_BINDERS),
            BindBeta => 4 + NUM_BINDERS,
            BindEndoscalar => 5 + NUM_BINDERS,
            EndoscalingStep(i) => endoscaling + super::checked_index(i, steps),
            Preamble => stages,
            InnerError => stages + 1,
            OuterError => stages + 2,
            Query => stages + 3,
            Eval => stages + 4,
            PointsBinding => stages + 5,
            PointsPreamble => stages + 6,
            PointsRegistryWx => stages + 7,
            PointsAb => stages + 8,
            PointsF => stages + 9,
            PointsWalk => stages + 10,
            ExtensionCircuit(i) => {
                stages
                    + 11
                    + super::checked_index(
                        i,
                        crate::profile::extension_lengths::<P>(false).circuits,
                    )
            }
            ExtensionStage(i) => {
                stages
                    + 11
                    + crate::profile::extension_lengths::<P>(false).circuits
                    + super::checked_index(i, crate::profile::extension_lengths::<P>(false).stages)
            }
        }
    }
}

/// Per-rx-component storage indexed by [`RxIndex`].
///
/// Each field corresponds 1:1 to a variant of [`RxIndex`].
/// Use [`get`](Self::get) to look up by variant, and
/// [`try_from_fn`](Self::try_from_fn) to construct from a closure.
#[derive(Clone)]
pub struct RxValues<T, P: Profile> {
    pub hashes_1: T,
    pub hashes_2: T,
    pub collapse: T,
    pub compute_v: T,
    pub bind_challenges: [T; NUM_BINDERS],
    pub bind_beta: T,
    pub bind_endoscalar: T,
    /// One per endoscaling step of the profile the values were built for.
    pub endoscaling_steps: FixedVec<T, NumSteps<P>>,
    pub preamble: T,
    pub inner_error: T,
    pub outer_error: T,
    pub query: T,
    pub eval: T,
    pub points_binding: T,
    pub points_preamble: T,
    pub points_registry_wx: T,
    pub points_ab: T,
    pub points_f: T,
    pub points_walk: T,
    /// One per circuit of the profile's native extension.
    pub extension_circuits: FixedVec<T, NumExtensionCircuits<P>>,
    /// One per stage of the profile's native extension.
    pub extension_stages: FixedVec<T, NumExtensionStages<P>>,
}

impl<T, P: Profile> RxValues<T, P> {
    /// Every value with its index, in [`all`](RxIndex::all) order.
    pub fn iter(&self) -> impl Iterator<Item = (RxIndex, &T)> {
        RxIndex::all::<P>()
            .into_iter()
            .map(move |id| (id, self.get(id)))
    }

    /// Maps every value, in [`all`](RxIndex::all) order.
    pub fn try_map<U, E>(
        &self,
        mut f: impl FnMut(RxIndex, &T) -> core::result::Result<U, E>,
    ) -> core::result::Result<RxValues<U, P>, E> {
        RxValues::try_from_fn(|id| f(id, self.get(id)))
    }

    /// Look up the value for the given rx index.
    pub fn get(&self, id: RxIndex) -> &T {
        use RxIndex::*;
        match id {
            Hashes1 => &self.hashes_1,
            Hashes2 => &self.hashes_2,
            Collapse => &self.collapse,
            ComputeV => &self.compute_v,
            BindChallenges(k) => &self.bind_challenges[k as usize],
            BindBeta => &self.bind_beta,
            BindEndoscalar => &self.bind_endoscalar,
            EndoscalingStep(step) => &self.endoscaling_steps[step as usize],
            Preamble => &self.preamble,
            InnerError => &self.inner_error,
            OuterError => &self.outer_error,
            Query => &self.query,
            Eval => &self.eval,
            PointsBinding => &self.points_binding,
            PointsPreamble => &self.points_preamble,
            PointsRegistryWx => &self.points_registry_wx,
            PointsAb => &self.points_ab,
            PointsF => &self.points_f,
            PointsWalk => &self.points_walk,
            ExtensionCircuit(k) => &self.extension_circuits[k as usize],
            ExtensionStage(k) => &self.extension_stages[k as usize],
        }
    }

    /// Construct from a closure called once per variant in
    /// [`all`](RxIndex::all) order, for profile `P`.
    pub fn from_fn(mut f: impl FnMut(RxIndex) -> T) -> Self {
        match Self::try_from_fn(|id| Ok::<_, core::convert::Infallible>(f(id))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`all`](RxIndex::all) order, for profile `P`.
    pub fn try_from_fn<E>(
        mut f: impl FnMut(RxIndex) -> core::result::Result<T, E>,
    ) -> core::result::Result<Self, E> {
        use RxIndex::*;
        Ok(RxValues {
            hashes_1: f(Hashes1)?,
            hashes_2: f(Hashes2)?,
            collapse: f(Collapse)?,
            compute_v: f(ComputeV)?,
            bind_challenges: {
                let mut out = [(); NUM_BINDERS].map(|()| None);
                for (k, slot) in out.iter_mut().enumerate() {
                    *slot = Some(f(BindChallenges(k as u32))?);
                }
                out.map(|slot| slot.expect("filled"))
            },
            bind_beta: f(BindBeta)?,
            bind_endoscalar: f(BindEndoscalar)?,
            endoscaling_steps: try_fixed_vec(|step| f(EndoscalingStep(step as u32)))?,
            preamble: f(Preamble)?,
            inner_error: f(InnerError)?,
            outer_error: f(OuterError)?,
            query: f(Query)?,
            eval: f(Eval)?,
            points_binding: f(PointsBinding)?,
            points_preamble: f(PointsPreamble)?,
            points_registry_wx: f(PointsRegistryWx)?,
            points_ab: f(PointsAb)?,
            points_f: f(PointsF)?,
            points_walk: f(PointsWalk)?,
            extension_circuits: try_fixed_vec(|k| f(ExtensionCircuit(k as u32)))?,
            extension_stages: try_fixed_vec(|k| f(ExtensionStage(k as u32)))?,
        })
    }
}

/// Identifies a native-field polynomial within a proof — either one of the
/// two AB polynomials (which are not rx polynomials) or one of the rx
/// polynomials addressed by [`RxIndex`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxComponent {
    /// The `a` polynomial from the AB proof (revdot claim).
    AbA,
    /// The `b` polynomial from the AB proof (revdot claim).
    AbB,
    /// An rx polynomial component indexed by [`RxIndex`].
    Rx(RxIndex),
}

/// Registers internal native circuits and masks into the provided registry.
///
/// Does not register internal steps (rerandomize, bootstrap); those are
/// registered by the caller after this function returns.
///
/// `stage_size` is the application stage's size in values, the largest any
/// registered step stages, which fixes the layout of the application masks.
pub fn register_all<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize>(
    mut registry: RegistryBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
    stage_size: usize,
    source_tag: Option<C::CircuitField>,
    source_domain: Option<u32>,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>> {
    C::Profile::check()?;
    let initial_internal_circuits = registry.num_internal_circuits();
    // The application stage follows the SYSTEM gate in every step circuit.
    let stage_gates = ragu_circuits::staging::stage_gates(stage_size);

    let extension = crate::profile::native_extension::<C::Profile>();
    let mut extension_circuits = alloc::vec::Vec::with_capacity(extension.circuits.len());
    let mut extension_bondings = alloc::vec::Vec::with_capacity(extension.bondings());
    // How the opening program is shared between its chunks, for a profile
    // that runs it in chunks.
    let opening = is_opening_chunked::<C::Profile>()
        .then(|| alloc::sync::Arc::new(open::Schedule::of::<C::Profile>()));
    for id in InternalCircuitIndex::all::<C::Profile>() {
        use InternalCircuitIndex::*;
        registry = match id {
            ExtensionCircuit(k) if builtin_circuit::<C::Profile>(k as usize).is_some() => {
                // A circuit of the fuse's own: it ends its output with the
                // zero suffix itself and loads no stage of the extension.
                extension_circuits.push(crate::profile::Registration::Circuit);
                match builtin_circuit::<C::Profile>(k as usize).expect("checked above") {
                    BuiltinCircuit::FoldInner(chunk) => {
                        registry.register_internal_circuit(circuits::fold_inner::Circuit::<
                            C,
                            R,
                            HEADER_SIZE,
                            RevdotParameters<C::Profile>,
                        >::new(chunk))?
                    }
                    BuiltinCircuit::FoldOuter => {
                        registry.register_internal_circuit(circuits::fold_outer::Circuit::<
                            C,
                            R,
                            HEADER_SIZE,
                            RevdotParameters<C::Profile>,
                        >::new())?
                    }
                    BuiltinCircuit::Open(chunk) => registry.register_internal_circuit(
                        circuits::open::Circuit::<C, R, HEADER_SIZE>::new(
                            chunk,
                            opening.clone().expect("a profile with opening chunks"),
                        ),
                    )?,
                }
            }
            ExtensionCircuit(k) => {
                use crate::profile::online::stages::{self as extension, Native};
                let slot = CircuitSlot::new(registry);
                let (registry, registration) =
                    if Some(k) == extension::helper::<C::Profile, Native>() {
                        extension::register_circuit::<_, R, C::Profile, Native>(
                            slot,
                            source_tag,
                            source_domain,
                        )?
                    } else {
                        C::Profile::register_native_circuit::<C::Base, R, HEADER_SIZE>(
                            k as usize, slot, params,
                        )?
                    }
                    .into_parts();
                extension_circuits.push(registration);
                registry
            }
            ExtensionBonding(j) => {
                use crate::profile::online::stages::{self as extension, Native};
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
                        BuiltinStage::WalkBits => slot.register_mask::<stages::points::BitsStage<
                            C::NestedCurve,
                            C::Profile,
                        >>()?,
                        BuiltinStage::WalkSegment(_) => slot
                            .register_mask::<stages::points::SegmentStage<
                                C::NestedCurve,
                                C::Profile,
                            >>()?,
                        BuiltinStage::WalkBoundaries => slot
                            .register_mask::<stages::points::BoundariesStage<
                                C::NestedCurve,
                                C::Profile,
                            >>()?,
                        BuiltinStage::FoldTargets => slot.register_mask::<stages::targets::Stage<
                            C,
                            R,
                            HEADER_SIZE,
                            RevdotParameters<C::Profile>,
                        >>()?,
                        BuiltinStage::OpenCarry => {
                            slot.register_mask::<stages::open::CarryStage<C, R, HEADER_SIZE>>()?
                        }
                        BuiltinStage::OpenBand(_) => {
                            slot.register_mask::<stages::open::BandStage<C, R, HEADER_SIZE>>()?
                        }
                    }
                } else {
                    let index = if j < declared { j } else { j - builtin };
                    match extension::bonding::<C::Profile, Native>(index)? {
                        extension::Bonding::Online(bonding) => {
                            bonding.register::<_, R, C::Profile, Native>(slot)?
                        }
                        extension::Bonding::User(index) => {
                            C::Profile::register_native_bonding::<C::Base, R, HEADER_SIZE>(
                                index, slot, params,
                            )?
                        }
                    }
                };
                let (registry, registration) = registered.into_parts();
                extension_bondings.push(registration);
                registry
            }
            WalkLoading(segment) => {
                let circuit = circuits::walk_loading::Circuit::<C, R>::new(segment as usize);
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
            WalkSegmentFinalStaged => registry.register_bonding(<stages::points::SegmentStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::final_mask(
            )?),
            OpeningLoading(band) => {
                let circuit = circuits::open_loading::Circuit::<C, R, HEADER_SIZE>::new(
                    band as usize,
                    opening.clone().expect("a profile with opening chunks"),
                );
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
            OpeningFinalStaged => registry.register_bonding(<stages::open::BandStage<
                C,
                R,
                HEADER_SIZE,
            > as StageExt<C::CircuitField, R>>::final_mask(
            )?),
            PreambleStage => {
                registry.register_bonding(stages::preamble::Stage::<C, R, HEADER_SIZE>::mask()?)
            }
            ApplicationStage => {
                registry.register_bonding(ragu_circuits::staging::stage_mask(1, stage_gates)?)
            }
            ApplicationFinalStaged => registry
                .register_bonding(ragu_circuits::staging::final_stage_mask(1 + stage_gates)?),
            InnerErrorStage => registry.register_bonding(stages::inner_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters<C::Profile>,
            >::mask()?),
            OuterErrorStage => registry.register_bonding(stages::outer_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters<C::Profile>,
            >::mask()?),
            QueryStage => {
                registry.register_bonding(stages::query::Stage::<C, R, HEADER_SIZE>::mask()?)
            }
            EvalStage => {
                registry.register_bonding(stages::eval::Stage::<C, R, HEADER_SIZE>::mask()?)
            }
            InnerErrorFinalStaged => registry.register_bonding(stages::inner_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters<C::Profile>,
            >::final_mask()?),
            OuterErrorFinalStaged => registry.register_bonding(stages::outer_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters<C::Profile>,
            >::final_mask()?),
            EvalFinalStaged => {
                registry.register_bonding(stages::eval::Stage::<C, R, HEADER_SIZE>::final_mask()?)
            }
            PreambleFinalStaged => {
                registry
                    .register_bonding(stages::preamble::Stage::<C, R, HEADER_SIZE>::final_mask()?)
            }
            PointsBindingStage => registry.register_bonding(<stages::points::BindingStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsPreambleStage => registry.register_bonding(<stages::points::PreambleStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsRegistryWxStage => registry.register_bonding(<stages::points::RegistryWxStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsAbStage => registry.register_bonding(<stages::points::AbStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsFStage => registry.register_bonding(<stages::points::FStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsWalkStage => registry.register_bonding(<stages::points::WalkStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsWalkFinalStaged => registry.register_bonding(<stages::points::WalkStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::final_mask(
            )?),
            BindEndoscalarCircuit => registry
                .register_internal_circuit(circuits::bind_endoscalar::Circuit::<C, R>::new())?,
            EndoscalingStep(step) => {
                if segments::<C::Profile>().is_split() {
                    registry.register_internal_circuit(
                        circuits::segment_step::Circuit::<C, R>::new(step as usize),
                    )?
                } else {
                    registry.register_internal_circuit(
                        circuits::endoscaling_step::Circuit::<C, R>::new(step as usize),
                    )?
                }
            }
            Hashes1Circuit => {
                registry.register_internal_circuit(circuits::hashes_1::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    RevdotParameters<C::Profile>,
                >::new(params, log2_circuits))?
            }
            Hashes2Circuit => registry.register_internal_circuit(circuits::hashes_2::Circuit::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters<C::Profile>,
            >::new(params))?,
            CollapseCircuit => {
                if is_fold_chunked::<C::Profile>() {
                    registry.register_internal_circuit(circuits::collapse::Targets::<
                        C,
                        R,
                        HEADER_SIZE,
                        RevdotParameters<C::Profile>,
                    >::new())?
                } else {
                    registry.register_internal_circuit(circuits::collapse::Circuit::<
                        C,
                        R,
                        HEADER_SIZE,
                        RevdotParameters<C::Profile>,
                    >::new())?
                }
            }
            ComputeVCircuit => match &opening {
                Some(schedule) => registry.register_internal_circuit(
                    circuits::open_base::Circuit::<C, R, HEADER_SIZE>::new(schedule.clone()),
                )?,
                None => registry.register_internal_circuit(circuits::compute_v::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                >::new())?,
            },
            BindChallengesCircuit(k) => {
                crate::with_binder!(k, C, R, HEADER_SIZE, params, |circuit| {
                    registry.register_internal_circuit(circuit)?
                })
            }
            BindBetaCircuit => {
                registry.register_internal_circuit(circuits::bind_beta::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                >::new(params))?
            }
        };
    }
    extension.check_registered("native", &extension_circuits, &extension_bondings)?;

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
        assert_eq!(
            num_claims::<P>(),
            2 + 1 + 2 * circuits + all.len() - circuits
        );
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
        check::<crate::profile::testing::Segmented>();
        check::<crate::profile::testing::Chunked>();
    }

    /// A fold verified in chunks names its circuits and its stage as the
    /// last of the native extension's, and its chunks share the fold's
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
        assert_eq!(num_fold_polynomials(0), 0);

        // A walk of several segments keeps its stages before the fold's.
        type S = crate::profile::testing::Segmented;
        let stages = NumExtensionStages::<S>::len();
        assert_eq!(
            builtin_stage::<S>(stages - 1),
            Some(BuiltinStage::WalkBoundaries)
        );
        assert_eq!(
            builtin_stage::<S>(walk_stage_offset::<S>()),
            Some(BuiltinStage::WalkBits)
        );
        assert_eq!(
            builtin_stage::<S>(walk_stage_offset::<S>() + 1),
            Some(BuiltinStage::WalkSegment(0))
        );
    }

    /// A walk of several segments names a polynomial per stage it adds, the
    /// last stages of the native extension, and a bonding per segment and
    /// one for its steps' final mask, the last of the internal circuits.
    #[test]
    fn a_segmented_walk_names_its_polynomials() {
        type P = crate::profile::testing::Segmented;
        let walk = segments::<P>();
        assert!(walk.is_split());
        let stages = NumExtensionStages::<P>::len();
        assert_eq!(
            stages,
            walk_stage_offset::<P>() + num_walk_stages(walk.count())
        );
        assert_eq!(
            walk_bits_rx::<P>(),
            RxIndex::ExtensionStage(walk_stage_offset::<P>() as u32)
        );
        assert_eq!(
            boundaries_rx::<P>(),
            RxIndex::ExtensionStage(stages as u32 - 1)
        );
        let named: Vec<_> = (0..walk.count()).map(segment_rx::<P>).collect();
        assert_eq!(named.len(), walk.count());
        assert!(named.windows(2).all(|pair| pair[0] != pair[1]));
        assert!(!named.contains(&walk_bits_rx::<P>()));
        assert!(!named.contains(&boundaries_rx::<P>()));

        let all = InternalCircuitIndex::all::<P>();
        let loadings = all
            .iter()
            .filter(|id| matches!(id, InternalCircuitIndex::WalkLoading(_)))
            .count();
        assert_eq!(loadings, walk.count());
        assert_eq!(
            all.last(),
            Some(&InternalCircuitIndex::WalkSegmentFinalStaged)
        );

        // A walk of one segment adds none of them.
        assert!(!segments::<Standard>().is_split());
        assert!(
            InternalCircuitIndex::all::<Standard>()
                .iter()
                .all(|id| !matches!(
                    id,
                    InternalCircuitIndex::WalkLoading(_)
                        | InternalCircuitIndex::WalkSegmentFinalStaged
                ))
        );
    }
}
