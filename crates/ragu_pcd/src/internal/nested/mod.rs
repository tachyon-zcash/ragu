//! Nested field circuits for the scalar field.
//!
//! Contains these circuits:
//!
//! - **Endoscaling**: verifies that the commitment accumulation
//!   in `compute_p` was computed correctly via Horner's rule.
//! - **Collapse**: pins the nested [`unified`] instance to its stages,
//!   holds the [`PointsStage`] inputs to the bridge stage commitments of the
//!   current step, and verifies both layers of the children's nested fold.
//! - **Compute v**: recomputes the nested batch evaluation $v_n$, the mirror
//!   of the native `compute_v`.
//!
//! The collapse and compute-v circuits share the [`unified`]
//! instance as their public input, each constraining the slots it owns.
//! Both load every nested stage. A relation between two stages belongs in
//! collapse, which also holds the stages' contracts.
//!
//! A profile with a large extension cannot load every stage in one circuit
//! ([`paged`]). It lays the stages side by side ([`layout`]), cuts its walk
//! into groups ([`walk_grouping`]) and checks what collapse and compute-v
//! check with a program of step circuits and two instance circuits
//! ([`circuits::paged`]).
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
    extract_endoscalar, lift_endoscalar,
    vec::{ConstLen, Len},
};
use udon::field::Field;

pub mod circuits {
    pub mod collapse;
    pub mod common;
    pub mod compute_v;
    pub mod paged;
}

use crate::{
    internal::{endoscalar, paging, program, revdot::Parameters},
    profile::{CircuitSlot, MaskSlot, Profile, ProfiledCycle, Shape},
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

/// Length type for the steps one group of the nested walk holds in profile
/// `P` ([`Profile::NESTED_WALK_GROUP`]): zero for a walk in one stage.
pub struct WalkGroup<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for WalkGroup<P> {
    fn len() -> usize {
        P::NESTED_WALK_GROUP
    }
}

/// The grouping of the nested walk in profile `P`.
pub fn walk_grouping<P: Profile>() -> paging::Grouping {
    endoscalar::grouping::<NumPoints<P>, Endoscalings<P>, WalkGroup<P>>()
}

/// Whether profile `P` lays its nested stages side by side ([`layout`])
/// and checks its instance with a program of step circuits
/// ([`circuits::paged`]): a profile that cuts its walk into groups
/// ([`Profile::NESTED_WALK_GROUP`]).
pub fn paged<P: Profile>() -> bool {
    P::NESTED_WALK_GROUP != 0
}

/// The stage polynomials a paged profile adds for a walk of `steps` steps
/// at `per_group` steps a group: a points stage for every group after the
/// first, the links stage and the memory stage. None for a profile that
/// is not paged.
pub const fn num_paged_stages(steps: usize, per_group: usize) -> usize {
    if per_group == 0 {
        0
    } else {
        steps.div_ceil(per_group) + 1
    }
}

/// The step circuits of a paged profile's program for a walk of `steps`
/// steps at `per_group` steps a group: the `fixed` steps the profile pins
/// ([`Profile::NESTED_STEPS`]) and a step for every group of the walk. None
/// for a profile that is not paged.
pub const fn num_paged_steps(steps: usize, per_group: usize, fixed: usize) -> usize {
    if per_group == 0 {
        0
    } else {
        fixed + steps.div_ceil(per_group)
    }
}

/// Length type for the stage polynomials profile `P` adds if it is paged
/// ([`num_paged_stages`]).
pub struct NumPagedStages<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumPagedStages<P> {
    fn len() -> usize {
        num_paged_stages(NumSteps::<P>::len(), P::NESTED_WALK_GROUP)
    }
}

/// Length type for the step circuits of the program of profile `P`
/// ([`num_paged_steps`]): the length of
/// [`schedule`](circuits::paged::schedule), which [`register_all`] checks.
pub struct NumProgramSteps<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumProgramSteps<P> {
    fn len() -> usize {
        num_paged_steps(NumSteps::<P>::len(), P::NESTED_WALK_GROUP, P::NESTED_STEPS)
    }
}

/// The masks a paged profile adds: the links and memory stages' masks and
/// the final masks of the circuits whose last stage is the `outer_error`,
/// the `query` or the `eval` stage.
pub const NUM_PAGED_MASKS: usize = 5;

/// The memory stage of a paged profile's program, the last stage of the
/// layout's trunk.
pub type MemoryStage<C, R, P> =
    program::MemoryStage<circuits::paged::Cells<P>, C, stages::challenges::Stage<C, R, P>>;

/// The nested points stage, over the native batch's commitments, for host
/// curve `C` in profile `P`: one group of the walk, the whole walk for a
/// profile that does not group it.
pub type PointsStage<C, P> = endoscalar::PointsStage<
    C,
    NumPoints<P>,
    Endoscalings<P>,
    stages::bridge_hash::Stage<C>,
    WalkGroup<P>,
>;

/// The nested links stage, which chains the groups of a grouped walk and
/// holds nothing otherwise.
pub type LinksStage<C, P> = endoscalar::LinksStage<
    C,
    NumPoints<P>,
    Endoscalings<P>,
    stages::bridge_hash::Stage<C>,
    WalkGroup<P>,
>;

/// The witness of the whole nested walk: every group and the links.
pub type WalkWitness<C, P> =
    endoscalar::WalkWitness<C, NumPoints<P>, Endoscalings<P>, WalkGroup<P>>;

/// The nested points stage's output gadget.
pub type Points<'dr, D, C, P> =
    endoscalar::Points<'dr, D, C, NumPoints<P>, Endoscalings<P>, WalkGroup<P>>;

/// The nested links stage's output gadget.
pub type Links<'dr, D, C, P> =
    endoscalar::Links<'dr, D, C, NumPoints<P>, Endoscalings<P>, WalkGroup<P>>;

/// A nested endoscaling step.
pub type EndoscalingStep<C, R, P> = endoscalar::EndoscalingStep<
    C,
    R,
    NumPoints<P>,
    Endoscalings<P>,
    stages::bridge_hash::Stage<C>,
    WalkGroup<P>,
>;

/// A nested endoscaling step's witness.
pub type EndoscalingStepWitness<'source, C, P> =
    endoscalar::EndoscalingStepWitness<'source, C, NumPoints<P>, Endoscalings<P>, WalkGroup<P>>;

/// The number of circuits whose public input is the nested [`unified`]
/// instance: collapse and compute-v.
pub const NUM_INSTANCE_CIRCUITS: usize = 2;

/// The nested rx polynomials that are not endoscaling steps: the instance
/// circuits', the endoscalar and points stages', the nine bridge stages'
/// and the challenge stage's.
pub const NUM_FIXED_RX: usize = NUM_INSTANCE_CIRCUITS + 12;

/// The nested internal circuits that are not endoscaling steps: the rx
/// polynomials' circuits and stages, and the two final stage masks.
pub const NUM_FIXED_INTERNAL: usize = NUM_FIXED_RX + 2;

/// The masks among them: every one but the instance circuits.
pub const NUM_FIXED_MASKS: usize = NUM_FIXED_INTERNAL - NUM_INSTANCE_CIRCUITS;

/// The minimum groups for the nested quotient fold: eleven groups with
/// eight claims each provide room for 88 claims, and the twelfth holds the
/// randomizer's half-claim (see
/// [`revdot`](crate::internal::revdot#the-randomizer)). Larger
/// profiles grow the group count.
pub const NUM_FOLD_GROUPS: usize = 12;

/// The nodes of a nested fold group: eight claims and the randomizer's.
pub const FOLD_GROUP_SIZE: usize = 9;

/// The nested revdot claims of profile `P` the fuse folds: two children's
/// raw claims, each internal circuit's claim per child, and each mask's
/// claim across both.
pub fn num_claims<P: Profile>() -> usize {
    let extension = crate::profile::extension_lengths::<P>(true);
    let paged_masks = if paged::<P>() { NUM_PAGED_MASKS } else { 0 };
    let circuits = 2 + NumSteps::<P>::len() + extension.circuits + NumProgramSteps::<P>::len();
    let masks = NUM_FIXED_MASKS + extension.masks + paged_masks;
    2 + 2 * circuits + masks
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
    /// A step circuit of a paged profile's program, at its position in
    /// [`schedule`](circuits::paged::schedule).
    Step(u32),
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
    /// Final staged mask of the instance circuits and of the circuits
    /// that end on the same stage: the challenge stage, or the `preamble`
    /// stage in a paged profile.
    ChallengeFinalStaged,
    /// A mask of the profile's nested extension, a stage mask or a final
    /// mask, in [`Extension::masks`](crate::profile::Extension::masks)
    /// order.
    ExtensionMask(u32),
    /// The links stage's mask, in a paged profile.
    LinksStage,
    /// The memory stage's mask, in a paged profile.
    MemoryStage,
    /// Final staged mask of a paged profile's circuits whose last stage is
    /// the `outer_error` stage.
    ErrorsFinalStaged,
    /// Final staged mask of a paged profile's circuits whose last stage is
    /// the `query` stage.
    QueryFinalStaged,
    /// Final staged mask of a paged profile's circuits whose last stage is
    /// the `eval` stage.
    EvalFinalStaged,
}

impl InternalCircuitIndex {
    /// The masks a paged profile adds, in registration order.
    pub const PAGED_MASKS: [Self; NUM_PAGED_MASKS] = [
        Self::LinksStage,
        Self::MemoryStage,
        Self::ErrorsFinalStaged,
        Self::QueryFinalStaged,
        Self::EvalFinalStaged,
    ];

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
        assert!(c == Self::NUM);
        slots
    }

    /// The number of internal circuits registered by [`register_all`] in
    /// profile `P`, equal to the length of [`all`](Self::all).
    pub fn num<P: Profile>() -> usize {
        // A paged profile adds its program's steps and its masks.
        let paged = if paged::<P>() {
            NumProgramSteps::<P>::len() + NUM_PAGED_MASKS
        } else {
            0
        };
        NumSteps::<P>::len()
            + NUM_FIXED_INTERNAL
            + crate::profile::nested_extension::<P>().internal()
            + paged
    }

    /// All variants in canonical iteration order, for profile `P`:
    /// [`ALL`](Self::ALL) with the walk resized to the profile's steps, the
    /// profile's extension circuits after the instance circuits and its
    /// masks last. A paged profile's step circuits follow the extension's
    /// circuits and its masks follow the extension's masks.
    /// The index tests compare this order with [`Self::circuit_index`].
    pub fn all<P: Profile>() -> Vec<Self> {
        let num_steps = NumSteps::<P>::len();
        let extension = crate::profile::nested_extension::<P>();
        let program_steps = NumProgramSteps::<P>::len();
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
                    all.extend((0..program_steps as u32).map(Self::Step));
                }
                id => all.push(id),
            }
        }
        all.extend((0..extension.masks() as u32).map(Self::ExtensionMask));
        if paged::<P>() {
            all.extend(Self::PAGED_MASKS);
        }
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
        let program_steps = NumProgramSteps::<P>::len();
        let mask = steps + 2 + extension.circuits + program_steps;
        let pos = match self {
            EndoscalingStep(i) => super::checked_index(i, steps),
            Collapse => steps,
            ComputeV => steps + 1,
            ExtensionCircuit(i) => steps + 2 + super::checked_index(i, extension.circuits),
            Step(i) => steps + 2 + extension.circuits + super::checked_index(i, program_steps),
            LinksStage | MemoryStage | ErrorsFinalStaged | QueryFinalStaged | EvalFinalStaged => {
                assert!(paged::<P>(), "index is outside the profile");
                let position = Self::PAGED_MASKS
                    .iter()
                    .position(|&mask| mask == self)
                    .expect("a paged profile's mask");
                mask + NUM_FIXED_MASKS + extension.masks + position
            }
            EndoscalarStage => mask,
            PointsStage => mask + 1,
            PointsFinalStaged => mask + 2,
            BridgePreamble => mask + 3,
            BridgeHash => mask + 4,
            BridgeSPrime => mask + 5,
            BridgeInnerError => mask + 6,
            BridgeOuterError => mask + 7,
            BridgeAB => mask + 8,
            BridgeQuery => mask + 9,
            BridgeF => mask + 10,
            BridgeEval => mask + 11,
            ChallengeStage => mask + 12,
            ChallengeFinalStaged => mask + 13,
            ExtensionMask(i) => mask + NUM_FIXED_MASKS + super::checked_index(i, extension.masks),
        };
        CircuitIndex::new(pos)
    }

    /// The stage whose mask `self` is, and `None` for a circuit, a final
    /// mask or an extension's mask.
    pub fn stage(self) -> Option<RxIndex> {
        Some(match self {
            Self::EndoscalarStage => RxIndex::EndoscalarStage,
            Self::PointsStage => RxIndex::PointsStage,
            Self::LinksStage => RxIndex::LinksStage,
            Self::MemoryStage => RxIndex::MemoryStage,
            Self::BridgePreamble => RxIndex::BridgePreamble,
            Self::BridgeHash => RxIndex::BridgeHash,
            Self::BridgeSPrime => RxIndex::BridgeSPrime,
            Self::BridgeInnerError => RxIndex::BridgeInnerError,
            Self::BridgeOuterError => RxIndex::BridgeOuterError,
            Self::BridgeAB => RxIndex::BridgeAB,
            Self::BridgeQuery => RxIndex::BridgeQuery,
            Self::BridgeF => RxIndex::BridgeF,
            Self::BridgeEval => RxIndex::BridgeEval,
            Self::ChallengeStage => RxIndex::ChallengeStage,
            _ => return None,
        })
    }

    /// Whether `self` is registered as a mask, a stage mask or a final
    /// mask, rather than as a circuit.
    pub fn is_mask(self) -> bool {
        use InternalCircuitIndex::*;
        match self {
            EndoscalingStep(_) | Collapse | ComputeV | ExtensionCircuit(_) | Step(_) => false,
            EndoscalarStage | PointsStage | PointsFinalStaged | BridgePreamble | BridgeHash
            | BridgeSPrime | BridgeInnerError | BridgeOuterError | BridgeAB | BridgeQuery
            | BridgeF | BridgeEval | ChallengeStage | ChallengeFinalStaged | ExtensionMask(_)
            | LinksStage | MemoryStage | ErrorsFinalStaged | QueryFinalStaged | EvalFinalStaged => {
                true
            }
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
    /// The points stage polynomial of a group of a grouped walk after the
    /// first, whose is [`PointsStage`](Self::PointsStage).
    PointsGroup(u32),
    /// The links stage's rx polynomial, in a paged profile.
    LinksStage,
    /// The memory stage's rx polynomial, in a paged profile.
    MemoryStage,
    /// The rx polynomial of a step circuit of a paged profile's program.
    Step(u32),
}

impl RxIndex {
    /// The number of rx components in the nested field,
    /// equal to the number of entries in [`RxIndex::ALL`].
    pub const NUM: usize = NUM_ENDOSCALING_STEPS + NUM_FIXED_RX;

    /// The rx polynomials of the instance circuits, in
    /// [`InternalCircuitIndex::INSTANCE`] order.
    pub const INSTANCE: [Self; NUM_INSTANCE_CIRCUITS] = [Self::Collapse, Self::ComputeV];

    /// The twelve nested stages, in the order of their gates: the chain an
    /// instance circuit reserves and loads (see
    /// [`load_all`](circuits::common::load_all)).
    pub const STAGES: [Self; 12] = [
        Self::EndoscalarStage,
        Self::BridgeHash,
        Self::PointsStage,
        Self::BridgePreamble,
        Self::BridgeSPrime,
        Self::BridgeInnerError,
        Self::BridgeOuterError,
        Self::BridgeAB,
        Self::BridgeQuery,
        Self::BridgeF,
        Self::BridgeEval,
        Self::ChallengeStage,
    ];

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
        all.extend(Self::paged_extras::<P>());
        assert_eq!(all.len(), Self::num::<P>());
        all
    }

    /// The rx polynomial of the points stage of group `group` of the walk.
    pub fn points_group(group: usize) -> Self {
        match group {
            0 => Self::PointsStage,
            group => Self::PointsGroup(group as u32),
        }
    }

    /// The rx polynomials a paged profile adds, in order: the points stages
    /// of the walk's groups after the first, the links stage, the memory
    /// stage, then the program's step circuits. None for a profile that is
    /// not paged.
    pub fn paged_extras<P: Profile>() -> Vec<Self> {
        if !paged::<P>() {
            return Vec::new();
        }
        let groups = walk_grouping::<P>().groups() as u32;
        (1..groups)
            .map(Self::PointsGroup)
            .chain([Self::LinksStage, Self::MemoryStage])
            .chain((0..NumProgramSteps::<P>::len() as u32).map(Self::Step))
            .collect()
    }

    /// The rx polynomials of the steps of the program of profile `P` whose
    /// circuits load `branch`, in schedule order: the circuits one final
    /// mask covers.
    pub fn steps_on<P: Profile>(branch: circuits::paged::Branch) -> impl Iterator<Item = Self> {
        let schedule = if paged::<P>() {
            circuits::paged::schedule::<P>()
        } else {
            Vec::new()
        };
        schedule
            .into_iter()
            .enumerate()
            .filter(move |(_, step)| step.branch() == branch)
            .map(|(position, _)| Self::Step(position as u32))
    }

    /// The stages an instance circuit's claim takes in profile `P`: every
    /// nested stage, or in a paged profile the stages of the layout's trunk
    /// and the `preamble` stage.
    pub fn instance_stages<P: Profile>() -> Vec<Self> {
        if paged::<P>() {
            Self::loaded_stages(circuits::paged::Branch::Preamble, None)
        } else {
            Self::STAGES.to_vec()
        }
    }

    /// The stages the claim of a paged profile's circuit takes: the stages
    /// of the layout's trunk, with the points stage of group `group` of the
    /// walk if the circuit loads one, then the stages of `branch`. See
    /// [`layout`].
    pub fn loaded_stages(branch: circuits::paged::Branch, group: Option<usize>) -> Vec<Self> {
        use circuits::paged::Branch;
        let mut stages = alloc::vec![Self::EndoscalarStage, Self::BridgeHash];
        stages.extend(group.map(Self::points_group));
        stages.extend([
            Self::LinksStage,
            Self::BridgeSPrime,
            Self::BridgeAB,
            Self::BridgeF,
            Self::ChallengeStage,
            Self::MemoryStage,
        ]);
        stages.extend(match branch {
            Branch::Preamble => alloc::vec![Self::BridgePreamble],
            Branch::Errors => alloc::vec![Self::BridgeInnerError, Self::BridgeOuterError],
            Branch::Query => alloc::vec![Self::BridgeQuery],
            Branch::Eval => alloc::vec![Self::BridgeQuery, Self::BridgeEval],
        });
        stages
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
            PointsGroup(_) | LinksStage | MemoryStage | Step(_) => {
                let extension = crate::profile::extension_lengths::<P>(true);
                let extra = Self::paged_extras::<P>()
                    .iter()
                    .position(|&extra| extra == self)
                    .expect("index is outside the profile");
                steps + 14 + extension.circuits + extension.stages + extra
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
pub mod layout;
pub mod online;
pub mod pcs;
pub mod unified;

pub mod stages {
    pub mod ab;
    pub mod bridge_hash;
    pub mod challenges;
    pub mod eval;
    pub mod f;
    pub mod inner_error;
    pub mod outer_error;
    pub mod preamble;
    pub mod query;
    pub mod s_prime;
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
    // The profile pins its program's steps; the schedule its sizes give
    // must be the one the pin laid the polynomials out for.
    if paged::<C::Profile>() {
        let fixed = circuits::paged::num_fixed_steps::<C::Profile>();
        if fixed != C::Profile::NESTED_STEPS {
            return Err(ragu_core::Error::Initialization(
                alloc::format!(
                    "the profile pins {} steps of its nested program, whose schedule has {fixed}",
                    C::Profile::NESTED_STEPS
                )
                .into(),
            ));
        }
    }
    let initial_internal_circuits = registry.num_internal_circuits();

    let extension = crate::profile::nested_extension::<C::Profile>();
    let mut extension_circuits = alloc::vec::Vec::with_capacity(extension.circuits.len());
    let mut extension_masks = alloc::vec::Vec::with_capacity(extension.masks());
    // Circuits first, then masks — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    for id in InternalCircuitIndex::all::<C::Profile>() {
        use InternalCircuitIndex::*;
        registry = match id {
            EndoscalingStep(step) => {
                let step_circuit =
                    self::EndoscalingStep::<C::HostCurve, R, C::Profile>::new(step as usize);
                let staged = MultiStage::new(step_circuit);
                registry.register_internal_circuit(staged)?
            }
            Collapse if paged::<C::Profile>() => {
                let circuit =
                    circuits::paged::instance::Circuit::<C::HostCurve, R, C::Profile>::new();
                registry.register_internal_circuit(MultiStage::new(circuit))?
            }
            ComputeV if paged::<C::Profile>() => {
                let circuit =
                    circuits::paged::export::Circuit::<C::HostCurve, R, C::Profile>::new();
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
            EndoscalarStage => registry.register_mask(<endoscalar::EndoscalarStage as StageExt<
                C::ScalarField,
                R,
            >>::stage_mask()?),
            PointsStage => {
                registry.register_mask(self::PointsStage::<C::HostCurve, C::Profile>::stage_mask()?)
            }
            PointsFinalStaged => {
                registry.register_mask(self::PointsStage::<C::HostCurve, C::Profile>::final_mask()?)
            }
            BridgePreamble => {
                registry.register_mask(
                    stages::preamble::Stage::<C::HostCurve, R, C::Profile>::stage_mask()?,
                )
            }
            BridgeHash => {
                registry.register_mask(stages::bridge_hash::Stage::<C::HostCurve>::stage_mask()?)
            }
            BridgeSPrime => {
                registry.register_mask(
                    stages::s_prime::Stage::<C::HostCurve, R, C::Profile>::stage_mask()?,
                )
            }
            BridgeInnerError => {
                registry.register_mask(
                    stages::inner_error::Stage::<C::HostCurve, R, C::Profile>::stage_mask()?,
                )
            }
            BridgeOuterError => {
                registry.register_mask(
                    stages::outer_error::Stage::<C::HostCurve, R, C::Profile>::stage_mask()?,
                )
            }
            BridgeAB => registry
                .register_mask(stages::ab::Stage::<C::HostCurve, R, C::Profile>::stage_mask()?),
            BridgeQuery => {
                registry.register_mask(
                    stages::query::Stage::<C::HostCurve, R, C::Profile>::stage_mask()?,
                )
            }
            BridgeF => registry
                .register_mask(stages::f::Stage::<C::HostCurve, R, C::Profile>::stage_mask()?),
            BridgeEval => registry
                .register_mask(stages::eval::Stage::<C::HostCurve, R, C::Profile>::stage_mask()?),
            ChallengeStage => {
                registry.register_mask(
                    stages::challenges::Stage::<C::HostCurve, R, C::Profile>::stage_mask()?,
                )
            }
            ChallengeFinalStaged if paged::<C::Profile>() => registry.register_mask(
                stages::preamble::Stage::<C::HostCurve, R, C::Profile>::final_mask()?,
            ),
            ChallengeFinalStaged => {
                registry.register_mask(
                    stages::challenges::Stage::<C::HostCurve, R, C::Profile>::final_mask()?,
                )
            }
            Step(step) => {
                use circuits::paged::{
                    Branch, OnErrors, OnEval, OnPreamble, OnQuery, StepCircuit, schedule,
                };
                let step = step as usize;
                macro_rules! on {
                    ($branch:ty) => {
                        registry.register_internal_circuit(MultiStage::new(StepCircuit::<
                            C::HostCurve,
                            R,
                            C::Profile,
                            $branch,
                        >::new(step)))?
                    };
                }
                match schedule::<C::Profile>()[step].branch() {
                    Branch::Preamble => on!(OnPreamble),
                    Branch::Errors => on!(OnErrors),
                    Branch::Query => on!(OnQuery),
                    Branch::Eval => on!(OnEval),
                }
            }
            LinksStage => {
                registry.register_mask(self::LinksStage::<C::HostCurve, C::Profile>::stage_mask()?)
            }
            MemoryStage => registry
                .register_mask(self::MemoryStage::<C::HostCurve, R, C::Profile>::stage_mask()?),
            ErrorsFinalStaged => {
                registry.register_mask(
                    stages::outer_error::Stage::<C::HostCurve, R, C::Profile>::final_mask()?,
                )
            }
            QueryFinalStaged => {
                registry.register_mask(
                    stages::query::Stage::<C::HostCurve, R, C::Profile>::final_mask()?,
                )
            }
            EvalFinalStaged => {
                registry.register_mask(
                    stages::eval::Stage::<C::HostCurve, R, C::Profile>::final_mask()?,
                )
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
            ExtensionMask(j) => {
                use crate::profile::online::stages::{self as extension, Nested};
                let slot = MaskSlot::new(registry);
                let (registry, registration) =
                    match extension::mask::<C::Profile, Nested>(j as usize)? {
                        extension::Mask::Online(mask) => {
                            mask.register::<_, R, C::Profile, Nested>(slot)?
                        }
                        extension::Mask::User(index) => {
                            C::Profile::register_nested_mask::<C::Base, R>(index, slot, params)?
                        }
                    }
                    .into_parts();
                extension_masks.push(registration);
                registry
            }
        };
    }
    extension.check_registered("nested", &extension_circuits, &extension_masks)?;

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
        let circuits = all.iter().filter(|id| !id.is_mask()).count();
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
        check::<crate::profile::testing::Grouped>();
        check::<crate::profile::Aggregator<4>>();
    }
}
