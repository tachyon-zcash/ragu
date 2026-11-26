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
}

use crate::{
    internal::{endoscalar, revdot::Parameters},
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
pub const ENDOSCALINGS_PER_STEP: usize = 8;

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

/// The nested points stage, over the native batch's commitments, for host
/// curve `C` in profile `P`.
pub type PointsStage<C, P> =
    endoscalar::PointsStage<C, NumPoints<P>, Endoscalings<P>, stages::bridge_hash::Stage<C>>;

/// The nested points stage's witness.
pub type PointsWitness<C, P> = endoscalar::PointsWitness<C, NumPoints<P>, Endoscalings<P>>;

/// The nested points stage's output gadget.
pub type Points<'dr, D, C, P> = endoscalar::Points<'dr, D, C, NumPoints<P>, Endoscalings<P>>;

/// A nested endoscaling step.
pub type EndoscalingStep<C, R, P> =
    endoscalar::EndoscalingStep<C, R, NumPoints<P>, Endoscalings<P>, stages::bridge_hash::Stage<C>>;

/// A nested endoscaling step's witness.
pub type EndoscalingStepWitness<'source, C, P> =
    endoscalar::EndoscalingStepWitness<'source, C, NumPoints<P>, Endoscalings<P>>;

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
    let circuits = 2 + NumSteps::<P>::len() + extension.circuits;
    let masks = NUM_FIXED_MASKS + extension.masks;
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
    /// A mask of the profile's nested extension, a stage mask or a final
    /// mask, in [`Extension::masks`](crate::profile::Extension::masks)
    /// order.
    ExtensionMask(u32),
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
        assert!(c == Self::NUM);
        slots
    }

    /// The number of internal circuits registered by [`register_all`] in
    /// profile `P`, equal to the length of [`all`](Self::all).
    pub fn num<P: Profile>() -> usize {
        NumSteps::<P>::len()
            + NUM_FIXED_INTERNAL
            + crate::profile::nested_extension::<P>().internal()
    }

    /// All variants in canonical iteration order, for profile `P`:
    /// [`ALL`](Self::ALL) with the walk resized to the profile's steps, the
    /// profile's extension circuits after the instance circuits and its
    /// masks last.
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
        all.extend((0..extension.masks() as u32).map(Self::ExtensionMask));
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
        let mask = steps + 2 + extension.circuits;
        let pos = match self {
            EndoscalingStep(i) => super::checked_index(i, steps),
            Collapse => steps,
            ComputeV => steps + 1,
            ExtensionCircuit(i) => steps + 2 + super::checked_index(i, extension.circuits),
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
    #[cfg(test)]
    pub fn is_mask(self) -> bool {
        use InternalCircuitIndex::*;
        match self {
            EndoscalingStep(_) | Collapse | ComputeV | ExtensionCircuit(_) => false,
            EndoscalarStage | PointsStage | PointsFinalStaged | BridgePreamble | BridgeHash
            | BridgeSPrime | BridgeInnerError | BridgeOuterError | BridgeAB | BridgeQuery
            | BridgeF | BridgeEval | ChallengeStage | ChallengeFinalStaged | ExtensionMask(_) => {
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
    pub mod bridge_hash;
    pub mod challenges;
    pub mod eval;
    pub mod f;
    pub mod inner_error;
    pub mod outer_error;
    pub mod preamble;
    pub mod query;
    pub mod s_prime;

    use ragu_circuits::{
        polynomials::Rank,
        staging::{Stage, StageExt},
    };
    use udon::curve::EndomorphismAffine as Affine;

    use crate::profile::Profile;

    /// The first gate of a stage that starts a branch, with parent
    /// `Parent`: after its parent, or, for a profile that lays the nested
    /// stages side by side
    /// ([`Pages::nested_branches`](crate::profile::Pages::nested_branches)),
    /// where the bridge-hash stage ends, beside the branches before it. No
    /// circuit loads two branches then, except in pages that load one each
    /// (see [`ragu_circuits::paging`]).
    pub(crate) fn branch_start<C: Affine, R: Rank, P: Profile, Parent: Stage<C::Base, R>>() -> usize
    {
        if P::PAGES.nested_branches {
            <bridge_hash::Stage<C> as Stage<C::Base, R>>::skip_gates()
                + <bridge_hash::Stage<C> as StageExt<C::Base, R>>::num_gates()
        } else {
            Parent::skip_gates() + Parent::num_gates()
        }
    }
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
) -> Result<(
    RegistryBuilder<'params, C::ScalarField, R>,
    crate::profile::paging::Plans<C::ScalarField>,
)> {
    C::Profile::check()?;
    let initial_internal_circuits = registry.num_internal_circuits();

    let extension = crate::profile::nested_extension::<C::Profile>();
    let mut extension_circuits = alloc::vec::Vec::with_capacity(extension.circuits.len());
    let mut extension_masks = alloc::vec::Vec::with_capacity(extension.masks());
    // The instance circuits go through the registrar, which registers each
    // whole or, for a profile that pages it, its last page here and its
    // other pages and their masks in the extension's slots.
    use crate::profile::paging;
    let mut pages = paging::Registrar::new::<C::Profile>(true);
    // The walk's steps are each a circuit of its own to page: they are
    // cut together here, and found cut where they are registered.
    pages.warm(
        InternalCircuitIndex::all::<C::Profile>()
            .into_iter()
            .filter_map(|id| match id {
                InternalCircuitIndex::EndoscalingStep(step) => Some((
                    paging::Circuit::NestedEndoscalingStep(step),
                    MultiStage::new(self::EndoscalingStep::<C::HostCurve, R, C::Profile>::new(
                        step as usize,
                    )),
                )),
                _ => None,
            })
            .collect(),
    );
    // Circuits first, then masks — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    for id in InternalCircuitIndex::all::<C::Profile>() {
        use InternalCircuitIndex::*;
        registry = match id {
            EndoscalingStep(step) => {
                let step_circuit =
                    self::EndoscalingStep::<C::HostCurve, R, C::Profile>::new(step as usize);
                C::Profile::register_internal(
                    &mut pages,
                    registry,
                    paging::Circuit::NestedEndoscalingStep(step),
                    MultiStage::new(step_circuit),
                )?
            }
            Collapse => {
                let circuit = circuits::collapse::Circuit::<C::HostCurve, R, C::Profile>::new();
                C::Profile::register_internal(
                    &mut pages,
                    registry,
                    paging::Circuit::NestedCollapse,
                    MultiStage::new(circuit),
                )?
            }
            ComputeV => {
                let circuit = circuits::compute_v::Circuit::<C::HostCurve, R, C::Profile>::new();
                C::Profile::register_internal(
                    &mut pages,
                    registry,
                    paging::Circuit::NestedComputeV,
                    MultiStage::new(circuit),
                )?
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
            ChallengeFinalStaged => {
                registry.register_mask(
                    stages::challenges::Stage::<C::HostCurve, R, C::Profile>::final_mask()?,
                )
            }
            ExtensionCircuit(k) => {
                use crate::profile::online::stages::{self as extension, Nested};
                let (registry, registration) = if pages.is_page(k) {
                    pages.page(registry, k)?
                } else {
                    let slot = CircuitSlot::new(registry);
                    if Some(k) == extension::helper::<C::Profile, Nested>() {
                        extension::register_circuit::<_, R, C::Profile, Nested>(
                            slot,
                            source_tag,
                            source_domain,
                        )?
                    } else {
                        C::Profile::register_nested_circuit::<C::Base, R>(k as usize, slot, params)?
                    }
                    .into_parts()
                };
                extension_circuits.push(registration);
                registry
            }
            ExtensionMask(j) => {
                use crate::profile::online::stages::{self as extension, Nested};
                let (registry, registration) = match pages.mask(registry, j as usize)? {
                    paging::Slotted::Paged(registry, registration) => (registry, registration),
                    paging::Slotted::Other(registry, index) => {
                        let slot = MaskSlot::new(registry);
                        match extension::mask::<C::Profile, Nested>(index)? {
                            extension::Mask::Online(mask) => {
                                mask.register::<_, R, C::Profile, Nested>(slot)?
                            }
                            extension::Mask::User(index) => {
                                C::Profile::register_nested_mask::<C::Base, R>(index, slot, params)?
                            }
                        }
                        .into_parts()
                    }
                };
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

    Ok((registry, pages.plans()))
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
        check::<crate::profile::Aggregator<4>>();
    }
}
