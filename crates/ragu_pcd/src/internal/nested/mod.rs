//! Nested field circuits for the scalar field.
//!
//! Contains these circuits:
//!
//! - **Endoscaling**: verifies that the commitment accumulation
//!   in `compute_p` was computed correctly via Horner's rule.
//! - **Loading**: enforces consistency between [`PointsStage`]
//!   inputs and the bridge stage commitments for the current step.
//! - **Export**: pins the nested [`unified`] instance, which a parent copies
//!   into its `BridgePreamble` and folds this step's claims with, to the
//!   stages that hold its values.
//! - **Collapse**: verifies the two-layer fold of the children's nested
//!   claims, the mirror of the native `inner_collapse` and `outer_collapse`.
//! - **Compute v**: recomputes the nested batch evaluation $v_n$, the mirror
//!   of the native `compute_v`.
//!
//! The export, collapse and compute-v circuits share the [`unified`]
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
    extract_endoscalar, lift_endoscalar,
    vec::{ConstLen, Len},
};
use udon::field::Field;

pub mod circuits {
    pub mod collapse;
    pub mod common;
    pub mod compute_v;
    pub mod export;
    pub mod loading;
}

use crate::{
    internal::{endoscalar, fold_revdot::Parameters},
    profile::{Profile, ProfiledCycle, Shape},
};

/// The number of curve points the nested walk folds for a native batch of
/// `native_rx` rx polynomials: `f`'s commitment, then for each child its
/// native rx commitments, $a$, $b$, `registry_xy` and $p$, then the current
/// step's two `registry_wx`, `registry_wy`, $a$, $b$ and `registry_xy`.
pub const fn num_endoscaling_points(native_rx: usize) -> usize {
    1 + 2 * (native_rx + 4) + 6
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
/// walk consumes, at the production rank. A profile sets its own
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

/// Length type for the stages of the profile's nested extension.
pub struct NumExtensionStages<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumExtensionStages<P> {
    fn len() -> usize {
        P::nested_extension().stages
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
pub type PointsStage<C, P> = endoscalar::PointsStage<C, NumPoints<P>, Endoscalings<P>>;

/// The nested points stage's witness.
pub type PointsWitness<C, P> = endoscalar::PointsWitness<C, NumPoints<P>, Endoscalings<P>>;

/// The nested points stage's output gadget.
pub type Points<'dr, D, C, P> = endoscalar::Points<'dr, D, C, NumPoints<P>, Endoscalings<P>>;

/// A nested endoscaling step.
pub type EndoscalingStep<C, R, P> =
    endoscalar::EndoscalingStep<C, R, NumPoints<P>, Endoscalings<P>>;

/// A nested endoscaling step's witness.
pub type EndoscalingStepWitness<'source, C, P> =
    endoscalar::EndoscalingStepWitness<'source, C, NumPoints<P>, Endoscalings<P>>;

/// The number of circuits whose public input is the nested [`unified`]
/// instance: export, collapse and compute-v.
pub const NUM_INSTANCE_CIRCUITS: usize = 3;

/// The nested rx polynomials that are not endoscaling steps: the instance
/// circuits', the endoscalar and points stages', the eight bridge stages'
/// and the challenge stage's.
pub const NUM_FIXED_RX: usize = NUM_INSTANCE_CIRCUITS + 11;

/// The nested internal circuits that are not endoscaling steps: the rx
/// polynomials' circuits and stages, the two final stage masks and the
/// loading circuit.
pub const NUM_FIXED_INTERNAL: usize = NUM_FIXED_RX + 3;

/// The groups the standard profile's nested claims fold into. Two children
/// contribute one raw accumulator claim each, one circuit claim each per
/// endoscaling step and per instance circuit, and one bonding claim per
/// bonding kind (each bonding kind is $z$-folded across both children): 78
/// claims, over twenty-eight steps, three instance circuits and fourteen
/// bonding kinds, in 12 groups of 7, which leaves a little room.
pub const NUM_FOLD_GROUPS: usize = 12;

/// The nested revdot claims of profile `P` the fuse folds: two children's
/// raw claims, each internal circuit's claim per child, and each bonding's
/// claim across both.
pub fn num_claims<P: Profile>() -> usize {
    let (circuits, bondings) =
        InternalCircuitIndex::all::<P>()
            .into_iter()
            .fold((0, 0), |(circuits, bondings), id| {
                if id.is_bonding() {
                    (circuits, bondings + 1)
                } else {
                    (circuits + 1, bondings)
                }
            });
    2 + 2 * circuits + bondings
}

/// Length type for the nested fold's groups in profile `P`: the standard
/// profile's [`NUM_FOLD_GROUPS`], or as many groups of
/// [`FOLD_GROUP_SIZE`](super::native::FOLD_GROUP_SIZE) as the profile's
/// [`num_claims`] need, whichever is more.
pub struct NumFoldGroups<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for NumFoldGroups<P> {
    fn len() -> usize {
        NUM_FOLD_GROUPS.max(num_claims::<P>().div_ceil(super::native::FOLD_GROUP_SIZE))
    }
}

/// Parameters for folding the children's nested revdot claims in profile
/// `P`: [`NumFoldGroups`] groups of
/// [`FOLD_GROUP_SIZE`](super::native::FOLD_GROUP_SIZE).
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
    type GroupSize = ConstLen<{ super::native::FOLD_GROUP_SIZE }>;
}

/// Derives the nested-field counterpart of a native Fiat-Shamir challenge.
///
/// The nested side squeezes nothing itself: every challenge it consumes is the
/// endoscalar lift, in the scalar field, of the low 128 bits of the
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
    pub nu: F,
    pub mu_prime: F,
    pub nu_prime: F,
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
            self.nu,
            self.mu_prime,
            self.nu_prime,
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
    /// Export circuit pinning the nested unified instance to the stages.
    Export,
    /// Collapse circuit verifying the fold of the children's nested claims.
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
    /// Loading circuit over all nested stages.
    Loading,
    /// A bonding of the profile's nested extension, a stage's mask or a
    /// final mask, in [`Extension::bondings`](crate::profile::Extension::bondings)
    /// order.
    ExtensionBonding(u32),
}

impl InternalCircuitIndex {
    /// The number of internal circuits registered by [`register_all`],
    /// equal to the number of entries in [`InternalCircuitIndex::ALL`].
    pub const NUM: usize = NUM_ENDOSCALING_STEPS + NUM_FIXED_INTERNAL;

    /// The circuits whose public input is the nested [`unified`] instance,
    /// in claim order.
    pub const INSTANCE: [Self; NUM_INSTANCE_CIRCUITS] =
        [Self::Export, Self::Collapse, Self::ComputeV];

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
        push(&mut slots, &mut c, Self::Export);
        push(&mut slots, &mut c, Self::Collapse);
        push(&mut slots, &mut c, Self::ComputeV);
        push(&mut slots, &mut c, Self::EndoscalarStage);
        push(&mut slots, &mut c, Self::PointsStage);
        push(&mut slots, &mut c, Self::PointsFinalStaged);
        push(&mut slots, &mut c, Self::BridgePreamble);
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
        NumSteps::<P>::len() + NUM_FIXED_INTERNAL + P::nested_extension().internal()
    }

    /// All variants in canonical iteration order, for profile `P`:
    /// [`ALL`](Self::ALL) with the walk resized to the profile's steps, the
    /// profile's extension circuits after the instance circuits and its
    /// bondings last.
    pub fn all<P: Profile>() -> Vec<Self> {
        let num_steps = NumSteps::<P>::len();
        let extension = P::nested_extension();
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
        assert_eq!(all.len(), Self::num::<P>());
        all
    }

    /// Convert to a [`CircuitIndex`] for registry lookup, in profile `P`.
    ///
    /// Circuit indices follow the `RegistryBuilder::finalize()` concatenation
    /// order: internal circuits first, then internal masks.
    pub fn circuit_index<P: Profile>(self) -> CircuitIndex {
        let pos = Self::all::<P>()
            .iter()
            .position(|&v| v == self)
            .expect("every variant appears in all");
        CircuitIndex::new(pos)
    }

    /// Whether `self` is registered as a bonding, a stage's mask, a final
    /// mask or the loading circuit's, rather than as a circuit.
    pub fn is_bonding(self) -> bool {
        use InternalCircuitIndex::*;
        match self {
            EndoscalingStep(_) | Export | Collapse | ComputeV | ExtensionCircuit(_) => false,
            EndoscalarStage | PointsStage | PointsFinalStaged | BridgePreamble | BridgeSPrime
            | BridgeInnerError | BridgeOuterError | BridgeAB | BridgeQuery | BridgeF
            | BridgeEval | ChallengeStage | ChallengeFinalStaged | Loading
            | ExtensionBonding(_) => true,
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
    /// Export circuit rx polynomial.
    Export,
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
    pub const INSTANCE: [Self; NUM_INSTANCE_CIRCUITS] =
        [Self::Export, Self::Collapse, Self::ComputeV];

    /// The bridge stages, in transcript absorption order.
    pub const BRIDGES: [Self; 8] = [
        Self::BridgePreamble,
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
        push(&mut slots, &mut c, Self::Export);
        push(&mut slots, &mut c, Self::Collapse);
        push(&mut slots, &mut c, Self::ComputeV);
        push(&mut slots, &mut c, Self::EndoscalarStage);
        push(&mut slots, &mut c, Self::PointsStage);
        push(&mut slots, &mut c, Self::BridgePreamble);
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
        NumSteps::<P>::len() + NUM_FIXED_RX + P::NESTED_EXTENSION
    }

    /// All variants in canonical order (circuits, then stages), for profile
    /// `P`: [`ALL`](Self::ALL) with the walk resized to the profile's steps,
    /// then the profile's extension circuits' and stages' polynomials.
    pub fn all<P: Profile>() -> Vec<Self> {
        let num_steps = NumSteps::<P>::len();
        let extension = P::nested_extension();
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
        Self::all::<P>()
            .iter()
            .position(|&v| v == self)
            .expect("every variant appears in all")
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
pub mod pcs;
pub mod unified;

pub mod stages {
    pub mod ab;
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
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    C::Profile::check()?;
    let initial_internal_circuits = registry.num_internal_circuits();

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
            Export => {
                let circuit = circuits::export::Circuit::<C::HostCurve, R, C::Profile>::new();
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
            ExtensionCircuit(k) => {
                super::register_one(registry, "nested", "circuit", k, |registry| {
                    C::Profile::register_nested_circuit::<C::Base, R>(k as usize, registry, params)
                })?
            }
            ExtensionBonding(j) => {
                super::register_one(registry, "nested", "bonding", j, |registry| {
                    C::Profile::register_nested_bonding::<C::Base, R>(j as usize, registry, params)
                })?
            }
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + InternalCircuitIndex::num::<C::Profile>(),
        "internal circuit count mismatch"
    );

    Ok(registry)
}
