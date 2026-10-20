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
    staging::StageExt,
};
use ragu_core::Result;
use ragu_primitives::vec::{ConstLen, Len};

use crate::{
    internal::{endoscalar, fold_revdot::Parameters, nested},
    profile::{Profile, ProfiledCycle, Shape},
    step,
};

/// The nested-curve points the native endoscaling walks into $P_n$: the
/// nested batch's commitments, in [`nested::pcs::Batch::evaluated`] order
/// after $f_n$'s.
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

/// The endoscalings a native step performs: what fits a step beside the
/// stages it reserves.
pub const ENDOSCALINGS_PER_STEP: usize = 4;

/// The number of native endoscaling steps: the standard profile's pin.
///
/// Pinned rather than derived: each side's step polynomials are opened by
/// the other side's batch, so the two step counts determine each other's
/// batch sizes, and one of them has to be fixed to break the cycle. The
/// assertion below checks the pin is the fixed point, so a change to either
/// batch that moves it fails to build here. The profile's shape rederives
/// the whole cycle (see [`Shape`]).
pub const NUM_ENDOSCALING_STEPS: usize = 25;

const _: () = assert!(
    endoscalar::num_steps::<ENDOSCALINGS_PER_STEP>(NUM_ENDOSCALING_POINTS) == NUM_ENDOSCALING_STEPS,
    "NUM_ENDOSCALING_STEPS is not the number of steps over the nested batch; re-pin it"
);

/// Length type for the native endoscaling steps in profile `P`.
///
/// Each side's step polynomials are opened by the other side's batch, so the
/// two step counts determine each other's batch sizes; the profile's
/// [`Shape`] solves that cycle to its fixed point, and this is the walk over
/// the batch that fixed point gives. The standard profile's is
/// [`NUM_ENDOSCALING_STEPS`].
pub type NumSteps<P> = endoscalar::NumStepsLen<NumPoints<P>, ENDOSCALINGS_PER_STEP>;

/// Length type for the circuits of the profile's native extension.
pub struct NumExtensionCircuits<P: Profile>(core::marker::PhantomData<P>);

impl<P: Profile> Len for NumExtensionCircuits<P> {
    fn len() -> usize {
        P::native_extension().circuits.len()
    }
}

/// Length type for the stages of the profile's native extension.
pub struct NumExtensionStages<P: Profile>(core::marker::PhantomData<P>);

impl<P: Profile> Len for NumExtensionStages<P> {
    fn len() -> usize {
        P::native_extension().stages
    }
}

/// The native rx polynomials that are not endoscaling steps: the
/// application's, the five hashing, collapse and compute-v circuits', the
/// binders', bind-beta's, bind-endoscalar's and the eleven stages'.
pub const NUM_FIXED_RX: usize = 19 + NUM_BINDERS;

/// The native internal circuits that are not endoscaling steps: the rx
/// polynomials' circuits and stages, the application's aside, and the four
/// final stage masks.
pub const NUM_FIXED_INTERNAL: usize = NUM_FIXED_RX - 1 + 4;

/// The groups the standard profile's native claims fold into: two raw and
/// two application claims, two per internal circuit and one per bonding,
/// 93 claims in 19 groups of 7. Fourteen would hold them; the count is
/// pinned at the layout's own, so the standard proof is unchanged.
pub const NUM_FOLD_GROUPS: usize = 19;

/// The claims in a fold group on either side.
pub const FOLD_GROUP_SIZE: usize = 7;

/// The native revdot claims of profile `P` the fuse folds: two children's
/// raw and application claims, each internal circuit's claim per child,
/// and each bonding's claim across both.
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
    2 + 2 + 2 * circuits + bondings
}

/// Length type for the native fold's groups in profile `P`: the standard
/// profile's [`NUM_FOLD_GROUPS`], or as many groups of [`FOLD_GROUP_SIZE`]
/// as the profile's [`num_claims`] need, whichever is more.
pub struct NumFoldGroups<P: Profile>(core::marker::PhantomData<P>);

impl<P: Profile> Len for NumFoldGroups<P> {
    fn len() -> usize {
        NUM_FOLD_GROUPS.max(num_claims::<P>().div_ceil(FOLD_GROUP_SIZE))
    }
}

/// Parameters for folding the children's native revdot claims in profile
/// `P`: [`NumFoldGroups`] groups of [`FOLD_GROUP_SIZE`].
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
    pub mod points;
    pub mod preamble;
    pub mod query;
}

pub mod circuits {
    pub mod bind_beta;
    pub mod bind_challenges;
    pub mod bind_endoscalar;
    pub mod compute_v;
    pub mod endoscaling_step;
    pub mod hashes_1;
    pub mod hashes_2;
    pub mod inner_collapse;
    pub mod outer_collapse;
}

pub mod claims;
pub mod unified;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCircuitIndex {
    // Native circuits
    Hashes1Circuit,
    Hashes2Circuit,
    InnerCollapseCircuit,
    OuterCollapseCircuit,
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
    PointsChildrenStage,
    PointsRegistryWxStage,
    PointsAbStage,
    PointsFStage,
    PointsWalkStage,
    // Final stage masks
    InnerErrorFinalStaged,
    OuterErrorFinalStaged,
    EvalFinalStaged,
    PointsWalkFinalStaged,
    /// A bonding of the profile's native extension, a stage's mask or a
    /// final mask, in [`Extension::bondings`](crate::profile::Extension::bondings)
    /// order.
    ExtensionBonding(u32),
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
        push(&mut slots, &mut c, Self::InnerCollapseCircuit);
        push(&mut slots, &mut c, Self::OuterCollapseCircuit);
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
        push(&mut slots, &mut c, Self::PointsChildrenStage);
        push(&mut slots, &mut c, Self::PointsRegistryWxStage);
        push(&mut slots, &mut c, Self::PointsAbStage);
        push(&mut slots, &mut c, Self::PointsFStage);
        push(&mut slots, &mut c, Self::PointsWalkStage);
        push(&mut slots, &mut c, Self::InnerErrorFinalStaged);
        push(&mut slots, &mut c, Self::OuterErrorFinalStaged);
        push(&mut slots, &mut c, Self::EvalFinalStaged);
        push(&mut slots, &mut c, Self::PointsWalkFinalStaged);
        assert!(c == Self::NUM);
        slots
    }

    /// The number of internal circuits registered by [`register_all`] in
    /// profile `P`, equal to the length of [`all`](Self::all).
    pub fn num<P: Profile>() -> usize {
        NUM_FIXED_INTERNAL + NumSteps::<P>::len() + P::native_extension().internal()
    }

    /// All variants in canonical iteration order, for profile `P`:
    /// [`ALL`](Self::ALL) with the walk resized to the profile's steps, the
    /// profile's extension circuits after the walk and its bondings last.
    pub fn all<P: Profile>() -> Vec<Self> {
        let extension = P::native_extension();
        let all = Self::all_with(
            NumSteps::<P>::len(),
            extension.circuits.len(),
            extension.bondings(),
        );
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
        let pos = Self::all::<P>()
            .iter()
            .position(|&v| v == self)
            .expect("every variant appears in all");
        CircuitIndex::from_u32(pos as u32)
    }

    /// Whether `self` is registered as a bonding, a stage's mask or a final
    /// mask, rather than as a circuit.
    pub fn is_bonding(self) -> bool {
        use InternalCircuitIndex::*;
        match self {
            Hashes1Circuit
            | Hashes2Circuit
            | InnerCollapseCircuit
            | OuterCollapseCircuit
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
            | PointsChildrenStage
            | PointsRegistryWxStage
            | PointsAbStage
            | PointsFStage
            | PointsWalkStage
            | InnerErrorFinalStaged
            | OuterErrorFinalStaged
            | EvalFinalStaged
            | PointsWalkFinalStaged
            | ExtensionBonding(_) => true,
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
pub struct InternalCircuitValues<T> {
    pub hashes_1_circuit: T,
    pub hashes_2_circuit: T,
    pub inner_collapse_circuit: T,
    pub outer_collapse_circuit: T,
    pub compute_v_circuit: T,
    pub bind_challenges_circuits: [T; NUM_BINDERS],
    pub bind_beta_circuit: T,
    pub bind_endoscalar_circuit: T,
    /// One per endoscaling step of the profile the values were built for.
    pub endoscaling_step_circuits: Vec<T>,
    /// One per circuit of the profile's native extension.
    pub extension_circuits: Vec<T>,
    pub preamble_stage: T,
    pub inner_error_stage: T,
    pub outer_error_stage: T,
    pub query_stage: T,
    pub eval_stage: T,
    pub points_binding_stage: T,
    pub points_children_stage: T,
    pub points_registry_wx_stage: T,
    pub points_ab_stage: T,
    pub points_f_stage: T,
    pub points_walk_stage: T,
    pub inner_error_final_staged: T,
    pub outer_error_final_staged: T,
    pub eval_final_staged: T,
    pub points_walk_final_staged: T,
    /// One per bonding of the profile's native extension.
    pub extension_bondings: Vec<T>,
}

impl<T> InternalCircuitValues<T> {
    /// The number of endoscaling steps these values were built for.
    pub fn num_steps(&self) -> usize {
        self.endoscaling_step_circuits.len()
    }

    /// Every value with its index, in [`all`](InternalCircuitIndex::all)
    /// order.
    pub fn iter(&self) -> impl Iterator<Item = (InternalCircuitIndex, &T)> {
        InternalCircuitIndex::all_with(
            self.num_steps(),
            self.extension_circuits.len(),
            self.extension_bondings.len(),
        )
        .into_iter()
        .map(move |id| (id, self.get(id)))
    }

    /// Maps every value, in [`all`](InternalCircuitIndex::all) order.
    pub fn try_map<U, E>(
        &self,
        mut f: impl FnMut(InternalCircuitIndex, &T) -> core::result::Result<U, E>,
    ) -> core::result::Result<InternalCircuitValues<U>, E> {
        use InternalCircuitIndex::*;
        Ok(InternalCircuitValues {
            hashes_1_circuit: f(Hashes1Circuit, &self.hashes_1_circuit)?,
            hashes_2_circuit: f(Hashes2Circuit, &self.hashes_2_circuit)?,
            inner_collapse_circuit: f(InnerCollapseCircuit, &self.inner_collapse_circuit)?,
            outer_collapse_circuit: f(OuterCollapseCircuit, &self.outer_collapse_circuit)?,
            compute_v_circuit: f(ComputeVCircuit, &self.compute_v_circuit)?,
            bind_challenges_circuits: {
                let mut out = [(); NUM_BINDERS].map(|()| None);
                for (k, slot) in out.iter_mut().enumerate() {
                    *slot = Some(f(
                        BindChallengesCircuit(k as u32),
                        &self.bind_challenges_circuits[k],
                    )?);
                }
                out.map(|slot| slot.expect("filled"))
            },
            bind_beta_circuit: f(BindBetaCircuit, &self.bind_beta_circuit)?,
            bind_endoscalar_circuit: f(BindEndoscalarCircuit, &self.bind_endoscalar_circuit)?,
            endoscaling_step_circuits: self
                .endoscaling_step_circuits
                .iter()
                .enumerate()
                .map(|(step, value)| f(EndoscalingStep(step as u32), value))
                .collect::<core::result::Result<_, E>>()?,
            extension_circuits: self
                .extension_circuits
                .iter()
                .enumerate()
                .map(|(k, value)| f(ExtensionCircuit(k as u32), value))
                .collect::<core::result::Result<_, E>>()?,
            preamble_stage: f(PreambleStage, &self.preamble_stage)?,
            inner_error_stage: f(InnerErrorStage, &self.inner_error_stage)?,
            outer_error_stage: f(OuterErrorStage, &self.outer_error_stage)?,
            query_stage: f(QueryStage, &self.query_stage)?,
            eval_stage: f(EvalStage, &self.eval_stage)?,
            points_binding_stage: f(PointsBindingStage, &self.points_binding_stage)?,
            points_children_stage: f(PointsChildrenStage, &self.points_children_stage)?,
            points_registry_wx_stage: f(PointsRegistryWxStage, &self.points_registry_wx_stage)?,
            points_ab_stage: f(PointsAbStage, &self.points_ab_stage)?,
            points_f_stage: f(PointsFStage, &self.points_f_stage)?,
            points_walk_stage: f(PointsWalkStage, &self.points_walk_stage)?,
            inner_error_final_staged: f(InnerErrorFinalStaged, &self.inner_error_final_staged)?,
            outer_error_final_staged: f(OuterErrorFinalStaged, &self.outer_error_final_staged)?,
            eval_final_staged: f(EvalFinalStaged, &self.eval_final_staged)?,
            points_walk_final_staged: f(PointsWalkFinalStaged, &self.points_walk_final_staged)?,
            extension_bondings: self
                .extension_bondings
                .iter()
                .enumerate()
                .map(|(j, value)| f(ExtensionBonding(j as u32), value))
                .collect::<core::result::Result<_, E>>()?,
        })
    }

    /// Look up the value for the given internal circuit index.
    pub fn get(&self, id: InternalCircuitIndex) -> &T {
        use InternalCircuitIndex::*;
        match id {
            Hashes1Circuit => &self.hashes_1_circuit,
            Hashes2Circuit => &self.hashes_2_circuit,
            InnerCollapseCircuit => &self.inner_collapse_circuit,
            OuterCollapseCircuit => &self.outer_collapse_circuit,
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
            PointsChildrenStage => &self.points_children_stage,
            PointsRegistryWxStage => &self.points_registry_wx_stage,
            PointsAbStage => &self.points_ab_stage,
            PointsFStage => &self.points_f_stage,
            PointsWalkStage => &self.points_walk_stage,
            InnerErrorFinalStaged => &self.inner_error_final_staged,
            OuterErrorFinalStaged => &self.outer_error_final_staged,
            EvalFinalStaged => &self.eval_final_staged,
            PointsWalkFinalStaged => &self.points_walk_final_staged,
            ExtensionBonding(j) => &self.extension_bondings[j as usize],
        }
    }

    /// Construct from a closure called once per variant in
    /// [`all`](InternalCircuitIndex::all) order, for profile `P`.
    pub fn from_fn<P: Profile>(mut f: impl FnMut(InternalCircuitIndex) -> T) -> Self {
        match Self::try_from_fn::<P, _>(|id| Ok::<_, core::convert::Infallible>(f(id))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`all`](InternalCircuitIndex::all) order, for
    /// profile `P`.
    pub fn try_from_fn<P: Profile, E>(
        mut f: impl FnMut(InternalCircuitIndex) -> core::result::Result<T, E>,
    ) -> core::result::Result<Self, E> {
        use InternalCircuitIndex::*;
        Ok(InternalCircuitValues {
            hashes_1_circuit: f(Hashes1Circuit)?,
            hashes_2_circuit: f(Hashes2Circuit)?,
            inner_collapse_circuit: f(InnerCollapseCircuit)?,
            outer_collapse_circuit: f(OuterCollapseCircuit)?,
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
            endoscaling_step_circuits: (0..NumSteps::<P>::len() as u32)
                .map(|step| f(EndoscalingStep(step)))
                .collect::<core::result::Result<_, E>>()?,
            extension_circuits: (0..P::native_extension().circuits.len() as u32)
                .map(|k| f(ExtensionCircuit(k)))
                .collect::<core::result::Result<_, E>>()?,
            preamble_stage: f(PreambleStage)?,
            inner_error_stage: f(InnerErrorStage)?,
            outer_error_stage: f(OuterErrorStage)?,
            query_stage: f(QueryStage)?,
            eval_stage: f(EvalStage)?,
            points_binding_stage: f(PointsBindingStage)?,
            points_children_stage: f(PointsChildrenStage)?,
            points_registry_wx_stage: f(PointsRegistryWxStage)?,
            points_ab_stage: f(PointsAbStage)?,
            points_f_stage: f(PointsFStage)?,
            points_walk_stage: f(PointsWalkStage)?,
            inner_error_final_staged: f(InnerErrorFinalStaged)?,
            outer_error_final_staged: f(OuterErrorFinalStaged)?,
            eval_final_staged: f(EvalFinalStaged)?,
            points_walk_final_staged: f(PointsWalkFinalStaged)?,
            extension_bondings: (0..P::native_extension().bondings() as u32)
                .map(|j| f(ExtensionBonding(j)))
                .collect::<core::result::Result<_, E>>()?,
        })
    }
}

/// Enum identifying which rx polynomial component to index within [`RxValues`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxIndex {
    // Circuits
    Application,
    Hashes1,
    Hashes2,
    InnerCollapse,
    OuterCollapse,
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
    /// The points stage holding the rest of the children's commitments.
    PointsChildren,
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
        push(&mut slots, &mut c, Self::Application);
        push(&mut slots, &mut c, Self::Hashes1);
        push(&mut slots, &mut c, Self::Hashes2);
        push(&mut slots, &mut c, Self::InnerCollapse);
        push(&mut slots, &mut c, Self::OuterCollapse);
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
        push(&mut slots, &mut c, Self::PointsChildren);
        push(&mut slots, &mut c, Self::PointsRegistryWx);
        push(&mut slots, &mut c, Self::PointsAb);
        push(&mut slots, &mut c, Self::PointsF);
        push(&mut slots, &mut c, Self::PointsWalk);
        assert!(c == Self::NUM);
        slots
    }

    /// The number of rx polynomial components in profile `P`.
    pub fn num<P: Profile>() -> usize {
        NUM_FIXED_RX + NumSteps::<P>::len() + P::NATIVE_EXTENSION
    }

    /// All variants in canonical order, for profile `P`: [`ALL`](Self::ALL)
    /// with the walk resized to the profile's steps, then the profile's
    /// extension circuits' and stages' polynomials.
    pub fn all<P: Profile>() -> Vec<Self> {
        let extension = P::native_extension();
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

/// Per-rx-component storage indexed by [`RxIndex`].
///
/// Each field corresponds 1:1 to a variant of [`RxIndex`].
/// Use [`get`](Self::get) to look up by variant, and
/// [`try_from_fn`](Self::try_from_fn) to construct from a closure.
#[derive(Clone)]
pub struct RxValues<T> {
    pub application: T,
    pub hashes_1: T,
    pub hashes_2: T,
    pub inner_collapse: T,
    pub outer_collapse: T,
    pub compute_v: T,
    pub bind_challenges: [T; NUM_BINDERS],
    pub bind_beta: T,
    pub bind_endoscalar: T,
    /// One per endoscaling step of the profile the values were built for.
    pub endoscaling_steps: Vec<T>,
    pub preamble: T,
    pub inner_error: T,
    pub outer_error: T,
    pub query: T,
    pub eval: T,
    pub points_binding: T,
    pub points_children: T,
    pub points_registry_wx: T,
    pub points_ab: T,
    pub points_f: T,
    pub points_walk: T,
    /// One per circuit of the profile's native extension.
    pub extension_circuits: Vec<T>,
    /// One per stage of the profile's native extension.
    pub extension_stages: Vec<T>,
}

impl<T> RxValues<T> {
    /// The number of endoscaling steps these values were built for.
    pub fn num_steps(&self) -> usize {
        self.endoscaling_steps.len()
    }

    /// Every value with its index, in [`all`](RxIndex::all) order.
    pub fn iter(&self) -> impl Iterator<Item = (RxIndex, &T)> {
        RxIndex::all_with(
            self.num_steps(),
            self.extension_circuits.len(),
            self.extension_stages.len(),
        )
        .into_iter()
        .map(move |id| (id, self.get(id)))
    }

    /// Maps every value, in [`all`](RxIndex::all) order.
    pub fn try_map<U, E>(
        &self,
        mut f: impl FnMut(RxIndex, &T) -> core::result::Result<U, E>,
    ) -> core::result::Result<RxValues<U>, E> {
        use RxIndex::*;
        Ok(RxValues {
            application: f(Application, &self.application)?,
            hashes_1: f(Hashes1, &self.hashes_1)?,
            hashes_2: f(Hashes2, &self.hashes_2)?,
            inner_collapse: f(InnerCollapse, &self.inner_collapse)?,
            outer_collapse: f(OuterCollapse, &self.outer_collapse)?,
            compute_v: f(ComputeV, &self.compute_v)?,
            bind_challenges: {
                let mut out = [(); NUM_BINDERS].map(|()| None);
                for (k, slot) in out.iter_mut().enumerate() {
                    *slot = Some(f(BindChallenges(k as u32), &self.bind_challenges[k])?);
                }
                out.map(|slot| slot.expect("filled"))
            },
            bind_beta: f(BindBeta, &self.bind_beta)?,
            bind_endoscalar: f(BindEndoscalar, &self.bind_endoscalar)?,
            endoscaling_steps: self
                .endoscaling_steps
                .iter()
                .enumerate()
                .map(|(step, value)| f(EndoscalingStep(step as u32), value))
                .collect::<core::result::Result<_, E>>()?,
            preamble: f(Preamble, &self.preamble)?,
            inner_error: f(InnerError, &self.inner_error)?,
            outer_error: f(OuterError, &self.outer_error)?,
            query: f(Query, &self.query)?,
            eval: f(Eval, &self.eval)?,
            points_binding: f(PointsBinding, &self.points_binding)?,
            points_children: f(PointsChildren, &self.points_children)?,
            points_registry_wx: f(PointsRegistryWx, &self.points_registry_wx)?,
            points_ab: f(PointsAb, &self.points_ab)?,
            points_f: f(PointsF, &self.points_f)?,
            points_walk: f(PointsWalk, &self.points_walk)?,
            extension_circuits: self
                .extension_circuits
                .iter()
                .enumerate()
                .map(|(k, value)| f(ExtensionCircuit(k as u32), value))
                .collect::<core::result::Result<_, E>>()?,
            extension_stages: self
                .extension_stages
                .iter()
                .enumerate()
                .map(|(k, value)| f(ExtensionStage(k as u32), value))
                .collect::<core::result::Result<_, E>>()?,
        })
    }

    /// Look up the value for the given rx index.
    pub fn get(&self, id: RxIndex) -> &T {
        use RxIndex::*;
        match id {
            Application => &self.application,
            Hashes1 => &self.hashes_1,
            Hashes2 => &self.hashes_2,
            InnerCollapse => &self.inner_collapse,
            OuterCollapse => &self.outer_collapse,
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
            PointsChildren => &self.points_children,
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
    pub fn from_fn<P: Profile>(mut f: impl FnMut(RxIndex) -> T) -> Self {
        match Self::try_from_fn::<P, _>(|id| Ok::<_, core::convert::Infallible>(f(id))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`all`](RxIndex::all) order, for profile `P`.
    pub fn try_from_fn<P: Profile, E>(
        mut f: impl FnMut(RxIndex) -> core::result::Result<T, E>,
    ) -> core::result::Result<Self, E> {
        use RxIndex::*;
        Ok(RxValues {
            application: f(Application)?,
            hashes_1: f(Hashes1)?,
            hashes_2: f(Hashes2)?,
            inner_collapse: f(InnerCollapse)?,
            outer_collapse: f(OuterCollapse)?,
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
            endoscaling_steps: (0..NumSteps::<P>::len() as u32)
                .map(|step| f(EndoscalingStep(step)))
                .collect::<core::result::Result<_, E>>()?,
            preamble: f(Preamble)?,
            inner_error: f(InnerError)?,
            outer_error: f(OuterError)?,
            query: f(Query)?,
            eval: f(Eval)?,
            points_binding: f(PointsBinding)?,
            points_children: f(PointsChildren)?,
            points_registry_wx: f(PointsRegistryWx)?,
            points_ab: f(PointsAb)?,
            points_f: f(PointsF)?,
            points_walk: f(PointsWalk)?,
            extension_circuits: (0..P::native_extension().circuits.len() as u32)
                .map(|k| f(ExtensionCircuit(k)))
                .collect::<core::result::Result<_, E>>()?,
            extension_stages: (0..P::native_extension().stages as u32)
                .map(|k| f(ExtensionStage(k)))
                .collect::<core::result::Result<_, E>>()?,
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

/// Static prefix of the polynomial-query order used to construct and verify
/// the fuse quotient polynomial $f(X)$.
///
/// These queries are consumed by both the prover-side `compute_f` path and the
/// `compute_v` circuit. Keeping this prefix in one ordered list prevents the
/// two implementations from drifting independently; the dynamic suffixes are
/// still driven by [`RxIndex::ALL`] and [`InternalCircuitIndex::ALL`].
pub(crate) enum StaticFQuery {
    /// Left child proof $p(u)=v$ check.
    LeftP,
    /// Right child proof $p(u)=v$ check.
    RightP,
    /// Left child registry-xy polynomial queried at the current $w$.
    LeftRegistryXyAtW,
    /// Right child registry-xy polynomial queried at the current $w$.
    RightRegistryXyAtW,
    /// Current $m(w, x_0, Y)$ queried at the left child's $y$.
    RegistryWx0AtLeftY,
    /// Current $m(w, x_1, Y)$ queried at the right child's $y$.
    RegistryWx1AtRightY,
    /// Current $m(w, x_0, Y)$ queried at the current $y$.
    RegistryWx0AtY,
    /// Current $m(w, x_1, Y)$ queried at the current $y$.
    RegistryWx1AtY,
    /// Current $m(w, X, y)$ queried at the left child's $x$.
    RegistryWyAtLeftX,
    /// Current $m(w, X, y)$ queried at the right child's $x$.
    RegistryWyAtRightX,
    /// Current $m(w, X, y)$ queried at the current $x$.
    RegistryWyAtX,
    /// Current registry-xy polynomial queried at the current $w$.
    RegistryXyAtW,
    /// Current registry-xy polynomial queried at the left child's circuit id.
    RegistryXyAtLeftCircuitId,
    /// Current registry-xy polynomial queried at the right child's circuit id.
    RegistryXyAtRightCircuitId,
    /// Left child $a$ polynomial queried at $xz$.
    LeftAbAAtXz,
    /// Left child $b$ polynomial queried at $x$.
    LeftAbBAtX,
    /// Right child $a$ polynomial queried at $xz$.
    RightAbAAtXz,
    /// Right child $b$ polynomial queried at $x$.
    RightAbBAtX,
    /// Current accumulator $a$ polynomial queried at $xz$.
    CurrentAAtXz,
    /// Current accumulator $b$ polynomial queried at $x$.
    CurrentBAtX,
}

/// Ordered static prefix for fuse quotient polynomial queries.
pub(crate) const STATIC_F_QUERIES: [StaticFQuery; 20] = [
    StaticFQuery::LeftP,
    StaticFQuery::RightP,
    StaticFQuery::LeftRegistryXyAtW,
    StaticFQuery::RightRegistryXyAtW,
    StaticFQuery::RegistryWx0AtLeftY,
    StaticFQuery::RegistryWx1AtRightY,
    StaticFQuery::RegistryWx0AtY,
    StaticFQuery::RegistryWx1AtY,
    StaticFQuery::RegistryWyAtLeftX,
    StaticFQuery::RegistryWyAtRightX,
    StaticFQuery::RegistryWyAtX,
    StaticFQuery::RegistryXyAtW,
    StaticFQuery::RegistryXyAtLeftCircuitId,
    StaticFQuery::RegistryXyAtRightCircuitId,
    StaticFQuery::LeftAbAAtXz,
    StaticFQuery::LeftAbBAtX,
    StaticFQuery::RightAbAAtXz,
    StaticFQuery::RightAbBAtX,
    StaticFQuery::CurrentAAtXz,
    StaticFQuery::CurrentBAtX,
];

/// Registers internal native circuits and masks into the provided registry.
///
/// Does not register internal steps (rerandomize, bootstrap); those are
/// registered by the caller after this function returns.
pub fn register_all<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize>(
    mut registry: RegistryBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>> {
    C::Profile::check()?;
    let initial_internal_circuits = registry.num_internal_circuits();

    for id in InternalCircuitIndex::all::<C::Profile>() {
        use InternalCircuitIndex::*;
        registry = match id {
            ExtensionCircuit(k) => {
                super::register_one(registry, "native", "circuit", k, |registry| {
                    C::Profile::register_native_circuit::<C::Base, R, HEADER_SIZE>(
                        k as usize, registry, params,
                    )
                })?
            }
            ExtensionBonding(j) => {
                super::register_one(registry, "native", "bonding", j, |registry| {
                    C::Profile::register_native_bonding::<C::Base, R, HEADER_SIZE>(
                        j as usize, registry, params,
                    )
                })?
            }
            PreambleStage => {
                registry.register_bonding(stages::preamble::Stage::<C, R, HEADER_SIZE>::mask()?)
            }
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
            PointsBindingStage => {
                registry.register_bonding(
                    <stages::points::BindingStage<C::NestedCurve> as StageExt<
                        C::CircuitField,
                        R,
                    >>::mask()?,
                )
            }
            PointsChildrenStage => registry.register_bonding(<stages::points::ChildrenStage<
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
            EndoscalingStep(step) => registry.register_internal_circuit(
                circuits::endoscaling_step::Circuit::<C, R>::new(step as usize),
            )?,
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
            InnerCollapseCircuit => {
                registry.register_internal_circuit(circuits::inner_collapse::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    RevdotParameters<C::Profile>,
                >::new())?
            }
            OuterCollapseCircuit => {
                registry.register_internal_circuit(circuits::outer_collapse::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    RevdotParameters<C::Profile>,
                >::new())?
            }
            ComputeVCircuit => {
                registry.register_internal_circuit(circuits::compute_v::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                >::new())?
            }
            BindChallengesCircuit(k) => {
                crate::with_binder!(k, C, R, HEADER_SIZE, params, |circuit| {
                    registry.register_internal_circuit(circuit)?
                })
            }
            BindBetaCircuit => registry
                .register_internal_circuit(circuits::bind_beta::Circuit::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters<C::Profile>,
            >::new(params))?,
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + InternalCircuitIndex::num::<C::Profile>(),
        "internal circuit count mismatch"
    );

    Ok(registry)
}
