//! Native curve circuits for recursive verification.
//!
//! Besides the circuits that verify the native fold and batch, the native
//! side walks the nested batch's commitments: the endoscaling steps of
//! [`circuits::endoscaling_step`] fold the [`num_endoscaling_points`]
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
use ragu_core::{Cycle, Result};
use ragu_primitives::vec::{ConstLen, Len};

use crate::{
    framework_hooks::HookConfig,
    internal::{endoscalar, fold_revdot::Parameters, nested},
    step,
};

/// The nested-curve points the native endoscaling walks into $P_n$ for an
/// application witnessing `polys` polynomials per step: the nested batch's
/// commitments, in [`nested::pcs::Batch::evaluated`] order after $f_n$'s.
pub const fn num_endoscaling_points(polys: usize) -> usize {
    nested::pcs::num_batched_points(polys)
}

/// The endoscalings a native step performs: what fits a step beside the
/// stages it reserves.
pub const ENDOSCALINGS_PER_STEP: usize = 4;

/// The number of native endoscaling steps for an application witnessing
/// `polys` polynomials per step.
///
/// Each side's step polynomials are opened by the other side's batch, so the
/// two step counts determine each other's batch sizes. This is the least
/// native count consistent with both, found by iterating from one step: the
/// count the nested batch it implies needs. The iteration is monotone and a
/// step absorbs four points while adding one to the far side's batch, so it
/// settles within a few rounds; at zero polynomials it is the 25 the walk
/// was first pinned at.
pub const fn num_endoscaling_steps(polys: usize) -> usize {
    let mut steps = 1;
    let mut rounds = 0;
    loop {
        let next = endoscalar::num_steps::<ENDOSCALINGS_PER_STEP>(
            nested::pcs::num_batched_points_at(polys, steps),
        );
        if next == steps {
            return steps;
        }
        steps = next;
        rounds += 1;
        assert!(rounds < 64, "the walks' step counts do not settle");
    }
}

/// [`num_endoscaling_steps`] at the type level, for a poly count `L`.
pub struct StepsLen<L: Len>(PhantomData<L>);

impl<L: Len> Len for StepsLen<L> {
    fn len() -> usize {
        num_endoscaling_steps(L::len())
    }
}

/// [`num_endoscaling_points`] at the type level, for a poly count `L`.
pub struct PointsLen<L: Len>(PhantomData<L>);

impl<L: Len> Len for PointsLen<L> {
    fn len() -> usize {
        num_endoscaling_points(L::len())
    }
}

/// Default parameters for native revdot folding
#[derive(Clone, Copy, Default)]
pub struct RevdotParameters;

impl Parameters for RevdotParameters {
    type NumGroups = ConstLen<19>;
    type GroupSize = ConstLen<7>;
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
    pub mod poly_query;
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
}

/// Compute the total circuit count and log2 domain size from the number of
/// application-defined steps and the polynomials each witnesses.
pub const fn total_circuit_counts(num_application_steps: usize, polys: usize) -> (usize, u32) {
    let total_circuits =
        num_application_steps + step::NUM_INTERNAL_STEPS + InternalCircuitIndex::num(polys);
    let log2_circuits = total_circuits.next_power_of_two().trailing_zeros();
    (total_circuits, log2_circuits)
}

impl InternalCircuitIndex {
    /// The number of internal circuits registered by [`register_all`] for an
    /// application witnessing `polys` polynomials per step: one per entry of
    /// [`all`](Self::all).
    pub const fn num(polys: usize) -> usize {
        22 + NUM_BINDERS + num_endoscaling_steps(polys)
    }

    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before masks), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this list.
    pub fn all(polys: usize) -> impl Iterator<Item = Self> + Clone {
        Self::all_with_steps(num_endoscaling_steps(polys))
    }

    /// [`all`](Self::all) for a native walk of `steps` steps.
    pub fn all_with_steps(steps: usize) -> impl Iterator<Item = Self> + Clone {
        [
            Self::Hashes1Circuit,
            Self::Hashes2Circuit,
            Self::InnerCollapseCircuit,
            Self::OuterCollapseCircuit,
            Self::ComputeVCircuit,
        ]
        .into_iter()
        .chain((0..NUM_BINDERS as u32).map(Self::BindChallengesCircuit))
        .chain([Self::BindBetaCircuit, Self::BindEndoscalarCircuit])
        .chain((0..steps as u32).map(Self::EndoscalingStep))
        .chain([
            Self::PreambleStage,
            Self::InnerErrorStage,
            Self::OuterErrorStage,
            Self::QueryStage,
            Self::EvalStage,
            Self::PointsBindingStage,
            Self::PointsChildrenStage,
            Self::PointsRegistryWxStage,
            Self::PointsAbStage,
            Self::PointsFStage,
            Self::PointsWalkStage,
            Self::InnerErrorFinalStaged,
            Self::OuterErrorFinalStaged,
            Self::EvalFinalStaged,
            Self::PointsWalkFinalStaged,
        ])
    }

    /// Convert to a [`CircuitIndex`] for registry lookup, in the registry of
    /// an application witnessing `polys` polynomials per step.
    pub fn circuit_index(self, polys: usize) -> CircuitIndex {
        let pos = Self::all(polys)
            .position(|v| v == self)
            .expect("every variant appears in `all`");
        CircuitIndex::from_u32(pos as u32)
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
    /// One per endoscaling step, so as many as the layout's walk takes.
    pub endoscaling_step_circuits: Vec<T>,
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
}

impl<T> InternalCircuitValues<T> {
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
        }
    }

    /// The number of endoscaling steps these values cover.
    pub fn num_endoscaling_steps(&self) -> usize {
        self.endoscaling_step_circuits.len()
    }

    /// The variants these values cover, in [`all`](InternalCircuitIndex::all)
    /// order.
    pub fn ids(&self) -> impl Iterator<Item = InternalCircuitIndex> + Clone {
        InternalCircuitIndex::all_with_steps(self.num_endoscaling_steps())
    }

    /// Construct from a closure called once per variant in
    /// [`all`](InternalCircuitIndex::all) order, for an application
    /// witnessing `polys` polynomials per step.
    pub fn from_fn(polys: usize, mut f: impl FnMut(InternalCircuitIndex) -> T) -> Self {
        match Self::try_from_fn(polys, |id| Ok::<_, core::convert::Infallible>(f(id))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`all`](InternalCircuitIndex::all) order.
    pub fn try_from_fn<E>(
        polys: usize,
        f: impl FnMut(InternalCircuitIndex) -> core::result::Result<T, E>,
    ) -> core::result::Result<Self, E> {
        Self::try_from_fn_with_steps(num_endoscaling_steps(polys), f)
    }

    /// [`try_from_fn`](Self::try_from_fn) for a walk of `steps` endoscaling
    /// steps, as an existing set of values carries it.
    pub fn try_from_fn_with_steps<E>(
        steps: usize,
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
            endoscaling_step_circuits: (0..steps as u32)
                .map(|step| f(EndoscalingStep(step)))
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
}

impl RxIndex {
    /// The number of rx polynomial components a proof of an application
    /// witnessing `polys` polynomials per step carries.
    pub const fn num(polys: usize) -> usize {
        Self::num_with_steps(num_endoscaling_steps(polys))
    }

    /// [`num`](Self::num) for a native walk of `steps` steps.
    pub const fn num_with_steps(steps: usize) -> usize {
        19 + NUM_BINDERS + steps
    }

    /// All variants in canonical order.
    ///
    /// This order matches the evaluation order in `poly_queries` (compute_v.rs)
    /// and `_08_f.rs`, and drives the `Write` impl for `RxValues`.
    pub fn all(polys: usize) -> impl Iterator<Item = Self> + Clone {
        Self::all_with_steps(num_endoscaling_steps(polys))
    }

    /// [`all`](Self::all) for a native walk of `steps` steps.
    pub fn all_with_steps(steps: usize) -> impl Iterator<Item = Self> + Clone {
        (0..Self::num_with_steps(steps)).map(move |i| Self::nth(steps, i))
    }

    /// The `i`-th variant of [`all_with_steps`](Self::all_with_steps), which
    /// is defined through this: the one statement of the canonical order.
    ///
    /// # Panics
    ///
    /// Panics if `i` is not below [`num_with_steps`](Self::num_with_steps).
    pub const fn nth(steps: usize, i: usize) -> Self {
        const HEAD: [RxIndex; 6] = [
            RxIndex::Application,
            RxIndex::Hashes1,
            RxIndex::Hashes2,
            RxIndex::InnerCollapse,
            RxIndex::OuterCollapse,
            RxIndex::ComputeV,
        ];
        const TAIL: [RxIndex; 11] = [
            RxIndex::Preamble,
            RxIndex::InnerError,
            RxIndex::OuterError,
            RxIndex::Query,
            RxIndex::Eval,
            RxIndex::PointsBinding,
            RxIndex::PointsChildren,
            RxIndex::PointsRegistryWx,
            RxIndex::PointsAb,
            RxIndex::PointsF,
            RxIndex::PointsWalk,
        ];
        let binders = HEAD.len();
        let bind_beta = binders + NUM_BINDERS;
        let walk = bind_beta + 2;
        let tail = walk + steps;
        if i < binders {
            HEAD[i]
        } else if i < bind_beta {
            Self::BindChallenges((i - binders) as u32)
        } else if i == bind_beta {
            Self::BindBeta
        } else if i == bind_beta + 1 {
            Self::BindEndoscalar
        } else if i < tail {
            Self::EndoscalingStep((i - walk) as u32)
        } else {
            TAIL[i - tail]
        }
    }

    /// The position of `self` in [`all`](Self::all).
    pub fn position(self, polys: usize) -> usize {
        Self::all(polys)
            .position(|v| v == self)
            .expect("every variant appears in `all`")
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
    /// One per endoscaling step, so as many as the layout's walk takes.
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
}

impl<T> RxValues<T> {
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
        }
    }

    /// The variants these values cover, in [`all`](RxIndex::all) order.
    pub fn ids(&self) -> impl Iterator<Item = RxIndex> + Clone {
        RxIndex::all_with_steps(self.endoscaling_steps.len())
    }

    /// Construct from a closure called once per variant in
    /// [`all`](RxIndex::all) order, for an application witnessing `polys`
    /// polynomials per step.
    pub fn from_fn(polys: usize, mut f: impl FnMut(RxIndex) -> T) -> Self {
        match Self::try_from_fn(polys, |id| Ok::<_, core::convert::Infallible>(f(id))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`all`](RxIndex::all) order.
    pub fn try_from_fn<E>(
        polys: usize,
        f: impl FnMut(RxIndex) -> core::result::Result<T, E>,
    ) -> core::result::Result<Self, E> {
        Self::try_from_fn_with_steps(num_endoscaling_steps(polys), f)
    }

    /// [`try_from_fn`](Self::try_from_fn) for a walk of `steps` endoscaling
    /// steps, as an existing set of values carries it.
    pub fn try_from_fn_with_steps<E>(
        steps: usize,
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
            endoscaling_steps: (0..steps as u32)
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
/// still driven by [`RxIndex::all`] and [`InternalCircuitIndex::all`].
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
pub fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig>(
    mut registry: RegistryBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();
    let polys = J::PolyWitnesses::len();

    for id in InternalCircuitIndex::all(polys) {
        use InternalCircuitIndex::*;
        registry = match id {
            PreambleStage => {
                registry.register_bonding(stages::preamble::Stage::<C, R, HEADER_SIZE, J>::mask()?)
            }
            InnerErrorStage => registry.register_bonding(stages::inner_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                J,
                RevdotParameters,
            >::mask()?),
            OuterErrorStage => registry.register_bonding(stages::outer_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                J,
                RevdotParameters,
            >::mask()?),
            QueryStage => {
                registry.register_bonding(stages::query::Stage::<C, R, HEADER_SIZE, J>::mask()?)
            }
            EvalStage => {
                registry.register_bonding(stages::eval::Stage::<C, R, HEADER_SIZE, J>::mask()?)
            }
            InnerErrorFinalStaged => registry.register_bonding(stages::inner_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                J,
                RevdotParameters,
            >::final_mask()?),
            OuterErrorFinalStaged => registry.register_bonding(stages::outer_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                J,
                RevdotParameters,
            >::final_mask()?),
            EvalFinalStaged => {
                registry
                    .register_bonding(stages::eval::Stage::<C, R, HEADER_SIZE, J>::final_mask()?)
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
                J::PolyWitnesses,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsRegistryWxStage => registry.register_bonding(<stages::points::RegistryWxStage<
                C::NestedCurve,
                J::PolyWitnesses,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsAbStage => registry.register_bonding(<stages::points::AbStage<
                C::NestedCurve,
                J::PolyWitnesses,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsFStage => registry.register_bonding(<stages::points::FStage<
                C::NestedCurve,
                J::PolyWitnesses,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsWalkStage => registry.register_bonding(<stages::points::WalkStage<
                C::NestedCurve,
                J::PolyWitnesses,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsWalkFinalStaged => registry.register_bonding(<stages::points::WalkStage<
                C::NestedCurve,
                J::PolyWitnesses,
            > as StageExt<C::CircuitField, R>>::final_mask(
            )?),
            BindEndoscalarCircuit => registry
                .register_internal_circuit(circuits::bind_endoscalar::Circuit::<C, R, J>::new())?,
            EndoscalingStep(step) => registry.register_internal_circuit(
                circuits::endoscaling_step::Circuit::<C, R, J>::new(step as usize),
            )?,
            Hashes1Circuit => {
                registry.register_internal_circuit(circuits::hashes_1::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    J,
                    RevdotParameters,
                >::new(params, log2_circuits))?
            }
            Hashes2Circuit => registry.register_internal_circuit(circuits::hashes_2::Circuit::<
                C,
                R,
                HEADER_SIZE,
                J,
                RevdotParameters,
            >::new(params))?,
            InnerCollapseCircuit => {
                registry.register_internal_circuit(circuits::inner_collapse::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    J,
                    RevdotParameters,
                >::new())?
            }
            OuterCollapseCircuit => {
                registry.register_internal_circuit(circuits::outer_collapse::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    J,
                    RevdotParameters,
                >::new())?
            }
            ComputeVCircuit => {
                registry.register_internal_circuit(circuits::compute_v::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    J,
                >::new())?
            }
            BindChallengesCircuit(k) => {
                crate::with_binder!(k, C, R, HEADER_SIZE, J, params, |circuit| {
                    registry.register_internal_circuit(circuit)?
                })
            }
            BindBetaCircuit => {
                registry.register_internal_circuit(circuits::bind_beta::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    J,
                    RevdotParameters,
                >::new(params))?
            }
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + InternalCircuitIndex::num(polys),
        "internal circuit count mismatch"
    );

    Ok(registry)
}
