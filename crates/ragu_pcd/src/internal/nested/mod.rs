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

use core::marker::PhantomData;

use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::{MultiStage, StageExt},
};
use ragu_core::{Cycle, Result};
use ragu_primitives::{extract_endoscalar, lift_endoscalar, vec::Len};
use udon::field::Field;

pub mod circuits {
    pub mod collapse;
    pub mod common;
    pub mod compute_v;
    pub mod export;
    pub mod loading;
}

use crate::internal::{
    endoscalar,
    fold_revdot::Parameters,
    native::{self, RxIndex as NativeRxIndex},
};

/// One child's block in the `_10_p` commitment walk, for a native walk of
/// `native_steps` steps: its native rx commitments, four extras (`ab_a`,
/// `ab_b`, `registry_xy`, `p`), and one stashed commitment per witnessed
/// polynomial. Shared with the nested preamble and the native eval stage, so
/// the accumulation, stash, and `v` fold orders cannot drift apart.
pub const fn child_endoscaling_points_at(polys: usize, native_steps: usize) -> usize {
    NativeRxIndex::num_with_steps(native_steps) + 4 + polys
}

/// [`child_endoscaling_points_at`] at the native walk `polys` fixes.
pub const fn child_endoscaling_points(polys: usize) -> usize {
    child_endoscaling_points_at(polys, native::num_endoscaling_steps(polys))
}

/// Number of curve points accumulated during `compute_p` for nested field
/// endoscaling verification, for a native walk of `native_steps` steps: the
/// native batch's commitments.
///
/// This is `f`'s commitment, then for each child its native rx commitments,
/// $a$, $b$, `registry_xy`, $p$ and its witnessed polynomials, then the
/// current step's two `registry_wx`, `registry_wy`, $a$, $b$ and
/// `registry_xy`. See `_10_p` for the canonical accumulation order.
pub const fn num_endoscaling_points_at(polys: usize, native_steps: usize) -> usize {
    // The leading point is `f.commitment`'s base point.
    1 + 2 * child_endoscaling_points_at(polys, native_steps) + 6
}

/// [`num_endoscaling_points_at`] at the native walk `polys` fixes. The
/// endoscaling circuits process these points across
/// [`num_endoscaling_steps`] steps.
pub const fn num_endoscaling_points(polys: usize) -> usize {
    num_endoscaling_points_at(polys, native::num_endoscaling_steps(polys))
}

/// The endoscalings a nested step performs: what fits a step beside the
/// stages it reserves, which hold every point the walk consumes.
pub const ENDOSCALINGS_PER_STEP: usize = 4;

/// Number of nested endoscaling steps for a native walk of `native_steps`
/// steps, via [`endoscalar::num_steps`].
pub const fn num_endoscaling_steps_at(polys: usize, native_steps: usize) -> usize {
    endoscalar::num_steps::<ENDOSCALINGS_PER_STEP>(num_endoscaling_points_at(polys, native_steps))
}

/// The number of nested endoscaling step circuits a fuse runs, derived from
/// [`num_endoscaling_points`] via [`endoscalar::num_steps`].
pub const fn num_endoscaling_steps(polys: usize) -> usize {
    num_endoscaling_steps_at(polys, native::num_endoscaling_steps(polys))
}

/// [`num_endoscaling_points`] at the type level, for a poly count `L`.
pub struct PointsLen<L: Len>(PhantomData<L>);

impl<L: Len> Len for PointsLen<L> {
    fn len() -> usize {
        num_endoscaling_points(L::len())
    }
}

/// The nested points stage, over the native batch's commitments.
pub type PointsStage<C, L> = endoscalar::PointsStage<C, PointsLen<L>, ENDOSCALINGS_PER_STEP>;

/// The nested points stage's witness.
pub type PointsWitness<C, L> = endoscalar::PointsWitness<C, PointsLen<L>, ENDOSCALINGS_PER_STEP>;

/// The nested points stage's output gadget.
pub type Points<'dr, D, C, L> = endoscalar::Points<'dr, D, C, PointsLen<L>, ENDOSCALINGS_PER_STEP>;

/// A nested endoscaling step.
pub type EndoscalingStep<C, R, L> =
    endoscalar::EndoscalingStep<C, R, PointsLen<L>, ENDOSCALINGS_PER_STEP>;

/// A nested endoscaling step's witness.
pub type EndoscalingStepWitness<'source, C, L> =
    endoscalar::EndoscalingStepWitness<'source, C, PointsLen<L>, ENDOSCALINGS_PER_STEP>;

/// Length type for the nested endoscaling steps.
pub type NumStepsLen<L> = endoscalar::NumStepsLen<PointsLen<L>, ENDOSCALINGS_PER_STEP>;

/// The number of circuits whose public input is the nested [`unified`]
/// instance: export, collapse and compute-v.
pub const NUM_INSTANCE_CIRCUITS: usize = 3;

/// The number of bonding kinds the nested claims fold across children: the
/// stage masks, the two final staged masks and the loading circuit.
const NUM_BONDING_KINDS: usize = 14;

/// The nested revdot claims of a fuse of two children: one raw accumulator
/// claim each, one circuit claim each per endoscaling step and per instance
/// circuit, and one bonding claim per bonding kind (each bonding kind is
/// $z$-folded across both children).
pub const fn num_claims(polys: usize) -> usize {
    2 + 2 * (num_endoscaling_steps(polys) + NUM_INSTANCE_CIRCUITS) + NUM_BONDING_KINDS
}

/// The claims one fold group takes.
const GROUP_SIZE: usize = 7;

/// The fold groups an application witnessing `polys` polynomials per step
/// needs: never fewer than twelve, which leaves a little room over the 78
/// claims of a layout without polynomials (twenty-eight steps, three instance
/// circuits and fourteen bonding kinds), and as many more as its longer
/// walk's claims fill.
pub const fn num_groups(polys: usize) -> usize {
    let needed = num_claims(polys).div_ceil(GROUP_SIZE);
    if needed > 12 { needed } else { 12 }
}

/// [`num_groups`] at the type level, for a poly count `L`.
pub struct NumGroups<L: Len>(PhantomData<L>);

impl<L: Len> Len for NumGroups<L> {
    fn len() -> usize {
        num_groups(L::len())
    }
}

/// Parameters for folding the children's nested-field revdot claims, for a
/// poly count `L`; see [`num_groups`].
pub struct RevdotParameters<L>(PhantomData<L>);

// Derives would demand `L: Clone` and so on, which a `Len` marker need not be.
impl<L> Clone for RevdotParameters<L> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<L> Copy for RevdotParameters<L> {}

impl<L> Default for RevdotParameters<L> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<L: Len> Parameters for RevdotParameters<L> {
    type NumGroups = NumGroups<L>;
    type GroupSize = ragu_primitives::vec::ConstLen<GROUP_SIZE>;
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
}

impl InternalCircuitIndex {
    /// The number of internal circuits registered by [`register_all`] for an
    /// application witnessing `polys` polynomials per step: one per entry of
    /// [`all`](Self::all).
    pub const fn num(polys: usize) -> usize {
        num_endoscaling_steps(polys) + NUM_INSTANCE_CIRCUITS + 14
    }

    /// The circuits whose public input is the nested [`unified`] instance,
    /// in claim order.
    pub const INSTANCE: [Self; NUM_INSTANCE_CIRCUITS] =
        [Self::Export, Self::Collapse, Self::ComputeV];

    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before masks), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this list.
    pub fn all(polys: usize) -> impl Iterator<Item = Self> + Clone {
        (0..num_endoscaling_steps(polys) as u32)
            .map(Self::EndoscalingStep)
            .chain([
                Self::Export,
                Self::Collapse,
                Self::ComputeV,
                Self::EndoscalarStage,
                Self::PointsStage,
                Self::PointsFinalStaged,
                Self::BridgePreamble,
                Self::BridgeSPrime,
                Self::BridgeInnerError,
                Self::BridgeOuterError,
                Self::BridgeAB,
                Self::BridgeQuery,
                Self::BridgeF,
                Self::BridgeEval,
                Self::ChallengeStage,
                Self::ChallengeFinalStaged,
                Self::Loading,
            ])
    }

    /// Convert to a [`CircuitIndex`] for registry lookup, in the registry of
    /// an application witnessing `polys` polynomials per step.
    ///
    /// Circuit indices follow the `RegistryBuilder::finalize()` concatenation
    /// order: internal circuits first, then internal masks.
    pub fn circuit_index(self, polys: usize) -> CircuitIndex {
        let pos = Self::all(polys)
            .position(|v| v == self)
            .expect("every variant appears in `all`");
        CircuitIndex::new(pos)
    }
}

/// Enum identifying which nested field rx polynomial to retrieve from a proof.
///
/// Analogous to [`native::RxIndex`] for the scalar
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
}

impl RxIndex {
    /// The number of rx components in the nested field for an application
    /// witnessing `polys` polynomials per step, equal to the number of
    /// entries in [`RxIndex::all`].
    pub const fn num(polys: usize) -> usize {
        Self::num_with_steps(num_endoscaling_steps(polys))
    }

    /// [`num`](Self::num) for a nested walk of `steps` steps.
    pub const fn num_with_steps(steps: usize) -> usize {
        steps + NUM_INSTANCE_CIRCUITS + 11
    }

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
    /// [`native::RxIndex::all`](super::native::RxIndex::all).
    pub fn all(polys: usize) -> impl Iterator<Item = Self> + Clone {
        Self::all_with_steps(num_endoscaling_steps(polys))
    }

    /// [`all`](Self::all) for a nested walk of `steps` steps.
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
        const TAIL: [RxIndex; NUM_INSTANCE_CIRCUITS + 11] = [
            RxIndex::Export,
            RxIndex::Collapse,
            RxIndex::ComputeV,
            RxIndex::EndoscalarStage,
            RxIndex::PointsStage,
            RxIndex::BridgePreamble,
            RxIndex::BridgeSPrime,
            RxIndex::BridgeInnerError,
            RxIndex::BridgeOuterError,
            RxIndex::BridgeAB,
            RxIndex::BridgeQuery,
            RxIndex::BridgeF,
            RxIndex::BridgeEval,
            RxIndex::ChallengeStage,
        ];
        if i < steps {
            Self::EndoscalingStep(i as u32)
        } else {
            TAIL[i - steps]
        }
    }

    /// The position of `self` in [`all`](Self::all).
    pub fn position(self, polys: usize) -> usize {
        Self::all(polys)
            .position(|v| v == self)
            .expect("every variant appears in `all`")
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
pub fn register_all<'params, C: Cycle, R: Rank, L: Len>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();

    // Circuits first, then masks — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    for id in InternalCircuitIndex::all(L::len()) {
        use InternalCircuitIndex::*;
        registry = match id {
            EndoscalingStep(step) => {
                let step_circuit = self::EndoscalingStep::<C::HostCurve, R, L>::new(step as usize);
                let staged = MultiStage::new(step_circuit);
                registry.register_internal_circuit(staged)?
            }
            Export => {
                let circuit = circuits::export::Circuit::<C::HostCurve, R, L>::new();
                registry.register_internal_circuit(MultiStage::new(circuit))?
            }
            Collapse => {
                let circuit = circuits::collapse::Circuit::<C::HostCurve, R, L>::new();
                registry.register_internal_circuit(MultiStage::new(circuit))?
            }
            ComputeV => {
                let circuit = circuits::compute_v::Circuit::<C::HostCurve, R, L>::new();
                registry.register_internal_circuit(MultiStage::new(circuit))?
            }
            EndoscalarStage => registry.register_bonding(endoscalar::EndoscalarStage::mask()?),
            PointsStage => registry.register_bonding(self::PointsStage::<C::HostCurve, L>::mask()?),
            PointsFinalStaged => {
                registry.register_bonding(self::PointsStage::<C::HostCurve, L>::final_mask()?)
            }
            BridgePreamble => {
                registry.register_bonding(stages::preamble::Stage::<C::HostCurve, R, L>::mask()?)
            }
            BridgeSPrime => {
                registry.register_bonding(stages::s_prime::Stage::<C::HostCurve, R, L>::mask()?)
            }
            BridgeInnerError => {
                registry.register_bonding(stages::inner_error::Stage::<C::HostCurve, R, L>::mask()?)
            }
            BridgeOuterError => {
                registry.register_bonding(stages::outer_error::Stage::<C::HostCurve, R, L>::mask()?)
            }
            BridgeAB => registry.register_bonding(stages::ab::Stage::<C::HostCurve, R, L>::mask()?),
            BridgeQuery => {
                registry.register_bonding(stages::query::Stage::<C::HostCurve, R, L>::mask()?)
            }
            BridgeF => registry.register_bonding(stages::f::Stage::<C::HostCurve, R, L>::mask()?),
            BridgeEval => {
                registry.register_bonding(stages::eval::Stage::<C::HostCurve, R, L>::mask()?)
            }
            ChallengeStage => {
                registry.register_bonding(stages::challenges::Stage::<C::HostCurve, R, L>::mask()?)
            }
            ChallengeFinalStaged => registry.register_bonding(stages::challenges::Stage::<
                C::HostCurve,
                R,
                L,
            >::final_mask()?),
            Loading => {
                let circuit = circuits::loading::Circuit::<C::HostCurve, R, L>::new();
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
        };
    }

    // `circuit_index` scans the same `all` list, so the two agree by
    // construction; this checks that the registry took one slot per entry.
    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + InternalCircuitIndex::num(L::len()),
        "internal circuit count mismatch"
    );

    Ok(registry)
}
