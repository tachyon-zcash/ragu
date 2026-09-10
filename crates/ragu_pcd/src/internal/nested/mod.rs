//! Nested field circuits for the scalar field.
//!
//! Contains three groups of circuits:
//!
//! - **Endoscaling**: verifies that the commitment accumulation
//!   in `compute_p` was computed correctly via Horner's rule.
//! - **Loading**: enforces consistency between [`PointsStage`]
//!   inputs and the bridge stage commitments for the current step.
//! - **Copying**: enforces that [`ChildWitness`] stash fields in
//!   `BridgePreamble` match the corresponding child proof's bridge
//!   stage contents.
//!
//! [`ChildWitness`]: stages::preamble::ChildWitness
//! [`PointsStage`]: crate::internal::endoscalar::PointsStage

use ragu_arithmetic::Cycle;
use ragu_arithmetic::ff::Field;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::{MultiStage, StageExt},
};
use ragu_core::Result;
use ragu_primitives::{extract_endoscalar, lift_endoscalar, vec::ConstLen};

pub mod circuits {
    pub mod copying;
    pub mod loading;
}

use crate::internal::{Side, endoscalar, fold_revdot::Parameters};

/// Number of curve points accumulated during `compute_p` for nested field
/// endoscaling verification.
///
/// This is the sum of per-child commitment components (for both proofs),
/// current-step stage proof components, and the `f.commitment` base
/// polynomial. See `_10_p` for the canonical accumulation order.
///
/// The endoscaling circuits process these points across
/// [`NUM_ENDOSCALING_STEPS`] steps.
pub const NUM_ENDOSCALING_POINTS: usize = 37 + 2 * (crate::internal::native::NUM_BINDERS + 1);

/// Number of endoscaling steps, derived from [`NUM_ENDOSCALING_POINTS`] via
/// [`endoscalar::num_steps`].
const NUM_ENDOSCALING_STEPS: usize = endoscalar::num_steps(NUM_ENDOSCALING_POINTS);

/// Parameters for folding the children's nested-field revdot claims.
///
/// Two children contribute one raw accumulator claim each, one circuit claim
/// each per endoscaling step, and one bonding claim per bonding kind (each
/// bonding kind is $z$-folded across both children): 42 claims today, over
/// twelve steps and sixteen bonding kinds. The nested side will grow claims
/// as it gains circuits, and `8 x 7` leaves room for that without re-laying
/// the error stages.
#[derive(Clone, Copy, Default)]
pub struct RevdotParameters;

impl Parameters for RevdotParameters {
    type NumGroups = ConstLen<8>;
    type GroupSize = ConstLen<7>;
}

/// Derives the nested-field counterpart of a native Fiat-Shamir challenge.
///
/// The nested side squeezes nothing itself: every challenge it consumes is the
/// endoscalar lift, in the scalar field, of the low 128 bits of the
/// corresponding native challenge, the derivation `compute_p` already applies
/// to `pre_beta`.
///
/// The protocol requires the relevant nested commitments to be bound into
/// the native transcript before the challenge, and the consuming circuits
/// to use this same lifted value. This helper performs only the scalar
/// conversion; it does not establish those recursive bindings or enforce
/// the nested fold in-circuit.
///
/// # Errors
///
/// Fails when the native challenge lies at or above $2^{\mathtt{CAPACITY}}$,
/// a $2^{-129}$ event for a transcript output.
pub fn challenge<C: Cycle>(native: C::CircuitField) -> Result<C::ScalarField> {
    Ok(lift_endoscalar(extract_endoscalar(native)?))
}

/// The native challenges the nested side consumes, in the order the
/// challenge stage holds their lifts (see [`stages::challenges`]), with
/// `pre_beta` last (its lift is the [`stages::beta`] stage).
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
    /// Beta stage mask.
    BetaStage,
    /// Loading circuit over all nested stages.
    Loading,
    /// Copying circuit relating current preamble to a child proof's stages.
    Copying(Side),
}

impl InternalCircuitIndex {
    /// The number of internal circuits registered by [`register_all`],
    /// equal to the number of entries in [`InternalCircuitIndex::ALL`].
    pub const NUM: usize = NUM_ENDOSCALING_STEPS + 16;

    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before masks), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this array.
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
        push(&mut slots, &mut c, Self::BetaStage);
        push(&mut slots, &mut c, Self::Loading);
        push(&mut slots, &mut c, Self::Copying(Side::Left));
        push(&mut slots, &mut c, Self::Copying(Side::Right));
        assert!(c == Self::NUM);
        slots
    }

    /// Convert to a [`CircuitIndex`] for registry lookup.
    ///
    /// Circuit indices follow the `RegistryBuilder::finalize()` concatenation
    /// order: internal circuits first, then internal masks.
    pub fn circuit_index(self) -> CircuitIndex {
        let pos = Self::ALL
            .iter()
            .position(|&v| v == self)
            .expect("every variant appears in ALL");
        CircuitIndex::new(pos)
    }
}

/// Enum identifying which nested field rx polynomial to retrieve from a proof.
///
/// Analogous to [`native::RxIndex`](super::native::RxIndex) for the scalar
/// field. Each variant maps to a polynomial in
/// the proof's nested-field polynomial storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildBridgeKind {
    /// Child proof's `BridgeSPrime` rx polynomial.
    SPrime,
    /// Child proof's `BridgeInnerError` rx polynomial.
    InnerError,
    /// Child proof's `BridgeOuterError` rx polynomial.
    OuterError,
    /// Child proof's `BridgeAB` rx polynomial.
    AB,
    /// Child proof's `BridgeQuery` rx polynomial.
    Query,
    /// Child proof's `BridgeEval` rx polynomial.
    Eval,
}

impl ChildBridgeKind {
    /// All kinds in the canonical slot order.
    ///
    /// This constant is the source of truth for the relative order of
    /// `RxIndex::ChildBridge(kind, side)` entries in [`RxIndex::ALL`]
    /// (see [`RxIndex::all_slots`]), and is therefore pinned by
    /// `test_nested_registry_digest` — re-ordering these variants
    /// changes the nested registry digest.
    pub const ALL: [Self; 6] = [
        Self::SPrime,
        Self::InnerError,
        Self::OuterError,
        Self::AB,
        Self::Query,
        Self::Eval,
    ];
}

#[derive(Clone, Copy, Debug)]
pub enum RxIndex {
    /// EndoscalingStep circuit rx polynomial (indexed by step number).
    EndoscalingStep(u32),
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
    /// Beta stage rx polynomial.
    BetaStage,
    /// Child proof's `PointsStage` rx polynomial (per-side, for copying).
    ChildPointsStage(Side),
    /// Child proof's bridge rx polynomial (per-side, for copying),
    /// keyed by which bridge stage it comes from.
    ChildBridge(ChildBridgeKind, Side),
}

impl RxIndex {
    /// The number of rx components in the nested field,
    /// equal to the number of entries in [`RxIndex::ALL`].
    pub const NUM: usize = NUM_ENDOSCALING_STEPS + 26;

    /// The number of rx components a proof carries for its own step: the
    /// endoscaling steps and stages, without the children's copies.
    pub const NUM_OWN: usize = NUM_ENDOSCALING_STEPS + 12;

    /// A proof's own rx components, in canonical order: the leading
    /// [`NUM_OWN`](Self::NUM_OWN) entries of [`ALL`](Self::ALL).
    pub const OWN: [Self; Self::NUM_OWN] = {
        let mut out = [Self::EndoscalarStage; Self::NUM_OWN];
        let mut i = 0;
        while i < Self::NUM_OWN {
            out[i] = Self::ALL[i];
            i += 1;
        }
        out
    };

    /// All variants in canonical order (circuits, then stages).
    ///
    /// Must maintain the same ordering convention as
    /// [`native::RxIndex::ALL`](super::native::RxIndex::ALL).
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
        push(&mut slots, &mut c, Self::BetaStage);
        push(&mut slots, &mut c, Self::ChildPointsStage(Side::Left));
        push(&mut slots, &mut c, Self::ChildPointsStage(Side::Right));
        {
            let mut i = 0;
            while i < ChildBridgeKind::ALL.len() {
                let kind = ChildBridgeKind::ALL[i];
                push(&mut slots, &mut c, Self::ChildBridge(kind, Side::Left));
                push(&mut slots, &mut c, Self::ChildBridge(kind, Side::Right));
                i += 1;
            }
        }
        assert!(c == Self::NUM);
        slots
    }
}

/// Identifies a nested-field polynomial within a proof: either one of the
/// two accumulator polynomials (which are not rx polynomials) or one of the
/// rx polynomials addressed by [`RxIndex`].
#[derive(Clone, Copy, Debug)]
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

pub mod stages {
    pub mod ab;
    pub mod beta;
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
pub fn register_all<'params, C: Cycle, R: Rank>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();

    // Circuits first, then masks — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    for &id in &InternalCircuitIndex::ALL {
        use InternalCircuitIndex::*;
        registry = match id {
            EndoscalingStep(step) => {
                let step_circuit =
                    endoscalar::EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(
                        step as usize,
                    );
                let staged = MultiStage::new(step_circuit);
                registry.register_internal_circuit(staged)?
            }
            EndoscalarStage => registry.register_bonding(endoscalar::EndoscalarStage::mask()?),
            PointsStage => registry.register_bonding(endoscalar::PointsStage::<
                C::HostCurve,
                NUM_ENDOSCALING_POINTS,
            >::mask()?),
            PointsFinalStaged => registry.register_bonding(endoscalar::PointsStage::<
                C::HostCurve,
                NUM_ENDOSCALING_POINTS,
            >::final_mask()?),
            BridgePreamble => {
                registry.register_bonding(stages::preamble::Stage::<C::HostCurve, R>::mask()?)
            }
            BridgeSPrime => {
                registry.register_bonding(stages::s_prime::Stage::<C::HostCurve, R>::mask()?)
            }
            BridgeInnerError => {
                registry.register_bonding(stages::inner_error::Stage::<C::HostCurve, R>::mask()?)
            }
            BridgeOuterError => {
                registry.register_bonding(stages::outer_error::Stage::<C::HostCurve, R>::mask()?)
            }
            BridgeAB => registry.register_bonding(stages::ab::Stage::<C::HostCurve, R>::mask()?),
            BridgeQuery => {
                registry.register_bonding(stages::query::Stage::<C::HostCurve, R>::mask()?)
            }
            BridgeF => registry.register_bonding(stages::f::Stage::<C::HostCurve, R>::mask()?),
            BridgeEval => {
                registry.register_bonding(stages::eval::Stage::<C::HostCurve, R>::mask()?)
            }
            ChallengeStage => {
                registry.register_bonding(stages::challenges::Stage::<C::HostCurve, R>::mask()?)
            }
            BetaStage => registry.register_bonding(stages::beta::Stage::<C::HostCurve, R>::mask()?),
            Loading => {
                let circuit = circuits::loading::Circuit::<C::HostCurve, R>::new();
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
            Copying(side) => {
                let circuit = circuits::copying::Circuit::<C::HostCurve, R>::new(side);
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + InternalCircuitIndex::NUM,
        "internal circuit count mismatch"
    );

    Ok(registry)
}
