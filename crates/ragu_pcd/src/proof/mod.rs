//! Proof and proof-carrying data structures.
//!
//! Defines the [`Proof`] structure containing trace polynomials, commitments,
//! and accumulated claims, along with [`Pcd`] which bundles a [`Proof`] with
//! the data that a [`Header`] succinctly encodes. Fields are organized by
//! protocol phase (application proof, folding, query/evaluation, and
//! commitment opening) alongside verifier challenges and bridge/nested-curve
//! data, kept flat to make verification and proof transformation explicit.

#![allow(dead_code)]

pub(crate) mod builder;
// Keep this beneath `proof` so the equivalence helper can inspect private
// `Proof` fields while the backend-equivalence suite remains consolidated.
// TODO: Revisit this temporary layout; for now, it keeps all
// backend-equivalence tests consolidated in a single subdirectory.
#[cfg(test)]
#[path = "../../tests/backend_equivalence/proof.rs"]
mod proof_equivalence;
// Mutable component access for the corruption vocabulary (see
// `crate::fuzzing`). Its source lives with the rest of the fuzzing surface in
// `src/fuzzing/`, but it is mounted here, as a child of `proof`, so it can
// reach the private `Cached` fields without loosening them. The file gates
// itself behind `unstable-fuzzing` with an inner `#![cfg]`, so no feature
// attribute appears here.
// TODO: Revisit this layout; for now, it keeps the fuzzing surface in one
// directory without loosening `Proof`'s privacy or adding a feature
// attribute here.
#[path = "../fuzzing/access.rs"]
mod access;

use alloc::{sync::Arc, vec, vec::Vec};

pub(crate) use builder::ProofBuilder;
use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::{MultiStage, StageExt},
};
use ragu_core::Result;
use ragu_primitives::{
    extract_endoscalar, lift_endoscalar,
    vec::{FixedVec, Len},
};

use crate::{
    header::Header,
    internal::{
        endoscalar::{
            EndoscalarStage, EndoscalingStep, EndoscalingStepWitness, NumStepsLen, PointsStage,
            PointsWitness,
        },
        native::{self, RxComponent, RxIndex},
        nested,
        nested::NUM_ENDOSCALING_POINTS,
    },
};

/// A newtype marking a field as derived/cacheable.
///
/// Wraps a value that can be recomputed from primary proof data. Used to
/// distinguish commitment caches from primary polynomial fields at the type
/// level. Immutable once constructed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cached<T>(T);

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    proof: Proof<C, R>,
    data: H::Data,
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Pcd<C, R, H> {
    /// Returns a reference to the data that the proof accompanies.
    pub fn data(&self) -> &H::Data {
        &self.data
    }

    /// Returns a reference to the recursive proof.
    pub fn proof(&self) -> &Proof<C, R> {
        &self.proof
    }

    /// Consumes the proof-carrying data and returns the proof and data
    /// separately.
    pub fn into_parts(self) -> (Proof<C, R>, H::Data) {
        (self.proof, self.data)
    }
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Clone for Pcd<C, R, H> {
    fn clone(&self) -> Self {
        Pcd {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
    }
}

/// The Horner fold of `polys` under `beta`, the first weighted highest: the
/// batch polynomial whose commitment the endoscaling walk over the
/// polynomials' commitments computes.
fn beta_fold<F: Field, R: Rank>(
    polys: &[&sparse::Polynomial<F, R>],
    beta: F,
) -> sparse::Polynomial<F, R> {
    let (first, rest) = polys.split_first().expect("at least one polynomial");
    rest.iter().fold((*first).clone(), |mut acc, poly| {
        acc.scale(beta);
        acc.add_assign(poly);
        acc
    })
}

/// The blinding of a cached bridge polynomial, as a distinct power of the
/// proof's `bridge_alpha`; shared by the builder that derives the bridge and
/// the verifier that rederives it.
pub(crate) fn bridge_alpha_power<F: Field>(bridge_alpha: F, idx: nested::RxIndex) -> F {
    let n = match idx {
        nested::RxIndex::BridgeAB => 2,
        _ => panic!("not a cached bridge: {idx:?}"),
    };
    bridge_alpha.pow_vartime([n])
}

/// Represents a recursive proof for the correctness of some computation.
///
/// All fields are flat (no nested component structs). Polynomial fields are
/// primary data; commitment fields are `Cached` values derivable from
/// polynomials, which [`verify`](crate::Application::verify) rederives
/// rather than trusts. The `ab` bridge polynomial is also `Cached`,
/// derivable from `bridge_alpha` and native commitments; the other seven
/// carry prover-chosen data (the nested fold's error terms and the nested
/// batch's values among them) and are primary.
#[derive(Clone)]
pub struct Proof<C: Cycle, R: Rank> {
    /// Shared alpha source for deriving cached bridge polynomial alphas.
    pub(crate) bridge_alpha: C::ScalarField,

    // Application metadata
    pub(crate) circuit_id: CircuitIndex,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,

    // Native rx polynomials (CircuitField, HostCurve commitment)
    pub(crate) native_application_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_preamble_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_inner_error_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_outer_error_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_a_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_b_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_query_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_registry_xy_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_eval_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_p_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_hashes_1_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_hashes_2_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_inner_collapse_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_outer_collapse_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_compute_v_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_bind_challenges_rxs: Vec<sparse::Polynomial<C::CircuitField, R>>,
    pub(crate) native_bind_beta_rx: sparse::Polynomial<C::CircuitField, R>,
    // The native endoscaling walk over the nested batch's commitments: the
    // endoscalar binding circuit, the steps, and the endoscalar, points
    // inputs and points interstitials stages.
    pub(crate) native_bind_endoscalar_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_endoscaling_step_rxs: Vec<sparse::Polynomial<C::CircuitField, R>>,
    pub(crate) native_endoscalar_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_inputs_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_interstitials_rx: sparse::Polynomial<C::CircuitField, R>,

    // Bridge rx polynomials (non-cached, set by caller)
    pub(crate) bridge_preamble_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_s_prime_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_inner_error_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_outer_error_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_query_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_f_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_eval_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,

    // Bridge rx polynomial (cached, derived from bridge_alpha + native commitments)
    bridge_ab_rx: Cached<Arc<sparse::Polynomial<C::ScalarField, R>>>,

    // Nested endoscaling data (ScalarField, NestedCurve commitment)
    pub(crate) nested_endoscaling_step_rxs: Vec<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) nested_endoscalar_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_points_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,

    // Nested accumulator polynomials (ScalarField, NestedCurve commitment):
    // the children's nested claims, folded.
    pub(crate) nested_a_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_b_poly: sparse::Polynomial<C::ScalarField, R>,

    // Nested batch polynomials (ScalarField, NestedCurve commitment): the
    // $m_n(W, x_n, y_n)$ restriction, and the batch accumulated into $p_n$.
    pub(crate) nested_registry_xy_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_p_poly: sparse::Polynomial<C::ScalarField, R>,

    // Nested challenge and beta stages (ScalarField, unblinded NestedCurve
    // commitments): the lifts of this step's challenges, bound by the native
    // binding circuits (the beta stage by the parent's).
    pub(crate) nested_challenges_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_beta_rx: sparse::Polynomial<C::ScalarField, R>,

    // Nested instance circuits (ScalarField, NestedCurve commitments): the
    // export circuit pins the nested unified instance to the stages, the
    // collapse circuit verifies the nested fold, and the compute-v circuit
    // the nested batch evaluation.
    pub(crate) nested_export_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_collapse_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_compute_v_rx: sparse::Polynomial<C::ScalarField, R>,

    // Nested endoscaling commitment caches
    nested_endoscaling_step_commitments: Vec<Cached<C::NestedCurve>>,
    nested_endoscalar_commitment: Cached<C::NestedCurve>,
    nested_points_commitment: Cached<C::NestedCurve>,

    // Nested accumulator commitment caches
    nested_a_commitment: Cached<C::NestedCurve>,
    nested_b_commitment: Cached<C::NestedCurve>,

    // Nested batch commitment caches
    nested_registry_xy_commitment: Cached<C::NestedCurve>,
    nested_p_commitment: Cached<C::NestedCurve>,

    // Nested challenge and beta stage commitment caches
    nested_challenges_commitment: Cached<C::NestedCurve>,
    nested_beta_commitment: Cached<C::NestedCurve>,

    // Nested instance circuit commitment caches
    nested_export_commitment: Cached<C::NestedCurve>,
    nested_collapse_commitment: Cached<C::NestedCurve>,
    nested_compute_v_commitment: Cached<C::NestedCurve>,

    // Challenges
    pub(crate) w: C::CircuitField,
    pub(crate) y: C::CircuitField,
    pub(crate) z: C::CircuitField,
    pub(crate) mu: C::CircuitField,
    pub(crate) nu: C::CircuitField,
    pub(crate) mu_prime: C::CircuitField,
    pub(crate) nu_prime: C::CircuitField,
    pub(crate) x: C::CircuitField,
    pub(crate) alpha: C::CircuitField,
    pub(crate) u: C::CircuitField,
    pub(crate) pre_beta: C::CircuitField,

    // Native commitment caches
    native_application_commitment: Cached<C::HostCurve>,
    native_preamble_commitment: Cached<C::HostCurve>,
    native_inner_error_commitment: Cached<C::HostCurve>,
    native_outer_error_commitment: Cached<C::HostCurve>,
    native_a_commitment: Cached<C::HostCurve>,
    native_b_commitment: Cached<C::HostCurve>,
    native_query_commitment: Cached<C::HostCurve>,
    native_registry_xy_commitment: Cached<C::HostCurve>,
    native_eval_commitment: Cached<C::HostCurve>,
    native_p_commitment: Cached<C::HostCurve>,
    native_hashes_1_commitment: Cached<C::HostCurve>,
    native_hashes_2_commitment: Cached<C::HostCurve>,
    native_inner_collapse_commitment: Cached<C::HostCurve>,
    native_outer_collapse_commitment: Cached<C::HostCurve>,
    native_compute_v_commitment: Cached<C::HostCurve>,
    native_bind_challenges_commitments: Vec<Cached<C::HostCurve>>,
    native_bind_beta_commitment: Cached<C::HostCurve>,
    native_bind_endoscalar_commitment: Cached<C::HostCurve>,
    native_endoscaling_step_commitments: Vec<Cached<C::HostCurve>>,
    native_endoscalar_commitment: Cached<C::HostCurve>,
    native_points_inputs_commitment: Cached<C::HostCurve>,
    native_points_interstitials_commitment: Cached<C::HostCurve>,

    // Bridge commitments (non-cached)
    pub(crate) bridge_preamble_commitment: C::NestedCurve,
    pub(crate) bridge_s_prime_commitment: C::NestedCurve,
    pub(crate) bridge_inner_error_commitment: C::NestedCurve,
    pub(crate) bridge_outer_error_commitment: C::NestedCurve,
    pub(crate) bridge_query_commitment: C::NestedCurve,
    pub(crate) bridge_f_commitment: C::NestedCurve,
    pub(crate) bridge_eval_commitment: C::NestedCurve,

    // Bridge commitment (cached, derived from the cached bridge rx)
    bridge_ab_commitment: Cached<C::NestedCurve>,
}

impl<C: Cycle, R: Rank> core::ops::Index<RxIndex> for Proof<C, R> {
    type Output = sparse::Polynomial<C::CircuitField, R>;
    fn index(&self, idx: RxIndex) -> &sparse::Polynomial<C::CircuitField, R> {
        use RxIndex::*;
        match idx {
            Preamble => &self.native_preamble_rx,
            InnerError => &self.native_inner_error_rx,
            OuterError => &self.native_outer_error_rx,
            Query => &self.native_query_rx,
            Eval => &self.native_eval_rx,
            Application => &self.native_application_rx,
            Hashes1 => &self.native_hashes_1_rx,
            Hashes2 => &self.native_hashes_2_rx,
            InnerCollapse => &self.native_inner_collapse_rx,
            OuterCollapse => &self.native_outer_collapse_rx,
            ComputeV => &self.native_compute_v_rx,
            BindChallenges(k) => &self.native_bind_challenges_rxs[k as usize],
            BindBeta => &self.native_bind_beta_rx,
            BindEndoscalar => &self.native_bind_endoscalar_rx,
            EndoscalingStep(step) => &self.native_endoscaling_step_rxs[step as usize],
            EndoscalarStage => &self.native_endoscalar_rx,
            PointsInputs => &self.native_points_inputs_rx,
            PointsInterstitials => &self.native_points_interstitials_rx,
        }
    }
}

impl<C: Cycle, R: Rank> core::ops::Index<RxComponent> for Proof<C, R> {
    type Output = sparse::Polynomial<C::CircuitField, R>;
    fn index(&self, component: RxComponent) -> &sparse::Polynomial<C::CircuitField, R> {
        match component {
            RxComponent::AbA => &self.native_a_poly,
            RxComponent::AbB => &self.native_b_poly,
            RxComponent::Rx(idx) => &self[idx],
        }
    }
}

impl<C: Cycle, R: Rank> core::ops::Index<nested::RxIndex> for Proof<C, R> {
    type Output = sparse::Polynomial<C::ScalarField, R>;
    fn index(&self, idx: nested::RxIndex) -> &sparse::Polynomial<C::ScalarField, R> {
        use nested::RxIndex::*;
        match idx {
            EndoscalingStep(step) => &self.nested_endoscaling_step_rxs[step as usize],
            Export => &self.nested_export_rx,
            Collapse => &self.nested_collapse_rx,
            ComputeV => &self.nested_compute_v_rx,
            EndoscalarStage => &self.nested_endoscalar_rx,
            PointsStage => self.nested_points_rx.as_ref(),
            BridgePreamble => self.bridge_preamble_rx.as_ref(),
            BridgeSPrime => self.bridge_s_prime_rx.as_ref(),
            BridgeInnerError => self.bridge_inner_error_rx.as_ref(),
            BridgeOuterError => self.bridge_outer_error_rx.as_ref(),
            BridgeAB => self.bridge_ab_rx.0.as_ref(),
            BridgeQuery => self.bridge_query_rx.as_ref(),
            BridgeF => self.bridge_f_rx.as_ref(),
            BridgeEval => self.bridge_eval_rx.as_ref(),
            ChallengeStage => &self.nested_challenges_rx,
            BetaStage => &self.nested_beta_rx,
        }
    }
}

impl<C: Cycle, R: Rank> core::ops::Index<nested::RxComponent> for Proof<C, R> {
    type Output = sparse::Polynomial<C::ScalarField, R>;
    fn index(&self, component: nested::RxComponent) -> &sparse::Polynomial<C::ScalarField, R> {
        match component {
            nested::RxComponent::AbA => &self.nested_a_poly,
            nested::RxComponent::AbB => &self.nested_b_poly,
            nested::RxComponent::Rx(idx) => &self[idx],
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> Pcd<C, R, H> {
        Pcd { proof: self, data }
    }

    // TODO: Route this witness-value computation through the selected backend
    // without making `Proof` backend-parametric or threading `c` through the
    // backend-independent stage-witness APIs.
    /// Returns the revdot product $c = \text{revdot}(A, B)$ for witness
    /// generation.
    ///
    /// This computes witness data, not circuit structure. An exact-equivalent
    /// backend implementation would leave the synthesized constraints unchanged.
    pub(crate) fn native_c(&self) -> C::CircuitField {
        self.native_a_poly.revdot(&self.native_b_poly)
    }

    // TODO: Route this witness-value computation through the selected backend
    // without making `Proof` backend-parametric or threading `v` through the
    // backend-independent stage-witness APIs.
    /// Returns the evaluation $v = p(u)$ for witness generation.
    ///
    /// As with [`Self::native_c`], this computes witness data, not circuit structure.
    /// An exact-equivalent backend implementation would leave the synthesized
    /// constraints unchanged.
    pub(crate) fn v(&self) -> C::CircuitField {
        self.native_p_poly.eval(self.u)
    }

    /// Returns the nested accumulator's revdot product
    /// $c = \text{revdot}(a, b)$ in the scalar field.
    ///
    /// As with [`Self::native_c`], this computes witness data, not circuit structure.
    pub(crate) fn nested_c(&self) -> C::ScalarField {
        self.nested_a_poly.revdot(&self.nested_b_poly)
    }

    /// Returns the nested batch's evaluation $v_n = p_n(u_n)$, at the nested
    /// counterpart of $u$.
    ///
    /// As with [`Self::v`], this computes witness data, not circuit structure.
    pub(crate) fn nested_v(&self) -> Result<C::ScalarField> {
        Ok(self.nested_p_poly.eval(nested::challenge::<C>(self.u)?))
    }

    pub(crate) fn nested_registry_xy_poly(&self) -> &sparse::Polynomial<C::ScalarField, R> {
        &self.nested_registry_xy_poly
    }

    pub(crate) fn nested_p_poly(&self) -> &sparse::Polynomial<C::ScalarField, R> {
        &self.nested_p_poly
    }

    pub(crate) fn nested_challenges_rx(&self) -> &sparse::Polynomial<C::ScalarField, R> {
        &self.nested_challenges_rx
    }

    pub(crate) fn nested_challenges_commitment(&self) -> C::NestedCurve {
        self.nested_challenges_commitment.0
    }

    pub(crate) fn nested_beta_rx(&self) -> &sparse::Polynomial<C::ScalarField, R> {
        &self.nested_beta_rx
    }

    pub(crate) fn nested_beta_commitment(&self) -> C::NestedCurve {
        self.nested_beta_commitment.0
    }

    pub(crate) fn nested_export_commitment(&self) -> C::NestedCurve {
        self.nested_export_commitment.0
    }

    pub(crate) fn nested_collapse_commitment(&self) -> C::NestedCurve {
        self.nested_collapse_commitment.0
    }

    pub(crate) fn nested_compute_v_commitment(&self) -> C::NestedCurve {
        self.nested_compute_v_commitment.0
    }

    /// This proof's nested unified instance, as its export circuit
    /// serialized it: the accumulator value, the batch evaluation, the lifts
    /// of $x$, $y$ and $u$, and the exported host-curve commitments.
    pub(crate) fn nested_instance(&self) -> Result<nested::unified::Instance<C::HostCurve>> {
        Ok(nested::unified::Instance {
            c: self.nested_c(),
            v: self.nested_v()?,
            x: nested::challenge::<C>(self.x)?,
            y: nested::challenge::<C>(self.y)?,
            u: nested::challenge::<C>(self.u)?,
            exported: [
                self.native_rx_commitment(RxIndex::Preamble),
                self.native_rx_commitment(RxIndex::InnerError),
                self.native_rx_commitment(RxIndex::OuterError),
                self.native_rx_commitment(RxIndex::Query),
                self.native_rx_commitment(RxIndex::Eval),
                self.native_commitment(RxComponent::AbA),
                self.native_commitment(RxComponent::AbB),
                self.native_registry_xy_commitment(),
                self.native_p_commitment(),
                self.native_rx_commitment(RxIndex::PointsInputs),
            ],
            coverage: Default::default(),
        })
    }

    /// Whether this proof's children were both trivial proofs: the base case
    /// of the recursion, read off the children's output headers exactly as
    /// the native preamble does.
    pub(crate) fn is_base_case<const HEADER_SIZE: usize>(&self) -> bool {
        let is_trivial = |header: &[C::CircuitField]| {
            header.len() == HEADER_SIZE && header[HEADER_SIZE - 1] == C::CircuitField::ONE
        };
        is_trivial(&self.left_header) && is_trivial(&self.right_header)
    }

    /// The native challenges of this proof, in challenge-stage order.
    pub(crate) fn challenges(&self) -> nested::Challenges<C::CircuitField> {
        nested::Challenges {
            w: self.w,
            y: self.y,
            z: self.z,
            mu: self.mu,
            nu: self.nu,
            mu_prime: self.mu_prime,
            nu_prime: self.nu_prime,
            x: self.x,
            alpha: self.alpha,
            u: self.u,
            pre_beta: self.pre_beta,
        }
    }

    pub(crate) fn circuit_id(&self) -> CircuitIndex {
        self.circuit_id
    }

    pub(crate) fn left_header(&self) -> &[C::CircuitField] {
        &self.left_header
    }

    pub(crate) fn right_header(&self) -> &[C::CircuitField] {
        &self.right_header
    }

    pub(crate) fn native_registry_xy_poly(&self) -> &sparse::Polynomial<C::CircuitField, R> {
        &self.native_registry_xy_poly
    }

    pub(crate) fn native_p_poly(&self) -> &sparse::Polynomial<C::CircuitField, R> {
        &self.native_p_poly
    }

    pub(crate) fn w(&self) -> C::CircuitField {
        self.w
    }

    pub(crate) fn y(&self) -> C::CircuitField {
        self.y
    }

    pub(crate) fn z(&self) -> C::CircuitField {
        self.z
    }

    pub(crate) fn mu(&self) -> C::CircuitField {
        self.mu
    }

    pub(crate) fn nu(&self) -> C::CircuitField {
        self.nu
    }

    pub(crate) fn mu_prime(&self) -> C::CircuitField {
        self.mu_prime
    }

    pub(crate) fn nu_prime(&self) -> C::CircuitField {
        self.nu_prime
    }

    pub(crate) fn x(&self) -> C::CircuitField {
        self.x
    }

    pub(crate) fn alpha(&self) -> C::CircuitField {
        self.alpha
    }

    pub(crate) fn u(&self) -> C::CircuitField {
        self.u
    }

    pub(crate) fn pre_beta(&self) -> C::CircuitField {
        self.pre_beta
    }

    /// Returns the native commitment for the given [`RxIndex`].
    pub(crate) fn native_rx_commitment(&self, idx: RxIndex) -> C::HostCurve {
        use RxIndex::*;
        match idx {
            Preamble => self.native_preamble_commitment.0,
            InnerError => self.native_inner_error_commitment.0,
            OuterError => self.native_outer_error_commitment.0,
            Query => self.native_query_commitment.0,
            Eval => self.native_eval_commitment.0,
            Application => self.native_application_commitment.0,
            Hashes1 => self.native_hashes_1_commitment.0,
            Hashes2 => self.native_hashes_2_commitment.0,
            InnerCollapse => self.native_inner_collapse_commitment.0,
            OuterCollapse => self.native_outer_collapse_commitment.0,
            ComputeV => self.native_compute_v_commitment.0,
            BindChallenges(k) => self.native_bind_challenges_commitments[k as usize].0,
            BindBeta => self.native_bind_beta_commitment.0,
            BindEndoscalar => self.native_bind_endoscalar_commitment.0,
            EndoscalingStep(step) => self.native_endoscaling_step_commitments[step as usize].0,
            EndoscalarStage => self.native_endoscalar_commitment.0,
            PointsInputs => self.native_points_inputs_commitment.0,
            PointsInterstitials => self.native_points_interstitials_commitment.0,
        }
    }

    /// Returns the native commitment for the given [`RxComponent`].
    pub(crate) fn native_commitment(&self, component: RxComponent) -> C::HostCurve {
        match component {
            RxComponent::AbA => self.native_a_commitment.0,
            RxComponent::AbB => self.native_b_commitment.0,
            RxComponent::Rx(idx) => self.native_rx_commitment(idx),
        }
    }

    pub(crate) fn native_registry_xy_commitment(&self) -> C::HostCurve {
        self.native_registry_xy_commitment.0
    }

    pub(crate) fn native_p_commitment(&self) -> C::HostCurve {
        self.native_p_commitment.0
    }

    pub(crate) fn bridge_preamble_commitment(&self) -> C::NestedCurve {
        self.bridge_preamble_commitment
    }

    pub(crate) fn bridge_s_prime_commitment(&self) -> C::NestedCurve {
        self.bridge_s_prime_commitment
    }

    pub(crate) fn bridge_inner_error_commitment(&self) -> C::NestedCurve {
        self.bridge_inner_error_commitment
    }

    pub(crate) fn bridge_f_commitment(&self) -> C::NestedCurve {
        self.bridge_f_commitment
    }

    pub(crate) fn bridge_outer_error_commitment(&self) -> C::NestedCurve {
        self.bridge_outer_error_commitment
    }

    pub(crate) fn bridge_ab_commitment(&self) -> C::NestedCurve {
        self.bridge_ab_commitment.0
    }

    pub(crate) fn bridge_query_commitment(&self) -> C::NestedCurve {
        self.bridge_query_commitment
    }

    pub(crate) fn bridge_eval_commitment(&self) -> C::NestedCurve {
        self.bridge_eval_commitment
    }

    pub(crate) fn nested_endoscaling_step_commitment(&self, step: u32) -> C::NestedCurve {
        self.nested_endoscaling_step_commitments[step as usize].0
    }

    pub(crate) fn nested_endoscalar_commitment(&self) -> C::NestedCurve {
        self.nested_endoscalar_commitment.0
    }

    pub(crate) fn nested_points_commitment(&self) -> C::NestedCurve {
        self.nested_points_commitment.0
    }

    pub(crate) fn nested_a_commitment(&self) -> C::NestedCurve {
        self.nested_a_commitment.0
    }

    pub(crate) fn nested_b_commitment(&self) -> C::NestedCurve {
        self.nested_b_commitment.0
    }

    pub(crate) fn nested_registry_xy_commitment(&self) -> C::NestedCurve {
        self.nested_registry_xy_commitment.0
    }

    pub(crate) fn nested_p_commitment(&self) -> C::NestedCurve {
        self.nested_p_commitment.0
    }

    /// Returns the nested commitment for one of this proof's nested rx
    /// components.
    pub(crate) fn nested_rx_commitment(&self, idx: nested::RxIndex) -> C::NestedCurve {
        use nested::RxIndex::*;
        match idx {
            EndoscalingStep(step) => self.nested_endoscaling_step_commitment(step),
            EndoscalarStage => self.nested_endoscalar_commitment(),
            PointsStage => self.nested_points_commitment(),
            BridgePreamble => self.bridge_preamble_commitment,
            BridgeSPrime => self.bridge_s_prime_commitment,
            BridgeInnerError => self.bridge_inner_error_commitment,
            BridgeOuterError => self.bridge_outer_error_commitment,
            BridgeAB => self.bridge_ab_commitment.0,
            BridgeQuery => self.bridge_query_commitment,
            BridgeF => self.bridge_f_commitment,
            BridgeEval => self.bridge_eval_commitment,
            ChallengeStage => self.nested_challenges_commitment.0,
            BetaStage => self.nested_beta_commitment.0,
            Export => self.nested_export_commitment.0,
            Collapse => self.nested_collapse_commitment.0,
            ComputeV => self.nested_compute_v_commitment.0,
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    crate::Application<'_, C, R, HEADER_SIZE, B>
{
    /// Runs endoscaling over the host-curve commitments that feed
    /// `PointsStage`, in the order `compute_p` (`_10_p.rs`)
    /// accumulates them. Writes `nested_endoscalar_rx`,
    /// `nested_points_rx`, and `nested_endoscaling_step_rxs` onto
    /// `builder`, and returns the accumulated `p` commitment (last
    /// `PointsStage` interstitial) together with the points witness the
    /// nested circuits load.
    ///
    /// Shared by `compute_p` (in `fuse/_10_p.rs`) and by
    /// [`trivial_proof`](Self::trivial_proof), so the nested
    /// endoscaling setup lives in one place.
    pub(crate) fn compute_endoscaling<RNG: ragu_arithmetic::rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: u128,
        points: &[C::HostCurve],
        endoscalar_alpha: C::ScalarField,
        points_alpha: C::ScalarField,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        C::HostCurve,
        PointsWitness<C::HostCurve, NUM_ENDOSCALING_POINTS>,
    )> {
        assert_eq!(points.len(), NUM_ENDOSCALING_POINTS);

        let witness = PointsWitness::<C::HostCurve, NUM_ENDOSCALING_POINTS>::new(beta_endo, points);

        let endoscalar_rx =
            <EndoscalarStage as StageExt<C::ScalarField, R>>::rx(endoscalar_alpha, beta_endo)?;
        let points_rx = <PointsStage<C::HostCurve, NUM_ENDOSCALING_POINTS> as StageExt<
            C::ScalarField,
            R,
        >>::rx(points_alpha, &witness)?;

        let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();
        let mut step_rxs = Vec::with_capacity(num_steps);
        for step in 0..num_steps {
            let step_circuit =
                EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(step);
            let staged = MultiStage::new(step_circuit);
            let step_trace = staged
                .trace(EndoscalingStepWitness {
                    endoscalar: beta_endo,
                    points: &witness,
                })?
                .into_output();
            let step_rx = self.nested_registry.assemble(
                &step_trace,
                nested::InternalCircuitIndex::EndoscalingStep(step as u32).circuit_index(),
                rng,
            )?;
            step_rxs.push(step_rx);
        }

        builder.set_nested_endoscaling_step_rxs(step_rxs);
        builder.set_nested_endoscalar_rx(endoscalar_rx);
        builder.set_nested_points_rx(points_rx);

        let p_commitment = *witness
            .interstitials
            .last()
            .expect("NUM_ENDOSCALING_POINTS guarantees at least one interstitial");
        Ok((p_commitment, witness))
    }

    /// Commits the native points inputs stage over the nested batch's
    /// commitments (`points`, in [`pcs::Batch::evaluated`] order after
    /// $f_n$'s), before $\beta$ is squeezed. Returns the witness the walk
    /// consumes.
    ///
    /// [`pcs::Batch::evaluated`]: nested::pcs::Batch::evaluated
    pub(crate) fn commit_native_points_inputs<RNG: ragu_arithmetic::rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        points: &[C::NestedCurve],
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<
        native::stages::points::InputsWitness<C::NestedCurve, { native::NUM_ENDOSCALING_POINTS }>,
    > {
        let witness = native::stages::points::InputsWitness::new(points);
        let rx = <native::stages::points::InputsStage<
            C::NestedCurve,
            { native::NUM_ENDOSCALING_POINTS },
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(&mut *rng), &witness
        )?;
        builder.set_native_points_inputs_rx(rx);
        Ok(witness)
    }

    /// Runs the native endoscaling over the committed inputs: walks them
    /// under `beta_endo`, commits the endoscalar and points interstitials
    /// stages, traces the steps, and writes all of it onto `builder`.
    /// Returns $P_n$ (the last interstitial) with the interstitials witness.
    ///
    /// Shared by `compute_p` (in `fuse/_10_p.rs`) and
    /// [`trivial_proof`](Self::trivial_proof), like
    /// [`compute_endoscaling`](Self::compute_endoscaling) on the nested side.
    pub(crate) fn compute_native_endoscaling<RNG: ragu_arithmetic::rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: u128,
        inputs: &native::stages::points::InputsWitness<
            C::NestedCurve,
            { native::NUM_ENDOSCALING_POINTS },
        >,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        C::NestedCurve,
        native::stages::points::InterstitialsWitness<
            C::NestedCurve,
            { native::NUM_ENDOSCALING_POINTS },
        >,
    )> {
        use native::stages::points::{InterstitialsStage, InterstitialsWitness};
        const N: usize = native::NUM_ENDOSCALING_POINTS;

        let points: Vec<C::NestedCurve> = core::iter::once(inputs.initial)
            .chain(inputs.inputs.iter().copied())
            .collect();
        let walk = PointsWitness::<C::NestedCurve, N>::new(beta_endo, &points);
        let interstitials = InterstitialsWitness::from(walk);

        let endoscalar_rx = <EndoscalarStage as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(&mut *rng),
            beta_endo,
        )?;
        let interstitials_rx = <InterstitialsStage<C::NestedCurve, N> as StageExt<
            C::CircuitField,
            R,
        >>::rx(C::CircuitField::random(&mut *rng), &interstitials)?;

        let mut step_rxs = Vec::with_capacity(native::NUM_ENDOSCALING_STEPS);
        for step in 0..native::NUM_ENDOSCALING_STEPS {
            let trace =
                native::circuits::endoscaling_step::Circuit::<C::NestedCurve, R, N>::new(step)
                    .trace(native::circuits::endoscaling_step::Witness {
                        endoscalar: beta_endo,
                        inputs,
                        interstitials: &interstitials,
                    })?
                    .into_output();
            step_rxs.push(self.native_registry.assemble(
                &trace,
                native::InternalCircuitIndex::EndoscalingStep(step as u32).circuit_index(),
                &mut *rng,
            )?);
        }

        builder.set_native_endoscalar_rx(endoscalar_rx);
        builder.set_native_points_interstitials_rx(interstitials_rx);
        builder.set_native_endoscaling_step_rxs(step_rxs);

        let p_commitment = *interstitials
            .interstitials
            .last()
            .expect("NUM_ENDOSCALING_POINTS guarantees at least one interstitial");
        Ok((p_commitment, interstitials))
    }

    pub(crate) fn trivial_pcd(&self) -> Pcd<C, R, ()> {
        self.trivial_proof().carry(())
    }

    pub(crate) fn trivial_proof(&self) -> Proof<C, R> {
        let ones_host = {
            let mut view = sparse::View::<_, R, _>::trace();
            view.a.push(C::CircuitField::ONE);
            view.b.push(C::CircuitField::ONE);
            view.c.push(C::CircuitField::ONE);
            view.d.push(C::CircuitField::ONE);
            view.build()
        };
        let host_commitment =
            B::sparse_commit_to_affine(&ones_host, C::host_generators(self.params));
        let ones_nested = {
            let mut view = sparse::View::<_, R, _>::trace();
            view.a.push(C::ScalarField::ONE);
            view.b.push(C::ScalarField::ONE);
            view.c.push(C::ScalarField::ONE);
            view.d.push(C::ScalarField::ONE);
            view.build()
        };

        // registry_xy must be the actual registry evaluation (fuse cross-checks it).
        let registry_xy_poly = B::registry_xy(
            &self.native_registry,
            C::CircuitField::ONE,
            C::CircuitField::ONE,
        );
        // The nested counterpart, at the nested counterparts of the all-one
        // challenges below: a parent opens it at its own nested w.
        let nested_one = nested::challenge::<C>(C::CircuitField::ONE)
            .expect("one is in the endoscalar challenge range");
        let nested_registry_xy_poly = B::registry_xy(&self.nested_registry, nested_one, nested_one);
        // The all-one challenges, and their lifts on the nested side.
        let challenges = nested::Challenges {
            w: C::CircuitField::ONE,
            y: C::CircuitField::ONE,
            z: C::CircuitField::ONE,
            mu: C::CircuitField::ONE,
            nu: C::CircuitField::ONE,
            mu_prime: C::CircuitField::ONE,
            nu_prime: C::CircuitField::ONE,
            x: C::CircuitField::ONE,
            alpha: C::CircuitField::ONE,
            u: C::CircuitField::ONE,
            pre_beta: C::CircuitField::ONE,
        };
        let lifts = challenges
            .lifts::<C>()
            .expect("one is in the endoscalar challenge range");

        let mut builder = ProofBuilder::<C, R, B>::new(self.params, C::ScalarField::ONE);

        builder.set_circuit_id(CircuitIndex::new(0));
        builder.set_left_header(vec![C::CircuitField::ZERO; HEADER_SIZE]);
        builder.set_right_header(vec![C::CircuitField::ZERO; HEADER_SIZE]);

        // Native rx polynomials (all trivial ones)
        builder.set_native_application_rx(ones_host.clone());
        builder.set_native_preamble_rx(ones_host.clone());
        builder.set_native_inner_error_rx(ones_host.clone());
        builder.set_native_outer_error_rx(ones_host.clone());
        builder.set_native_a_poly(ones_host.clone(), host_commitment);
        builder.set_native_b_poly(ones_host.clone(), host_commitment);
        builder.set_native_query_rx(ones_host.clone());
        builder.set_native_registry_xy_poly(registry_xy_poly);
        // The eval stage carries the binding partial sums over the challenge
        // lifts; a trivial proof's are those of the all-one challenges.
        builder.set_native_eval_rx(
            native::stages::eval::Stage::<C, R, HEADER_SIZE>::rx(
                C::CircuitField::ONE,
                &native::stages::eval::Witness::<C>::trivial(
                    native::stages::eval::BindingPartials::compute::<C, R, B>(
                        self.params,
                        &lifts[..native::circuits::bind_challenges::NUM_BOUND],
                        true,
                    ),
                ),
            )
            .expect("trivial eval rx"),
        );
        // native_p_poly: deferred until after endoscaling computation,
        // since the real p commitment is the PointsStage last interstitial.
        builder.set_native_hashes_1_rx(ones_host.clone());
        builder.set_native_hashes_2_rx(ones_host.clone());
        builder.set_native_inner_collapse_rx(ones_host.clone());
        builder.set_native_outer_collapse_rx(ones_host.clone());
        builder.set_native_compute_v_rx(ones_host.clone());
        builder.set_native_bind_challenges_rxs(vec![ones_host.clone(); native::NUM_BINDERS]);
        builder.set_native_bind_beta_rx(ones_host.clone());
        builder.set_native_bind_endoscalar_rx(ones_host.clone());

        // Nested accumulator: a trivial claim (all-ones traces), so that a
        // trivial child contributes a well-formed raw claim to its parent's
        // nested fold. The nested batch is trivial too, except for the
        // registry restriction a parent opens. Commitments are computed
        // lazily by the builder, except P_n, which the native walk below
        // computes.
        builder.set_nested_a_poly(ones_nested.clone());
        builder.set_nested_b_poly(ones_nested.clone());
        builder.set_nested_registry_xy_poly(nested_registry_xy_poly);

        let beta_endo = extract_endoscalar(C::CircuitField::ONE)
            .expect("one should satisfy the endoscalar challenge range");
        let mut trivial_rng =
            <ragu_arithmetic::rand::rngs::StdRng as ragu_arithmetic::rand::SeedableRng>::from_seed(
                [0u8; 32],
            );

        // The native walk over placeholder nested-curve points, in the
        // nested batch's order, delegated to the real helpers so this
        // trivial setup cannot drift from the prover path. Its result is
        // this proof's P_n.
        // Every placeholder is the commitment of a polynomial this proof
        // holds, so that p_n is their beta-fold and P_n its commitment, as
        // a parent's batch requires of a child.
        let (nested_p_poly, nested_p_commitment) = {
            let nested_commitment =
                B::sparse_commit_to_affine(&ones_nested, C::nested_generators(self.params));
            let registry_xy_commitment = builder.nested_registry_xy_commitment();
            let mut points = Vec::with_capacity(native::NUM_ENDOSCALING_POINTS);
            let mut polys: Vec<&sparse::Polynomial<C::ScalarField, R>> =
                Vec::with_capacity(native::NUM_ENDOSCALING_POINTS);
            let mut push = |point, poly| {
                points.push(point);
                polys.push(poly);
            };
            let registry_xy = builder.nested_registry_xy_poly();
            push(nested_commitment, &ones_nested); // f_n
            for _ in 0..2 {
                for _ in &nested::RxIndex::ALL {
                    push(nested_commitment, &ones_nested);
                }
                push(nested_commitment, &ones_nested); // a
                push(nested_commitment, &ones_nested); // b
                push(registry_xy_commitment, registry_xy); // registry_xy
                push(nested_commitment, &ones_nested); // p placeholder
            }
            push(nested_commitment, &ones_nested); // registry_wx0
            push(nested_commitment, &ones_nested); // registry_wx1
            push(nested_commitment, &ones_nested); // registry_wy
            push(nested_commitment, &ones_nested); // a
            push(nested_commitment, &ones_nested); // b
            push(registry_xy_commitment, registry_xy); // registry_xy
            let poly = beta_fold(&polys, lift_endoscalar(beta_endo));
            let inputs = self
                .commit_native_points_inputs(&mut trivial_rng, &points, &mut builder)
                .expect("trivial native points inputs");
            let (commitment, _) = self
                .compute_native_endoscaling(&mut trivial_rng, beta_endo, &inputs, &mut builder)
                .expect("trivial native endoscaling");
            (poly, commitment)
        };
        builder.set_nested_p_poly(nested_p_poly, nested_p_commitment);

        // The challenge and beta stages hold the lifts of the all-one
        // challenges, unblinded, exactly as a real fuse would commit them. A
        // trivial proof's children are trivial, so its base-case sign is set.
        let (challenge_lifts, beta_lift) = lifts.split_at(nested::stages::challenges::NUM);
        builder.set_nested_challenges_rx(
            nested::stages::challenges::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ZERO,
                &nested::stages::challenges::Witness::new(
                    challenge_lifts.try_into().expect("NUM challenge lifts"),
                    true,
                ),
            )
            .expect("trivial challenge stage rx"),
        );
        builder.set_nested_export_rx(ones_nested.clone());
        builder.set_nested_collapse_rx(ones_nested.clone());
        builder.set_nested_compute_v_rx(ones_nested);
        builder.set_nested_beta_rx(
            nested::stages::beta::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ZERO,
                nested::stages::beta::Witness { lift: beta_lift[0] },
            )
            .expect("trivial beta stage rx"),
        );

        // Bridge polynomials: compute via Stage::rx() with trivial witnesses
        // so that traces are valid for their witnesses (not just ones).
        // The cached bridge (ab) is already computed lazily by the builder
        // via cached_bridge! with a proper witness.
        //
        // Order: s_prime, inner_error, outer_error, query, f, eval first
        // (independent of p_commitment), then endoscaling (computes
        // p_commitment), then preamble (needs p_commitment for
        // ChildWitness.p), then native_p_poly.
        let nested_gen = C::nested_generators(self.params);
        {
            let rx = nested::stages::s_prime::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ONE,
                &nested::stages::s_prime::Witness {
                    registry_wx0: host_commitment,
                    registry_wx1: host_commitment,
                },
            )
            .expect("trivial s_prime rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_s_prime_rx(rx, commitment);
        }
        {
            let rx = nested::stages::inner_error::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ONE,
                &nested::stages::inner_error::Witness {
                    native_inner_error: host_commitment,
                    registry_wy: host_commitment,
                    // A trivial proof folds nothing, so its nested fold has
                    // no error terms.
                    error_terms: FixedVec::from_fn(|_| FixedVec::from_fn(|_| C::ScalarField::ZERO)),
                },
            )
            .expect("trivial inner_error rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_inner_error_rx(rx, commitment);
        }
        {
            let rx = nested::stages::outer_error::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ONE,
                &nested::stages::outer_error::Witness {
                    native_outer_error: builder.native_outer_error_commitment(),
                    error_terms: FixedVec::from_fn(|_| C::ScalarField::ZERO),
                    collapsed: FixedVec::from_fn(|_| C::ScalarField::ZERO),
                },
            )
            .expect("trivial outer_error rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_outer_error_rx(rx, commitment);
        }
        {
            let rx = nested::stages::query::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ONE,
                &nested::stages::query::Witness {
                    native_query: builder.native_query_commitment(),
                    registry_xy: builder.native_registry_xy_commitment(),
                    nested: nested::stages::query::Evaluations::zero(),
                },
            )
            .expect("trivial query rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_query_rx(rx, commitment);
        }
        {
            let rx = nested::stages::f::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ONE,
                &nested::stages::f::Witness {
                    native_f: host_commitment,
                },
            )
            .expect("trivial f rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_f_rx(rx, commitment);
        }
        {
            let rx = nested::stages::eval::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ONE,
                &nested::stages::eval::Witness {
                    native_eval: builder.native_eval_commitment(),
                    native_points_inputs: builder.native_points_inputs_commitment(),
                    nested: nested::stages::eval::Evaluations::zero(),
                },
            )
            .expect("trivial eval rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_eval_rx(rx, commitment);
        }

        // Build dummy PointsStage inputs in `_10_p` accumulation order
        // and delegate to `compute_endoscaling` so this trivial setup
        // cannot silently drift from the real prover path.
        // As on the nested side: every placeholder is the commitment of a
        // polynomial this proof holds, p is their beta-fold, and P is the
        // walk's result, which is then p's commitment.
        let (p_poly, p_commitment) = {
            let mut points = Vec::with_capacity(NUM_ENDOSCALING_POINTS);
            let mut polys: Vec<&sparse::Polynomial<C::CircuitField, R>> =
                Vec::with_capacity(NUM_ENDOSCALING_POINTS);
            let mut push = |point, poly| {
                points.push(point);
                polys.push(poly);
            };
            let registry_xy_commitment = builder.native_registry_xy_commitment();
            let registry_xy = builder.native_registry_xy_poly();

            // Initial: native_f commitment.
            push(host_commitment, &ones_host);

            // Per-child block: all per-child commitments are
            // `host_commitment` (ones_host), except registry_xy which
            // has its own commitment.
            for _ in 0..2 {
                for _ in &RxIndex::ALL {
                    push(host_commitment, &ones_host);
                }
                push(host_commitment, &ones_host); // AbA
                push(host_commitment, &ones_host); // AbB
                push(registry_xy_commitment, registry_xy); // RegistryXY
                push(host_commitment, &ones_host); // P placeholder
            }

            // Current-step bridge inputs.
            push(host_commitment, &ones_host); // registry_wx0
            push(host_commitment, &ones_host); // registry_wx1
            push(host_commitment, &ones_host); // registry_wy
            push(host_commitment, &ones_host); // a
            push(host_commitment, &ones_host); // b
            push(registry_xy_commitment, registry_xy); // native_registry_xy

            let poly = beta_fold(&polys, lift_endoscalar(beta_endo));
            let (commitment, _) = self
                .compute_endoscaling(
                    &mut trivial_rng,
                    beta_endo,
                    &points,
                    C::ScalarField::ONE,
                    C::ScalarField::ONE,
                    &mut builder,
                )
                .expect("trivial endoscaling");
            (poly, commitment)
        };

        // Set native_p_poly with the real accumulated commitment.
        builder.set_native_p_poly(p_poly, p_commitment);

        // Preamble bridge: computed last because ChildWitness.p needs
        // the real p_commitment from endoscaling.
        {
            let registry_xy_commitment = builder.native_registry_xy_commitment();
            let trivial_child_witness = nested::stages::preamble::ChildWitness {
                application: host_commitment,
                hashes_1: host_commitment,
                hashes_2: host_commitment,
                inner_collapse: host_commitment,
                outer_collapse: host_commitment,
                compute_v: host_commitment,
                bind_challenges: [host_commitment; native::NUM_BINDERS],
                bind_beta: host_commitment,
                bind_endoscalar: host_commitment,
                endoscaling_steps: [host_commitment; native::NUM_ENDOSCALING_STEPS],
                endoscalar_stage: host_commitment,
                points_interstitials: host_commitment,
                stashed_preamble: host_commitment,
                stashed_inner_error: host_commitment,
                stashed_outer_error: host_commitment,
                stashed_query: host_commitment,
                stashed_eval: host_commitment,
                stashed_ab_a: host_commitment,
                stashed_ab_b: host_commitment,
                stashed_registry_xy: registry_xy_commitment,
                stashed_p: p_commitment,
                stashed_points_inputs: builder.native_points_inputs_commitment(),
                // What a parent will read off this proof as its nested
                // instance scalars: a trivial "child" is this proof itself.
                nested: nested::stages::preamble::NestedValues {
                    c: builder.nested_c(),
                    v: B::sparse_eval(builder.nested_p_poly(), nested_one),
                    x: nested_one,
                    y: nested_one,
                    u: nested_one,
                },
            };
            let rx = nested::stages::preamble::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ONE,
                &nested::stages::preamble::Witness {
                    native_preamble: host_commitment,
                    left: trivial_child_witness.clone(),
                    right: trivial_child_witness,
                },
            )
            .expect("trivial preamble rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_preamble_rx(rx, commitment);
        }

        // Challenges (all ones for trivial)
        builder.set_w(C::CircuitField::ONE);
        builder.set_y(C::CircuitField::ONE);
        builder.set_z(C::CircuitField::ONE);
        builder.set_mu(C::CircuitField::ONE);
        builder.set_nu(C::CircuitField::ONE);
        builder.set_mu_prime(C::CircuitField::ONE);
        builder.set_nu_prime(C::CircuitField::ONE);
        builder.set_x(C::CircuitField::ONE);
        builder.set_alpha(C::CircuitField::ONE);
        builder.set_u(C::CircuitField::ONE);
        builder.set_pre_beta(C::CircuitField::ONE);

        // Commitments are computed lazily by the builder from the polynomials.
        builder.build().expect("trivial proof construction failed")
    }
}
