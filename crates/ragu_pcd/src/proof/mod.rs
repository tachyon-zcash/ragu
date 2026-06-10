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

use alloc::{vec, vec::Vec};

pub(crate) use builder::ProofBuilder;
use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::{MultiStage, StageExt},
};
use ragu_core::Result;
use ragu_primitives::{extract_endoscalar, vec::Len};

use crate::{
    header::Header,
    internal::{
        endoscalar::{
            EndoscalarStage, EndoscalingStep, EndoscalingStepWitness, NumStepsLen, PointsStage,
            PointsWitness,
        },
        native::{RxComponent, RxIndex},
        nested,
        nested::{ChildBridgeKind, NUM_ENDOSCALING_POINTS},
    },
};

/// A newtype marking a field as derived/cacheable.
///
/// Wraps a value that can be recomputed from primary proof data. Used to
/// distinguish commitment caches from primary polynomial fields at the type
/// level. Immutable once constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub(crate) fn proof(&self) -> &Proof<C, R> {
        &self.proof
    }

    /// Consumes the proof-carrying data and returns the proof and data
    /// separately.
    pub(crate) fn into_parts(self) -> (Proof<C, R>, H::Data) {
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

/// Stage rx polynomials from a child proof, stored so the verifier can
/// check copying circuit claims.
#[derive(Clone)]
pub(crate) struct ChildStageRx<F: ragu_arithmetic::ff::PrimeField, R: Rank> {
    pub points_stage: sparse::Polynomial<F, R>,
    pub bridge_s_prime: sparse::Polynomial<F, R>,
    pub bridge_inner_error: sparse::Polynomial<F, R>,
    pub bridge_outer_error: sparse::Polynomial<F, R>,
    pub bridge_ab: sparse::Polynomial<F, R>,
    pub bridge_query: sparse::Polynomial<F, R>,
    pub bridge_eval: sparse::Polynomial<F, R>,
}

impl<F: ragu_arithmetic::ff::PrimeField, R: Rank> ChildStageRx<F, R> {
    /// Dispatch to the bridge-stage rx polynomial named by `kind`.
    pub(crate) fn bridge_at(&self, kind: ChildBridgeKind) -> &sparse::Polynomial<F, R> {
        match kind {
            ChildBridgeKind::SPrime => &self.bridge_s_prime,
            ChildBridgeKind::InnerError => &self.bridge_inner_error,
            ChildBridgeKind::OuterError => &self.bridge_outer_error,
            ChildBridgeKind::AB => &self.bridge_ab,
            ChildBridgeKind::Query => &self.bridge_query,
            ChildBridgeKind::Eval => &self.bridge_eval,
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Extract stage rx polynomials from this proof for storage as child
    /// data in a parent proof.
    //
    // TODO: wrap each child polynomial in `Arc` so this extraction can
    // share ownership instead of cloning every rx polynomial.
    pub(crate) fn as_child_stage_rx(&self) -> ChildStageRx<C::ScalarField, R> {
        ChildStageRx {
            points_stage: self.nested_points_rx.clone(),
            bridge_s_prime: self.bridge_s_prime_rx.clone(),
            bridge_inner_error: self.bridge_inner_error_rx.clone(),
            // .0 = polynomial (these are (poly, commitment) tuples from cached_bridge!)
            bridge_outer_error: self.bridge_outer_error_rx.0.clone(),
            bridge_ab: self.bridge_ab_rx.0.clone(),
            bridge_query: self.bridge_query_rx.0.clone(),
            bridge_eval: self.bridge_eval_rx.0.clone(),
        }
    }
}

/// Represents a recursive proof for the correctness of some computation.
///
/// All fields are flat (no nested component structs). Polynomial fields are
/// primary data; commitment fields are `Cached` values derivable from
/// polynomials. Four bridge polynomials (outer_error, ab, query, eval) are
/// also `Cached`, derivable from `bridge_alpha` and native commitments.
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

    // Bridge rx polynomials (non-cached, set by caller)
    pub(crate) bridge_preamble_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) bridge_s_prime_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) bridge_inner_error_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) bridge_f_rx: sparse::Polynomial<C::ScalarField, R>,

    // Bridge rx polynomials (cached, derived from bridge_alpha + native commitments)
    bridge_outer_error_rx: Cached<sparse::Polynomial<C::ScalarField, R>>,
    bridge_ab_rx: Cached<sparse::Polynomial<C::ScalarField, R>>,
    bridge_query_rx: Cached<sparse::Polynomial<C::ScalarField, R>>,
    bridge_eval_rx: Cached<sparse::Polynomial<C::ScalarField, R>>,

    // Nested endoscaling data (ScalarField, NestedCurve commitment)
    pub(crate) nested_endoscaling_step_rxs: Vec<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) nested_endoscalar_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_points_rx: sparse::Polynomial<C::ScalarField, R>,

    // Nested endoscaling commitment caches
    nested_endoscaling_step_commitments: Vec<Cached<C::NestedCurve>>,
    nested_endoscalar_commitment: Cached<C::NestedCurve>,
    nested_points_commitment: Cached<C::NestedCurve>,

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

    // Bridge commitments (non-cached)
    pub(crate) bridge_preamble_commitment: C::NestedCurve,
    pub(crate) bridge_s_prime_commitment: C::NestedCurve,
    pub(crate) bridge_inner_error_commitment: C::NestedCurve,
    pub(crate) bridge_f_commitment: C::NestedCurve,

    // Bridge commitments (cached, derived from cached bridge rx)
    bridge_outer_error_commitment: Cached<C::NestedCurve>,
    bridge_ab_commitment: Cached<C::NestedCurve>,
    bridge_query_commitment: Cached<C::NestedCurve>,
    bridge_eval_commitment: Cached<C::NestedCurve>,

    // Children's stage rx polynomials (for copying circuit claims)
    pub(crate) child_left_stage_rx: ChildStageRx<C::ScalarField, R>,
    pub(crate) child_right_stage_rx: ChildStageRx<C::ScalarField, R>,
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
            EndoscalarStage => &self.nested_endoscalar_rx,
            PointsStage => &self.nested_points_rx,
            BridgePreamble => &self.bridge_preamble_rx,
            BridgeSPrime => &self.bridge_s_prime_rx,
            BridgeInnerError => &self.bridge_inner_error_rx,
            BridgeOuterError => &self.bridge_outer_error_rx.0,
            BridgeAB => &self.bridge_ab_rx.0,
            BridgeQuery => &self.bridge_query_rx.0,
            BridgeF => &self.bridge_f_rx,
            BridgeEval => &self.bridge_eval_rx.0,
            ChildPointsStage(side) => &self.child_stage_rx(side).points_stage,
            ChildBridge(kind, side) => self.child_stage_rx(side).bridge_at(kind),
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    fn child_stage_rx(&self, side: crate::internal::Side) -> &ChildStageRx<C::ScalarField, R> {
        match side {
            crate::internal::Side::Left => &self.child_left_stage_rx,
            crate::internal::Side::Right => &self.child_right_stage_rx,
        }
    }

    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> Pcd<C, R, H> {
        Pcd { proof: self, data }
    }

    /// Returns the revdot product $c = \text{revdot}(A, B)$.
    pub(crate) fn c(&self) -> C::CircuitField {
        self.native_a_poly.revdot(&self.native_b_poly)
    }

    /// Returns the evaluation $v = p(u)$.
    pub(crate) fn v(&self) -> C::CircuitField {
        self.native_p_poly.eval(self.u)
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
        self.bridge_outer_error_commitment.0
    }

    pub(crate) fn bridge_ab_commitment(&self) -> C::NestedCurve {
        self.bridge_ab_commitment.0
    }

    pub(crate) fn bridge_query_commitment(&self) -> C::NestedCurve {
        self.bridge_query_commitment.0
    }

    pub(crate) fn bridge_eval_commitment(&self) -> C::NestedCurve {
        self.bridge_eval_commitment.0
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
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> crate::Application<'_, C, R, HEADER_SIZE> {
    /// Runs endoscaling over the host-curve commitments that feed
    /// `PointsStage`, in the order `compute_p` (`_10_p.rs`)
    /// accumulates them. Writes `nested_endoscalar_rx`,
    /// `nested_points_rx`, and `nested_endoscaling_step_rxs` onto
    /// `builder`, and returns the accumulated `p` commitment (last
    /// `PointsStage` interstitial).
    ///
    /// Shared by `compute_p` (in `fuse/_10_p.rs`) and by
    /// [`trivial_proof`](Self::trivial_proof), so the nested
    /// endoscaling setup lives in one place.
    pub(crate) fn compute_endoscaling<RNG: ragu_arithmetic::CryptoRngCore>(
        &self,
        rng: &mut RNG,
        beta_endo: u128,
        points: &[C::HostCurve],
        endoscalar_alpha: C::ScalarField,
        points_alpha: C::ScalarField,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<C::HostCurve> {
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

        Ok(*witness
            .interstitials
            .last()
            .expect("NUM_ENDOSCALING_POINTS guarantees at least one interstitial"))
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
        let host_commitment = ones_host.commit_to_affine(C::host_generators(self.params));

        // registry_xy must be the actual registry evaluation (fuse cross-checks it).
        let registry_xy_poly = self
            .native_registry
            .xy(C::CircuitField::ONE, C::CircuitField::ONE);

        let mut builder = ProofBuilder::new(self.params, C::ScalarField::ONE);

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
        builder.set_native_eval_rx(ones_host.clone());
        // native_p_poly: deferred until after endoscaling computation,
        // since the real p commitment is the PointsStage last interstitial.
        builder.set_native_hashes_1_rx(ones_host.clone());
        builder.set_native_hashes_2_rx(ones_host.clone());
        builder.set_native_inner_collapse_rx(ones_host.clone());
        builder.set_native_outer_collapse_rx(ones_host.clone());
        builder.set_native_compute_v_rx(ones_host.clone());

        // Bridge polynomials: compute via Stage::rx() with trivial witnesses
        // so that traces are valid for their witnesses (not just ones).
        // Cached bridges (outer_error, ab, query, eval) are already computed
        // lazily by the builder via cached_bridge! with proper witnesses.
        //
        // Order: s_prime, inner_error, f first (independent of p_commitment),
        // then endoscaling (computes p_commitment), then preamble (needs
        // p_commitment for ChildWitness.p), then native_p_poly.
        let nested_gen = C::nested_generators(self.params);
        {
            let rx = nested::stages::s_prime::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ONE,
                &nested::stages::s_prime::Witness {
                    registry_wx0: host_commitment,
                    registry_wx1: host_commitment,
                    stashed_preamble: host_commitment,
                },
            )
            .expect("trivial s_prime rx");
            let commitment = rx.commit_to_affine(nested_gen);
            builder.set_bridge_s_prime_rx(rx, commitment);
        }
        {
            let rx = nested::stages::inner_error::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ONE,
                &nested::stages::inner_error::Witness {
                    native_inner_error: host_commitment,
                    registry_wy: host_commitment,
                },
            )
            .expect("trivial inner_error rx");
            let commitment = rx.commit_to_affine(nested_gen);
            builder.set_bridge_inner_error_rx(rx, commitment);
        }
        {
            let rx = nested::stages::f::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ONE,
                &nested::stages::f::Witness {
                    native_f: host_commitment,
                },
            )
            .expect("trivial f rx");
            let commitment = rx.commit_to_affine(nested_gen);
            builder.set_bridge_f_rx(rx, commitment);
        }

        // Build dummy PointsStage inputs in `_10_p` accumulation order
        // and delegate to `compute_endoscaling` so this trivial setup
        // cannot silently drift from the real prover path.
        let beta_endo = extract_endoscalar(C::CircuitField::ONE);
        let p_commitment = {
            let mut points = Vec::with_capacity(NUM_ENDOSCALING_POINTS);

            // Initial: native_f commitment.
            points.push(host_commitment);

            let registry_xy_commitment = builder.native_registry_xy_commitment();

            // Per-child block: all per-child commitments are
            // `host_commitment` (ones_host), except registry_xy which
            // has its own commitment.
            for _ in 0..2 {
                for _ in &RxIndex::ALL {
                    points.push(host_commitment);
                }
                points.push(host_commitment); // AbA
                points.push(host_commitment); // AbB
                points.push(registry_xy_commitment); // RegistryXY
                points.push(host_commitment); // P placeholder
            }

            // Current-step bridge inputs.
            points.push(host_commitment); // registry_wx0
            points.push(host_commitment); // registry_wx1
            points.push(host_commitment); // registry_wy
            points.push(host_commitment); // a
            points.push(host_commitment); // b
            points.push(registry_xy_commitment); // native_registry_xy

            let mut trivial_rng = <ragu_arithmetic::rand::rngs::StdRng as ragu_arithmetic::rand::SeedableRng>::from_seed([0u8; 32]);
            self.compute_endoscaling(
                &mut trivial_rng,
                beta_endo,
                &points,
                C::ScalarField::ONE,
                C::ScalarField::ONE,
                &mut builder,
            )
            .expect("trivial endoscaling")
        };

        // Set native_p_poly with the real accumulated commitment.
        builder.set_native_p_poly(ones_host, p_commitment);

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
                stashed_preamble: host_commitment,
                stashed_inner_error: host_commitment,
                stashed_outer_error: host_commitment,
                stashed_query: host_commitment,
                stashed_eval: host_commitment,
                stashed_ab_a: host_commitment,
                stashed_ab_b: host_commitment,
                stashed_registry_xy: registry_xy_commitment,
                stashed_p: p_commitment,
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
            let commitment = rx.commit_to_affine(nested_gen);
            builder.set_bridge_preamble_rx(rx, commitment);
        }

        // Children's stage rx: a trivial proof is its own "child", so
        // child rx must match the proof's own rx. Force lazy evaluation of
        // cached bridges first so we can clone them.
        let trivial_child = ChildStageRx {
            points_stage: builder.nested_points_rx().clone(),
            bridge_s_prime: builder.bridge_s_prime_rx().clone(),
            bridge_inner_error: builder.bridge_inner_error_rx().clone(),
            bridge_outer_error: builder
                .bridge_outer_error_rx()
                .expect("trivial bridge_outer_error_rx")
                .clone(),
            bridge_ab: builder
                .bridge_ab_rx()
                .expect("trivial bridge_ab_rx")
                .clone(),
            bridge_query: builder
                .bridge_query_rx()
                .expect("trivial bridge_query_rx")
                .clone(),
            bridge_eval: builder
                .bridge_eval_rx()
                .expect("trivial bridge_eval_rx")
                .clone(),
        };
        builder.set_child_left_stage_rx(trivial_child.clone());
        builder.set_child_right_stage_rx(trivial_child);

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
