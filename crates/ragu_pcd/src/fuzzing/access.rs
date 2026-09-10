#![cfg(feature = "unstable-fuzzing")]
//! Mutable access to a [`Proof`]'s components, for the corruption vocabulary
//! in [`fuzzing::corrupt`](crate::fuzzing::corrupt).
//!
//! The source lives in `src/fuzzing/` with the rest of the fuzzing surface,
//! but the module is mounted as a child of `proof` (see `proof/mod.rs`): that
//! is what lets it reach `Proof`'s private fields — the `Cached` bridge
//! polynomials and the commitment caches — without loosening their
//! visibility. It gates itself behind `unstable-fuzzing` with the inner
//! attribute above, so `proof/mod.rs` carries no feature attribute.
//!
//! The accessors mirror the read-only [`Index`](core::ops::Index) impls on
//! `Proof`, so a corruption names a component exactly the way a verifier
//! check does rather than reaching for whichever field happens to be
//! reachable. Every `match` is exhaustive over the mirrors `corrupt`
//! declares, which is what keeps them honest: a mirror variant with no field
//! mapped to it fails to compile.

use alloc::sync::Arc;

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{Rank, sparse};

use super::Proof;
use crate::fuzzing::corrupt::{
    BridgeCommitment, NativeCommitment, NativeRx, NestedAccumulator, NestedCommitment, NestedRx,
    RxComponent,
};

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// The native polynomial named by `component`, mutably.
    pub(crate) fn native_component_mut(
        &mut self,
        component: RxComponent,
    ) -> &mut sparse::Polynomial<C::CircuitField, R> {
        use NativeRx::*;
        match component {
            RxComponent::AbA => &mut self.native_a_poly,
            RxComponent::AbB => &mut self.native_b_poly,
            RxComponent::Rx(idx) => match idx {
                Preamble => &mut self.native_preamble_rx,
                InnerError => &mut self.native_inner_error_rx,
                OuterError => &mut self.native_outer_error_rx,
                Query => &mut self.native_query_rx,
                Eval => &mut self.native_eval_rx,
                Application => &mut self.native_application_rx,
                Hashes1 => &mut self.native_hashes_1_rx,
                Hashes2 => &mut self.native_hashes_2_rx,
                InnerCollapse => &mut self.native_inner_collapse_rx,
                OuterCollapse => &mut self.native_outer_collapse_rx,
                ComputeV => &mut self.native_compute_v_rx,
                BindChallenges(k) => &mut self.native_bind_challenges_rxs[k as usize],
                BindBeta => &mut self.native_bind_beta_rx,
                BindEndoscalar => &mut self.native_bind_endoscalar_rx,
                EndoscalingStep(step) => &mut self.native_endoscaling_step_rxs[step as usize],
                PointsBinding => &mut self.native_points_binding_rx,
                PointsChildren => &mut self.native_points_children_rx,
                PointsRegistryWx => &mut self.native_points_registry_wx_rx,
                PointsAb => &mut self.native_points_ab_rx,
                PointsF => &mut self.native_points_f_rx,
                PointsWalk => &mut self.native_points_walk_rx,
            },
        }
    }

    /// The `registry_xy` polynomial, mutably.
    pub(crate) fn native_registry_xy_poly_mut(
        &mut self,
    ) -> &mut sparse::Polynomial<C::CircuitField, R> {
        &mut self.native_registry_xy_poly
    }

    /// The `p` polynomial, mutably.
    pub(crate) fn native_p_poly_mut(&mut self) -> &mut sparse::Polynomial<C::CircuitField, R> {
        &mut self.native_p_poly
    }

    /// The nested accumulator polynomial named by `which`, mutably.
    pub(crate) fn nested_accumulator_mut(
        &mut self,
        which: NestedAccumulator,
    ) -> &mut sparse::Polynomial<C::ScalarField, R> {
        match which {
            NestedAccumulator::A => &mut self.nested_a_poly,
            NestedAccumulator::B => &mut self.nested_b_poly,
        }
    }

    /// The nested `registry_xy` polynomial, mutably.
    pub(crate) fn nested_registry_xy_poly_mut(
        &mut self,
    ) -> &mut sparse::Polynomial<C::ScalarField, R> {
        &mut self.nested_registry_xy_poly
    }

    /// The nested `p` polynomial, mutably.
    pub(crate) fn nested_p_poly_mut(&mut self) -> &mut sparse::Polynomial<C::ScalarField, R> {
        &mut self.nested_p_poly
    }

    /// The nested polynomial named by `idx`, mutably.
    ///
    /// The `Arc`-shared polynomials are unshared through
    /// [`Arc::make_mut`](alloc::sync::Arc::make_mut), so corrupting a proof's
    /// copy never reaches into another that shares it.
    pub(crate) fn nested_rx_mut(
        &mut self,
        idx: NestedRx,
    ) -> &mut sparse::Polynomial<C::ScalarField, R> {
        use NestedRx::*;
        match idx {
            EndoscalingStep(step) => &mut self.nested_endoscaling_step_rxs[step as usize],
            Export => &mut self.nested_export_rx,
            Collapse => &mut self.nested_collapse_rx,
            ComputeV => &mut self.nested_compute_v_rx,
            EndoscalarStage => &mut self.nested_endoscalar_rx,
            PointsStage => Arc::make_mut(&mut self.nested_points_rx),
            BridgePreamble => Arc::make_mut(&mut self.bridge_preamble_rx),
            BridgeSPrime => Arc::make_mut(&mut self.bridge_s_prime_rx),
            BridgeInnerError => Arc::make_mut(&mut self.bridge_inner_error_rx),
            BridgeOuterError => Arc::make_mut(&mut self.bridge_outer_error_rx),
            BridgeAB => Arc::make_mut(&mut self.bridge_ab_rx.0),
            BridgeQuery => Arc::make_mut(&mut self.bridge_query_rx),
            BridgeF => Arc::make_mut(&mut self.bridge_f_rx),
            BridgeEval => Arc::make_mut(&mut self.bridge_eval_rx),
            ChallengeStage => &mut self.nested_challenges_rx,
        }
    }

    /// The nested challenge stage's exported partial binding, mutably.
    pub(crate) fn nested_challenges_partial_mut(&mut self) -> &mut C::NestedCurve {
        &mut self.nested_challenges_partial
    }

    /// The cached native commitment named by `which`, mutably.
    ///
    /// The verifier recomputes every cached commitment from its polynomial,
    /// so these are worth corrupting.
    pub(crate) fn native_commitment_cache_mut(
        &mut self,
        which: NativeCommitment,
    ) -> &mut C::HostCurve {
        use NativeRx::*;
        match which {
            NativeCommitment::AbA => &mut self.native_a_commitment.0,
            NativeCommitment::AbB => &mut self.native_b_commitment.0,
            NativeCommitment::RegistryXy => &mut self.native_registry_xy_commitment.0,
            NativeCommitment::P => &mut self.native_p_commitment.0,
            NativeCommitment::Rx(idx) => match idx {
                Preamble => &mut self.native_preamble_commitment.0,
                InnerError => &mut self.native_inner_error_commitment.0,
                OuterError => &mut self.native_outer_error_commitment.0,
                Query => &mut self.native_query_commitment.0,
                Eval => &mut self.native_eval_commitment.0,
                Application => &mut self.native_application_commitment.0,
                Hashes1 => &mut self.native_hashes_1_commitment.0,
                Hashes2 => &mut self.native_hashes_2_commitment.0,
                InnerCollapse => &mut self.native_inner_collapse_commitment.0,
                OuterCollapse => &mut self.native_outer_collapse_commitment.0,
                ComputeV => &mut self.native_compute_v_commitment.0,
                BindChallenges(k) => &mut self.native_bind_challenges_commitments[k as usize].0,
                BindBeta => &mut self.native_bind_beta_commitment.0,
                BindEndoscalar => &mut self.native_bind_endoscalar_commitment.0,
                EndoscalingStep(step) => {
                    &mut self.native_endoscaling_step_commitments[step as usize].0
                }
                PointsBinding => &mut self.native_points_binding_commitment.0,
                PointsChildren => &mut self.native_points_children_commitment.0,
                PointsRegistryWx => &mut self.native_points_registry_wx_commitment.0,
                PointsAb => &mut self.native_points_ab_commitment.0,
                PointsF => &mut self.native_points_f_commitment.0,
                PointsWalk => &mut self.native_points_walk_commitment.0,
            },
        }
    }

    /// The cached nested commitment named by `which`, mutably.
    pub(crate) fn nested_commitment_cache_mut(
        &mut self,
        which: NestedCommitment,
    ) -> &mut C::NestedCurve {
        use NestedRx::*;
        match which {
            NestedCommitment::AbA => &mut self.nested_a_commitment.0,
            NestedCommitment::AbB => &mut self.nested_b_commitment.0,
            NestedCommitment::RegistryXy => &mut self.nested_registry_xy_commitment.0,
            NestedCommitment::P => &mut self.nested_p_commitment.0,
            NestedCommitment::Rx(idx) => match idx {
                EndoscalingStep(step) => {
                    &mut self.nested_endoscaling_step_commitments[step as usize].0
                }
                Export => &mut self.nested_export_commitment.0,
                Collapse => &mut self.nested_collapse_commitment.0,
                ComputeV => &mut self.nested_compute_v_commitment.0,
                EndoscalarStage => &mut self.nested_endoscalar_commitment.0,
                PointsStage => &mut self.nested_points_commitment.0,
                BridgePreamble => &mut self.bridge_preamble_commitment,
                BridgeSPrime => &mut self.bridge_s_prime_commitment,
                BridgeInnerError => &mut self.bridge_inner_error_commitment,
                BridgeOuterError => &mut self.bridge_outer_error_commitment,
                BridgeAB => &mut self.bridge_ab_commitment.0,
                BridgeQuery => &mut self.bridge_query_commitment,
                BridgeF => &mut self.bridge_f_commitment,
                BridgeEval => &mut self.bridge_eval_commitment,
                ChallengeStage => &mut self.nested_challenges_commitment.0,
            },
        }
    }

    /// The bridge commitment named by `which`, mutably.
    ///
    /// These are the eight nested-curve points the unified instance carries
    /// (see `unified::Output::alloc_from_proof`).
    pub(crate) fn bridge_commitment_mut(&mut self, which: BridgeCommitment) -> &mut C::NestedCurve {
        use BridgeCommitment::*;
        match which {
            Preamble => &mut self.bridge_preamble_commitment,
            SPrime => &mut self.bridge_s_prime_commitment,
            InnerError => &mut self.bridge_inner_error_commitment,
            F => &mut self.bridge_f_commitment,
            OuterError => &mut self.bridge_outer_error_commitment,
            AB => &mut self.bridge_ab_commitment.0,
            Query => &mut self.bridge_query_commitment,
            Eval => &mut self.bridge_eval_commitment,
        }
    }
}
