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
    BridgeCommitment, NativeRx, NestedAccumulator, NestedRx, RxComponent,
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
            BetaStage => &mut self.nested_beta_rx,
        }
    }

    /// The bridge commitment named by `which`, mutably.
    ///
    /// These are the eight nested-curve points the unified instance carries
    /// (see `unified::Output::alloc_from_proof`); the native commitment caches
    /// have no accessor because single-proof verification never reads them.
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
