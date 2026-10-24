//! Structural checks shared by expanded and minimal proofs.

use ragu_circuits::polynomials::Rank;
use ragu_core::Cycle;
use ragu_primitives::vec::Len;
use udon::curve::Affine;

use super::{MinimalProof, Proof};
use crate::internal::{native, nested::NumStepsLen};

// All fields inspected here are retained in MinimalProof. Define the check once
// so the pre-expansion and expanded-proof entry points enforce the same rules.
macro_rules! impl_representation_checks {
    ($($proof:ident),+ $(,)?) => {$(
        impl<C: Cycle, R: Rank> $proof<C, R> {
            /// Checks lengths before indexed access and rejects identity points in
            /// slots that the verifier allocates as affine point gadgets. This only
            /// validates the representation, not the proof's cryptographic claims.
            pub(crate) fn is_well_formed(&self) -> bool {
                if self.native_bind_challenges_rxs.len() != native::NUM_BINDERS
                    || self.native_bind_challenges_commitments.len() != native::NUM_BINDERS
                    || self.native_endoscaling_step_rxs.len() != native::NUM_ENDOSCALING_STEPS
                    || self.native_endoscaling_step_commitments.len() != native::NUM_ENDOSCALING_STEPS
                    || self.nested_endoscaling_step_rxs.len() != NumStepsLen::len()
                    || self.nested_endoscaling_step_commitments.len() != NumStepsLen::len()
                {
                    return false;
                }

                // Points allocated by native::unified::Output::alloc_from_proof,
                // including the bridge commitments absorbed into the transcript.
                let native_instance = [
                    self.bridge_preamble_commitment,
                    self.bridge_s_prime_commitment,
                    self.bridge_inner_error_commitment,
                    self.bridge_outer_error_commitment,
                    self.bridge_ab_commitment.0,
                    self.bridge_query_commitment,
                    self.bridge_f_commitment,
                    self.bridge_eval_commitment,
                    self.nested_challenges_partial,
                    self.nested_p_commitment.0,
                    self.nested_a_commitment.0,
                    self.nested_b_commitment.0,
                    self.nested_registry_xy_commitment.0,
                ];

                // The exported points allocated by nested::unified::Output::alloc;
                // these are the same slots returned by Proof::nested_instance.
                let nested_instance = [
                    self.native_preamble_commitment.0,
                    self.native_inner_error_commitment.0,
                    self.native_outer_error_commitment.0,
                    self.native_query_commitment.0,
                    self.native_eval_commitment.0,
                    self.native_a_commitment.0,
                    self.native_b_commitment.0,
                    self.native_registry_xy_commitment.0,
                    self.native_p_commitment.0,
                    self.native_points_binding_commitment.0,
                    self.native_points_children_commitment.0,
                    self.native_points_registry_wx_commitment.0,
                    self.native_points_ab_commitment.0,
                    self.native_points_f_commitment.0,
                ];

                native_instance
                    .iter()
                    .all(|point| point.coordinates().is_some())
                    && nested_instance
                        .iter()
                        .all(|point| point.coordinates().is_some())
            }
        }
    )+};
}

impl_representation_checks!(Proof, MinimalProof);
