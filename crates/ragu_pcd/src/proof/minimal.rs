//! The minimal form of a proof: its primary fields alone.
//!
//! See [`Proof`]'s documentation for which fields are primary and how the
//! verifier derives the rest.

use alloc::{sync::Arc, vec::Vec};

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};

use super::Proof;
use crate::internal::{native, nested};

/// A [`Proof`] reduced to its primary fields.
///
/// These are the fields only the prover can supply: the statement, the
/// polynomials and the blinding seed of the `ab` bridge. The verifier can
/// recompute every other field of a [`Proof`] from them, as that type's
/// documentation lays out, so [`Proof::into_minimal`] loses nothing by
/// dropping them. Nothing rebuilds a [`Proof`] from a `MinimalProof` yet.
///
/// The binder and endoscaling-step polynomials are arrays where the working
/// form holds vectors, so a minimal proof of the wrong shape cannot be
/// represented.
#[derive(Clone)]
pub struct MinimalProof<C: Cycle, R: Rank> {
    // The statement: which circuit, and the children's headers.
    pub(crate) circuit_id: CircuitIndex,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,

    // Blinding seed of the derived `ab` bridge stage.
    pub(crate) bridge_alpha: C::ScalarField,

    // Native polynomials (CircuitField): this step's traces, accumulator
    // and batch.
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
    pub(crate) native_bind_challenges_rxs:
        [sparse::Polynomial<C::CircuitField, R>; native::NUM_BINDERS],
    pub(crate) native_bind_beta_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_bind_endoscalar_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_endoscaling_step_rxs:
        [sparse::Polynomial<C::CircuitField, R>; native::NUM_ENDOSCALING_STEPS],
    pub(crate) native_points_binding_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_children_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_registry_wx_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_ab_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_f_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_walk_rx: sparse::Polynomial<C::CircuitField, R>,

    // Bridge polynomials (ScalarField): the seven stages the fuse blinds and
    // fills with data the proof holds nowhere else.
    pub(crate) bridge_preamble_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_s_prime_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_inner_error_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_outer_error_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_query_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_f_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_eval_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,

    // Nested polynomials (ScalarField): the nested traces, accumulator and
    // batch.
    pub(crate) nested_endoscaling_step_rxs:
        [sparse::Polynomial<C::ScalarField, R>; nested::NUM_ENDOSCALING_STEPS],
    pub(crate) nested_endoscalar_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_points_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) nested_a_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_b_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_registry_xy_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_p_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_export_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_collapse_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_compute_v_rx: sparse::Polynomial<C::ScalarField, R>,
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Drops the derived fields, keeping what only the prover can supply.
    pub fn into_minimal(self) -> MinimalProof<C, R> {
        MinimalProof {
            circuit_id: self.circuit_id,
            left_header: self.left_header,
            right_header: self.right_header,
            bridge_alpha: self.bridge_alpha,
            native_application_rx: self.native_application_rx,
            native_preamble_rx: self.native_preamble_rx,
            native_inner_error_rx: self.native_inner_error_rx,
            native_outer_error_rx: self.native_outer_error_rx,
            native_a_poly: self.native_a_poly,
            native_b_poly: self.native_b_poly,
            native_query_rx: self.native_query_rx,
            native_registry_xy_poly: self.native_registry_xy_poly,
            native_eval_rx: self.native_eval_rx,
            native_p_poly: self.native_p_poly,
            native_hashes_1_rx: self.native_hashes_1_rx,
            native_hashes_2_rx: self.native_hashes_2_rx,
            native_inner_collapse_rx: self.native_inner_collapse_rx,
            native_outer_collapse_rx: self.native_outer_collapse_rx,
            native_compute_v_rx: self.native_compute_v_rx,
            native_bind_challenges_rxs: sized(self.native_bind_challenges_rxs),
            native_bind_beta_rx: self.native_bind_beta_rx,
            native_bind_endoscalar_rx: self.native_bind_endoscalar_rx,
            native_endoscaling_step_rxs: sized(self.native_endoscaling_step_rxs),
            native_points_binding_rx: self.native_points_binding_rx,
            native_points_children_rx: self.native_points_children_rx,
            native_points_registry_wx_rx: self.native_points_registry_wx_rx,
            native_points_ab_rx: self.native_points_ab_rx,
            native_points_f_rx: self.native_points_f_rx,
            native_points_walk_rx: self.native_points_walk_rx,
            bridge_preamble_rx: self.bridge_preamble_rx,
            bridge_s_prime_rx: self.bridge_s_prime_rx,
            bridge_inner_error_rx: self.bridge_inner_error_rx,
            bridge_outer_error_rx: self.bridge_outer_error_rx,
            bridge_query_rx: self.bridge_query_rx,
            bridge_f_rx: self.bridge_f_rx,
            bridge_eval_rx: self.bridge_eval_rx,
            nested_endoscaling_step_rxs: sized(self.nested_endoscaling_step_rxs),
            nested_endoscalar_rx: self.nested_endoscalar_rx,
            nested_points_rx: self.nested_points_rx,
            nested_a_poly: self.nested_a_poly,
            nested_b_poly: self.nested_b_poly,
            nested_registry_xy_poly: self.nested_registry_xy_poly,
            nested_p_poly: self.nested_p_poly,
            nested_export_rx: self.nested_export_rx,
            nested_collapse_rx: self.nested_collapse_rx,
            nested_compute_v_rx: self.nested_compute_v_rx,
        }
    }
}

/// The array the minimal form holds in place of one of the working form's
/// polynomial vectors.
///
/// # Panics
///
/// Panics if the vector is not `N` long. The builder sizes every such vector
/// from the same constant as the array, so a mismatch is a bug in the prover
/// rather than a malformed proof.
fn sized<T, const N: usize>(polys: Vec<T>) -> [T; N] {
    match polys.try_into() {
        Ok(array) => array,
        Err(polys) => panic!("expected {N} polynomials, found {}", polys.len()),
    }
}

#[cfg(test)]
#[path = "../../tests/minimal.rs"]
mod tests;
