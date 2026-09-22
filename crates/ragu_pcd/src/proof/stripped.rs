//! The stripped form of a proof: its primary fields alone.
//!
//! See [`Proof`]'s documentation for which fields are primary and how the
//! verifier derives the rest.

use alloc::{sync::Arc, vec::Vec};

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::StageExt,
};
use ragu_core::Result;

use super::{Pcd, Proof, ProofBuilder, replay_challenges};
use crate::{
    Application, SelectableBackend,
    header::Header,
    internal::{native, nested},
};

/// A [`Proof`] stripped to its primary fields.
///
/// These are the fields only the prover can supply: the statement, the
/// polynomials and the blinding seed of the `ab` bridge. The verifier can
/// recompute every other field of a [`Proof`] from them, as that type's
/// documentation lays out, so [`Proof::strip`] loses nothing by
/// dropping them: [`Application::expand`] rebuilds the [`Proof`], and
/// [`Application::verify`] accepts the stripped form as it stands.
///
/// The binder and endoscaling-step polynomials are arrays where the working
/// form holds vectors, so a stripped proof of the wrong shape cannot be
/// represented.
#[derive(Clone)]
pub struct StrippedProof<C: Cycle, R: Rank> {
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

impl<C: Cycle, R: Rank> StrippedProof<C, R> {
    /// Augment a stripped proof with some data, described by a [`Header`],
    /// for [`Application::verify`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> Pcd<C, R, H, Self> {
        Pcd::new(self, data)
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Drops the derived fields, keeping what only the prover can supply;
    /// [`Application::expand`] derives them again.
    pub fn strip(self) -> StrippedProof<C, R> {
        StrippedProof {
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

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Rebuilds the working form of a stripped proof, deriving every field
    /// [`Proof::strip`] dropped: the commitments, from the
    /// polynomials; the challenges, from the transcript over the bridge
    /// commitments; the `ab` bridge, from `bridge_alpha` and the native
    /// commitments; and the nested challenge stage with its binding partial,
    /// from the challenges and the headers.
    ///
    /// # Errors
    ///
    /// Fails when the polynomials do not admit a derivation, such as a
    /// replayed challenge outside the endoscalar range. An honest proof's
    /// always do.
    pub fn expand(&self, stripped: StrippedProof<C, R>) -> Result<Proof<C, R>> {
        let host = C::host_generators(self.params);
        let nested_gen = C::nested_generators(self.params);
        let commit_host =
            |poly: &sparse::Polynomial<C::CircuitField, R>| B::sparse_commit_to_affine(poly, host);
        let commit_nested = |poly: &sparse::Polynomial<C::ScalarField, R>| {
            B::sparse_commit_to_affine(poly, nested_gen)
        };

        // Destructured exhaustively, so that a field added to the stripped
        // form fails to compile until this derivation accounts for it.
        let StrippedProof {
            circuit_id,
            left_header,
            right_header,
            bridge_alpha,
            native_application_rx,
            native_preamble_rx,
            native_inner_error_rx,
            native_outer_error_rx,
            native_a_poly,
            native_b_poly,
            native_query_rx,
            native_registry_xy_poly,
            native_eval_rx,
            native_p_poly,
            native_hashes_1_rx,
            native_hashes_2_rx,
            native_inner_collapse_rx,
            native_outer_collapse_rx,
            native_compute_v_rx,
            native_bind_challenges_rxs,
            native_bind_beta_rx,
            native_bind_endoscalar_rx,
            native_endoscaling_step_rxs,
            native_points_binding_rx,
            native_points_children_rx,
            native_points_registry_wx_rx,
            native_points_ab_rx,
            native_points_f_rx,
            native_points_walk_rx,
            bridge_preamble_rx,
            bridge_s_prime_rx,
            bridge_inner_error_rx,
            bridge_outer_error_rx,
            bridge_query_rx,
            bridge_f_rx,
            bridge_eval_rx,
            nested_endoscaling_step_rxs,
            nested_endoscalar_rx,
            nested_points_rx,
            nested_a_poly,
            nested_b_poly,
            nested_registry_xy_poly,
            nested_p_poly,
            nested_export_rx,
            nested_collapse_rx,
            nested_compute_v_rx,
        } = stripped;

        let mut builder = ProofBuilder::<C, R, B>::new(self.params, bridge_alpha);
        builder.set_circuit_id(circuit_id);
        builder.set_left_header(left_header);
        builder.set_right_header(right_header);

        // The native polynomials. The builder commits to most of them itself;
        // $a$, $b$ and $p$ take their commitments explicitly because the fuse
        // obtains those from folds and walks, which here are just the
        // commitments of the polynomials.
        builder.set_native_application_rx(native_application_rx);
        builder.set_native_preamble_rx(native_preamble_rx);
        builder.set_native_inner_error_rx(native_inner_error_rx);
        builder.set_native_outer_error_rx(native_outer_error_rx);
        let a_commitment = commit_host(&native_a_poly);
        builder.set_native_a_poly(native_a_poly, a_commitment);
        let b_commitment = commit_host(&native_b_poly);
        builder.set_native_b_poly(native_b_poly, b_commitment);
        builder.set_native_query_rx(native_query_rx);
        builder.set_native_registry_xy_poly(native_registry_xy_poly);
        builder.set_native_eval_rx(native_eval_rx);
        let p_commitment = commit_host(&native_p_poly);
        builder.set_native_p_poly(native_p_poly, p_commitment);
        builder.set_native_hashes_1_rx(native_hashes_1_rx);
        builder.set_native_hashes_2_rx(native_hashes_2_rx);
        builder.set_native_inner_collapse_rx(native_inner_collapse_rx);
        builder.set_native_outer_collapse_rx(native_outer_collapse_rx);
        builder.set_native_compute_v_rx(native_compute_v_rx);
        builder.set_native_bind_challenges_rxs(native_bind_challenges_rxs.into());
        builder.set_native_bind_beta_rx(native_bind_beta_rx);
        builder.set_native_bind_endoscalar_rx(native_bind_endoscalar_rx);
        builder.set_native_endoscaling_step_rxs(native_endoscaling_step_rxs.into());
        builder.set_native_points_binding_rx(native_points_binding_rx);
        builder.set_native_points_children_rx(native_points_children_rx);
        builder.set_native_points_registry_wx_rx(native_points_registry_wx_rx);
        builder.set_native_points_ab_rx(native_points_ab_rx);
        builder.set_native_points_f_rx(native_points_f_rx);
        builder.set_native_points_walk_rx(native_points_walk_rx);

        // The bridge polynomials with their commitments, as the fuse sets
        // them. The `ab` bridge is derived by the builder.
        macro_rules! set_bridge {
            ($setter:ident, $rx:expr) => {{
                let rx = Arc::unwrap_or_clone($rx);
                let commitment = commit_nested(&rx);
                builder.$setter(rx, commitment);
            }};
        }
        set_bridge!(set_bridge_preamble_rx, bridge_preamble_rx);
        set_bridge!(set_bridge_s_prime_rx, bridge_s_prime_rx);
        set_bridge!(set_bridge_inner_error_rx, bridge_inner_error_rx);
        set_bridge!(set_bridge_outer_error_rx, bridge_outer_error_rx);
        set_bridge!(set_bridge_query_rx, bridge_query_rx);
        set_bridge!(set_bridge_f_rx, bridge_f_rx);
        set_bridge!(set_bridge_eval_rx, bridge_eval_rx);

        // The nested polynomials; $p_n$ takes its commitment like $p$.
        builder.set_nested_endoscaling_step_rxs(nested_endoscaling_step_rxs.into());
        builder.set_nested_endoscalar_rx(nested_endoscalar_rx);
        builder.set_nested_points_rx(Arc::unwrap_or_clone(nested_points_rx));
        builder.set_nested_a_poly(nested_a_poly);
        builder.set_nested_b_poly(nested_b_poly);
        builder.set_nested_registry_xy_poly(nested_registry_xy_poly);
        let p_n_commitment = commit_nested(&nested_p_poly);
        builder.set_nested_p_poly(nested_p_poly, p_n_commitment);
        builder.set_nested_export_rx(nested_export_rx);
        builder.set_nested_collapse_rx(nested_collapse_rx);
        builder.set_nested_compute_v_rx(nested_compute_v_rx);

        // The challenges, replayed from the transcript over the bridge
        // commitments in the fuse's schedule.
        let challenges = replay_challenges::<C>(
            self.params,
            &[
                builder.bridge_preamble_commitment(),
                builder.bridge_s_prime_commitment(),
                builder.bridge_inner_error_commitment(),
                builder.bridge_outer_error_commitment(),
                builder.bridge_ab_commitment()?,
                builder.bridge_query_commitment(),
                builder.bridge_f_commitment(),
                builder.bridge_eval_commitment(),
            ],
        )?;
        builder.set_w(challenges.w);
        builder.set_y(challenges.y);
        builder.set_z(challenges.z);
        builder.set_mu(challenges.mu);
        builder.set_nu(challenges.nu);
        builder.set_mu_prime(challenges.mu_prime);
        builder.set_nu_prime(challenges.nu_prime);
        builder.set_x(challenges.x);
        builder.set_alpha(challenges.alpha);
        builder.set_u(challenges.u);
        builder.set_pre_beta(challenges.pre_beta);

        // The nested challenge stage over the challenges' lifts and the
        // headers, unblinded, and its commitment without the beta term.
        let lifts = challenges.lifts::<C>()?;
        let (challenge_lifts, beta_lift) = lifts.split_at(nested::stages::challenges::NUM);
        let stage = nested::stages::challenges::Witness::new::<_, HEADER_SIZE>(
            challenge_lifts.try_into().expect("NUM challenge lifts"),
            builder.left_header(),
            builder.right_header(),
            beta_lift[0],
        );
        builder.set_nested_challenges_partial(
            native::stages::eval::BindingPartials::compute::<C, R, B>(self.params, &stage).binding,
        );
        builder.set_nested_challenges_rx(nested::stages::challenges::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::ZERO,
            &stage,
        )?);

        builder.build()
    }
}

/// The array the stripped form holds in place of one of the working form's
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
#[path = "../../tests/stripped.rs"]
mod tests;
