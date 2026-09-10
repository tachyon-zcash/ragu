//! Semantic proof comparison for backend-equivalence tests.

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::polynomials::{Rank, sparse::Polynomial};

use super::Proof;
use crate::internal::{native, nested};

fn polynomial_eq<F: Field, R: Rank>(left: &Polynomial<F, R>, right: &Polynomial<F, R>) -> bool {
    left.iter_coeffs().eq(right.iter_coeffs())
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Returns the first category in which two proofs differ semantically.
    ///
    /// The exhaustive pattern makes additions to [`Proof`] fail to compile
    /// until this comparison is reviewed. Polynomials are compared by their
    /// coefficient streams rather than their sparse storage layout.
    pub(crate) fn test_mismatch(&self, other: &Self) -> Option<&'static str> {
        let Self {
            bridge_alpha: _,
            circuit_id: _,
            left_header: _,
            right_header: _,
            native_application_rx: _,
            native_preamble_rx: _,
            native_inner_error_rx: _,
            native_outer_error_rx: _,
            native_a_poly: _,
            native_b_poly: _,
            native_query_rx: _,
            native_registry_xy_poly: _,
            native_eval_rx: _,
            native_p_poly: _,
            native_hashes_1_rx: _,
            native_hashes_2_rx: _,
            native_inner_collapse_rx: _,
            native_outer_collapse_rx: _,
            native_compute_v_rx: _,
            bridge_preamble_rx: _,
            bridge_s_prime_rx: _,
            bridge_inner_error_rx: _,
            bridge_f_rx: _,
            bridge_outer_error_rx: _,
            bridge_ab_rx: _,
            bridge_query_rx: _,
            bridge_eval_rx: _,
            nested_endoscaling_step_rxs: _,
            nested_endoscalar_rx: _,
            nested_points_rx: _,
            nested_a_poly: _,
            nested_b_poly: _,
            nested_endoscaling_step_commitments: _,
            nested_endoscalar_commitment: _,
            nested_points_commitment: _,
            nested_a_commitment: _,
            nested_b_commitment: _,
            w: _,
            y: _,
            z: _,
            mu: _,
            nu: _,
            mu_prime: _,
            nu_prime: _,
            x: _,
            alpha: _,
            u: _,
            pre_beta: _,
            native_application_commitment: _,
            native_preamble_commitment: _,
            native_inner_error_commitment: _,
            native_outer_error_commitment: _,
            native_a_commitment: _,
            native_b_commitment: _,
            native_query_commitment: _,
            native_registry_xy_commitment: _,
            native_eval_commitment: _,
            native_p_commitment: _,
            native_hashes_1_commitment: _,
            native_hashes_2_commitment: _,
            native_inner_collapse_commitment: _,
            native_outer_collapse_commitment: _,
            native_compute_v_commitment: _,
            bridge_preamble_commitment: _,
            bridge_s_prime_commitment: _,
            bridge_inner_error_commitment: _,
            bridge_f_commitment: _,
            bridge_outer_error_commitment: _,
            bridge_ab_commitment: _,
            bridge_query_commitment: _,
            bridge_eval_commitment: _,
            child_left_stage_rx: _,
            child_right_stage_rx: _,
        } = self;

        if self.bridge_alpha != other.bridge_alpha {
            return Some("bridge alpha");
        }
        if self.circuit_id != other.circuit_id {
            return Some("circuit id");
        }
        if self.left_header != other.left_header || self.right_header != other.right_header {
            return Some("headers");
        }

        if native::RxIndex::ALL
            .into_iter()
            .any(|index| !polynomial_eq(&self[index], &other[index]))
        {
            return Some("native rx polynomials");
        }
        if !polynomial_eq(&self.native_a_poly, &other.native_a_poly)
            || !polynomial_eq(&self.native_b_poly, &other.native_b_poly)
        {
            return Some("native ab polynomials");
        }
        if !polynomial_eq(
            &self.native_registry_xy_poly,
            &other.native_registry_xy_poly,
        ) || !polynomial_eq(&self.native_p_poly, &other.native_p_poly)
        {
            return Some("native protocol polynomials");
        }
        if nested::RxIndex::ALL
            .into_iter()
            .any(|index| !polynomial_eq(&self[index], &other[index]))
        {
            return Some("nested polynomials");
        }
        if !polynomial_eq(&self.nested_a_poly, &other.nested_a_poly)
            || !polynomial_eq(&self.nested_b_poly, &other.nested_b_poly)
        {
            return Some("nested ab polynomials");
        }

        if [
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
        ] != [
            other.w,
            other.y,
            other.z,
            other.mu,
            other.nu,
            other.mu_prime,
            other.nu_prime,
            other.x,
            other.alpha,
            other.u,
            other.pre_beta,
        ] {
            return Some("challenges");
        }

        if native::RxIndex::ALL
            .into_iter()
            .any(|index| self.native_rx_commitment(index) != other.native_rx_commitment(index))
        {
            return Some("native rx commitments");
        }
        if self.native_commitment(native::RxComponent::AbA)
            != other.native_commitment(native::RxComponent::AbA)
            || self.native_commitment(native::RxComponent::AbB)
                != other.native_commitment(native::RxComponent::AbB)
        {
            return Some("native ab commitments");
        }
        if self.native_registry_xy_commitment() != other.native_registry_xy_commitment()
            || self.native_p_commitment() != other.native_p_commitment()
        {
            return Some("native protocol commitments");
        }

        if self.nested_endoscaling_step_commitments != other.nested_endoscaling_step_commitments
            || self.nested_endoscalar_commitment != other.nested_endoscalar_commitment
            || self.nested_points_commitment != other.nested_points_commitment
        {
            return Some("nested commitments");
        }
        if self.nested_a_commitment != other.nested_a_commitment
            || self.nested_b_commitment != other.nested_b_commitment
        {
            return Some("nested ab commitments");
        }
        if [
            self.bridge_preamble_commitment(),
            self.bridge_s_prime_commitment(),
            self.bridge_inner_error_commitment(),
            self.bridge_outer_error_commitment(),
            self.bridge_ab_commitment(),
            self.bridge_query_commitment(),
            self.bridge_f_commitment(),
            self.bridge_eval_commitment(),
        ] != [
            other.bridge_preamble_commitment(),
            other.bridge_s_prime_commitment(),
            other.bridge_inner_error_commitment(),
            other.bridge_outer_error_commitment(),
            other.bridge_ab_commitment(),
            other.bridge_query_commitment(),
            other.bridge_f_commitment(),
            other.bridge_eval_commitment(),
        ] {
            return Some("bridge commitments");
        }

        None
    }
}
