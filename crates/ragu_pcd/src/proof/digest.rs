use blake2b_simd::{Params, State};
use ragu_arithmetic::{CurveAffine, ff::PrimeField};
use ragu_circuits::polynomials::{Rank, sparse::Polynomial};

use super::Proof;
use crate::internal::{native, nested};

struct ProofDigester(State);

impl ProofDigester {
    fn new() -> Self {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(b"ragu-proof-digest-v1");
        Self(state)
    }

    fn frame(&mut self, bytes: &[u8]) {
        self.0.update(&(bytes.len() as u64).to_le_bytes());
        self.0.update(bytes);
    }

    fn sequence(&mut self, name: &[u8], len: usize) {
        self.frame(name);
        self.0.update(&(len as u64).to_le_bytes());
    }

    fn field<F: PrimeField>(&mut self, name: &[u8], value: &F) {
        self.frame(name);
        self.field_value(value);
    }

    fn field_value<F: PrimeField>(&mut self, value: &F) {
        let repr = value.to_repr();
        self.frame(repr.as_ref());
    }

    fn field_slice<F: PrimeField>(&mut self, name: &[u8], values: &[F]) {
        self.sequence(name, values.len());
        for value in values {
            self.field_value(value);
        }
    }

    fn polynomial<F: PrimeField, R: Rank>(&mut self, poly: &Polynomial<F, R>) {
        self.0.update(&(R::num_coeffs() as u64).to_le_bytes());
        for coeff in poly.iter_coeffs() {
            self.field_value(&coeff);
        }
    }

    fn point<C: CurveAffine>(&mut self, point: &C) {
        let repr = point.to_bytes();
        self.frame(repr.as_ref());
    }

    fn finish(self) -> [u8; 32] {
        let hash = self.0.finalize();
        let mut digest = [0; 32];
        digest.copy_from_slice(hash.as_bytes());
        digest
    }
}

impl<C: ragu_arithmetic::Cycle, R: Rank> Proof<C, R> {
    pub(crate) fn test_digest(&self) -> [u8; 32] {
        let mut digest = ProofDigester::new();

        digest.field(b"bridge_alpha", &self.bridge_alpha);
        digest.frame(b"circuit_id");
        digest
            .0
            .update(&(usize::from(self.circuit_id) as u64).to_le_bytes());
        digest.field_slice(b"left_header", &self.left_header);
        digest.field_slice(b"right_header", &self.right_header);

        digest.sequence(b"native_rx_polynomials", native::RxIndex::ALL.len());
        for index in native::RxIndex::ALL {
            digest.polynomial(&self[index]);
        }
        digest.sequence(b"native_ab_polynomials", 2);
        digest.polynomial(&self.native_a_poly);
        digest.polynomial(&self.native_b_poly);
        digest.sequence(b"native_protocol_polynomials", 2);
        digest.polynomial(&self.native_registry_xy_poly);
        digest.polynomial(&self.native_p_poly);

        digest.sequence(b"nested_polynomials", nested::RxIndex::ALL.len());
        for index in nested::RxIndex::ALL {
            digest.polynomial(&self[index]);
        }

        for (name, value) in [
            (b"w".as_slice(), self.w),
            (b"y".as_slice(), self.y),
            (b"z".as_slice(), self.z),
            (b"mu".as_slice(), self.mu),
            (b"nu".as_slice(), self.nu),
            (b"mu_prime".as_slice(), self.mu_prime),
            (b"nu_prime".as_slice(), self.nu_prime),
            (b"x".as_slice(), self.x),
            (b"alpha".as_slice(), self.alpha),
            (b"u".as_slice(), self.u),
            (b"pre_beta".as_slice(), self.pre_beta),
        ] {
            digest.field(name, &value);
        }

        digest.sequence(b"native_rx_commitments", native::RxIndex::ALL.len());
        for index in native::RxIndex::ALL {
            digest.point(&self.native_rx_commitment(index));
        }
        digest.sequence(b"native_ab_commitments", 2);
        digest.point(&self.native_commitment(native::RxComponent::AbA));
        digest.point(&self.native_commitment(native::RxComponent::AbB));
        digest.sequence(b"native_protocol_commitments", 2);
        digest.point(&self.native_registry_xy_commitment());
        digest.point(&self.native_p_commitment());

        digest.sequence(
            b"nested_endoscaling_step_commitments",
            self.nested_endoscaling_step_commitments.len(),
        );
        for commitment in &self.nested_endoscaling_step_commitments {
            digest.point(&commitment.0);
        }
        digest.sequence(b"nested_stage_commitments", 2);
        digest.point(&self.nested_endoscalar_commitment());
        digest.point(&self.nested_points_commitment());
        digest.sequence(b"bridge_commitments", 8);
        digest.point(&self.bridge_preamble_commitment());
        digest.point(&self.bridge_s_prime_commitment());
        digest.point(&self.bridge_inner_error_commitment());
        digest.point(&self.bridge_outer_error_commitment());
        digest.point(&self.bridge_ab_commitment());
        digest.point(&self.bridge_query_commitment());
        digest.point(&self.bridge_f_commitment());
        digest.point(&self.bridge_eval_commitment());

        digest.finish()
    }
}
