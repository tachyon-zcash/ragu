//! This module provides the [`Application::verify`] method implementation.

mod stub_step;
mod stub_unified;

use arithmetic::Cycle;
use ff::PrimeField;
use ragu_circuits::{
    mesh::{CircuitIndex, Mesh},
    polynomials::{Rank, structured},
};
use ragu_core::{Error, Result};
use ragu_primitives::vec::{ConstLen, FixedVec};
use rand::Rng;

use crate::{
    Application, Pcd,
    header::Header,
    internal_circuits::{self, InternalCircuitIndex},
    step::adapter::Adapter,
};

use stub_step::StubStep;
use stub_unified::StubUnified;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Verifies some [`Pcd`] for the provided [`Header`].
    pub fn verify<RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<'_, C, R, H>,
        mut rng: RNG,
    ) -> Result<bool> {
        // The `Verifier` helper struct holds onto a verification context to
        // simplify performing revdot claims on different polynomials in the
        // proof.
        let verifier = Verifier::new(&self.circuit_mesh, self.num_application_steps, &mut rng);

        // Preamble verification
        let preamble_valid = verifier.check_stage(
            &pcd.proof.preamble.native_preamble_rx,
            internal_circuits::stages::native::preamble::STAGING_ID,
        );

        // Error_m stage verification (Layer 1).
        let error_m_valid = verifier.check_stage(
            &pcd.proof.error.native_error_m_rx,
            internal_circuits::stages::native::error_m::STAGING_ID,
        );

        // Error_n stage verification (Layer 2).
        let error_n_valid = verifier.check_stage(
            &pcd.proof.error.native_error_n_rx,
            internal_circuits::stages::native::error_n::STAGING_ID,
        );

        // Query verification.
        let query_valid = verifier.check_stage(
            &pcd.proof.query.native_query_rx,
            internal_circuits::stages::native::query::STAGING_ID,
        );

        // Eval verification.
        let eval_valid = verifier.check_stage(
            &pcd.proof.eval.native_eval_rx,
            internal_circuits::stages::native::eval::STAGING_ID,
        );

        // Internal circuit c verification
        let c_stage_valid = verifier.check_stage(
            &pcd.proof.internal_circuits.c_rx,
            internal_circuits::c::STAGED_ID,
        );

        // Internal circuit v verification
        let v_stage_valid = verifier.check_stage(
            &pcd.proof.internal_circuits.v_rx,
            internal_circuits::v::STAGED_ID,
        );

        // Internal circuit ky stage verification
        let ky_stage_valid = verifier.check_stage(
            &pcd.proof.internal_circuits.ky_rx,
            internal_circuits::ky::STAGED_ID,
        );

        // Internal circuit hashes_1 stage verification
        let hashes_1_stage_valid = verifier.check_stage(
            &pcd.proof.internal_circuits.hashes_1_rx,
            internal_circuits::hashes_1::STAGED_ID,
        );

        // Internal circuit hashes_2 stage verification
        let hashes_2_stage_valid = verifier.check_stage(
            &pcd.proof.internal_circuits.hashes_2_rx,
            internal_circuits::hashes_2::STAGED_ID,
        );

        let unified_instance = internal_circuits::unified::Instance {
            nested_preamble_commitment: pcd.proof.preamble.nested_preamble_commitment,
            w: pcd.proof.internal_circuits.w,
            nested_s_prime_commitment: pcd.proof.s_prime.nested_s_prime_commitment,
            y: pcd.proof.internal_circuits.y,
            z: pcd.proof.internal_circuits.z,
            nested_error_m_commitment: pcd.proof.error.nested_error_m_commitment,
            mu: pcd.proof.internal_circuits.mu,
            nu: pcd.proof.internal_circuits.nu,
            nested_error_n_commitment: pcd.proof.error.nested_error_n_commitment,
            mu_prime: pcd.proof.internal_circuits.mu_prime,
            nu_prime: pcd.proof.internal_circuits.nu_prime,
            c: pcd.proof.internal_circuits.c,
            nested_ab_commitment: pcd.proof.ab.nested_ab_commitment,
            x: pcd.proof.internal_circuits.x,
            nested_query_commitment: pcd.proof.query.nested_query_commitment,
            alpha: pcd.proof.internal_circuits.alpha,
            nested_f_commitment: pcd.proof.f.nested_f_commitment,
            u: pcd.proof.internal_circuits.u,
            nested_eval_commitment: pcd.proof.eval.nested_eval_commitment,
            beta: pcd.proof.internal_circuits.beta,
        };

        // Compute unified k(Y) once for both C and V circuits.
        let unified_ky = {
            let stub = StubUnified::<C>::new();
            crate::components::ky::emulate(&stub, &unified_instance, verifier.y)?
        };

        // C circuit verification with ky.
        // C's final stage is error_n, so combine preamble_rx + error_m_rx + error_n_rx with c_rx.
        let c_circuit_valid = {
            let mut c_combined_rx = pcd.proof.preamble.native_preamble_rx.clone();
            c_combined_rx.add_assign(&pcd.proof.error.native_error_m_rx);
            c_combined_rx.add_assign(&pcd.proof.error.native_error_n_rx);
            c_combined_rx.add_assign(&pcd.proof.internal_circuits.c_rx);

            verifier.check_internal_circuit(
                &c_combined_rx,
                internal_circuits::c::CIRCUIT_ID,
                unified_ky,
            )
        };

        // V circuit verification with ky.
        // V's final stage is eval, so combine preamble_rx + query_rx + eval_rx with v_rx.
        let v_circuit_valid = {
            let mut v_combined_rx = pcd.proof.preamble.native_preamble_rx.clone();
            v_combined_rx.add_assign(&pcd.proof.query.native_query_rx);
            v_combined_rx.add_assign(&pcd.proof.eval.native_eval_rx);
            v_combined_rx.add_assign(&pcd.proof.internal_circuits.v_rx);

            verifier.check_internal_circuit(
                &v_combined_rx,
                internal_circuits::v::CIRCUIT_ID,
                unified_ky,
            )
        };

        // Hashes_1 circuit verification with ky.
        // Hashes_1's final stage is error_n, so combine preamble_rx + error_m_rx + error_n_rx with hashes_1_rx.
        let hashes_1_valid = {
            let mut hashes_1_combined_rx = pcd.proof.preamble.native_preamble_rx.clone();
            hashes_1_combined_rx.add_assign(&pcd.proof.error.native_error_m_rx);
            hashes_1_combined_rx.add_assign(&pcd.proof.error.native_error_n_rx);
            hashes_1_combined_rx.add_assign(&pcd.proof.internal_circuits.hashes_1_rx);

            verifier.check_internal_circuit(
                &hashes_1_combined_rx,
                internal_circuits::hashes_1::CIRCUIT_ID,
                unified_ky,
            )
        };

        // Hashes_2 circuit verification with ky.
        // Hashes_2's final stage is error_n, so combine preamble_rx + error_m_rx + error_n_rx with hashes_2_rx.
        let hashes_2_valid = {
            let mut hashes_2_combined_rx = pcd.proof.preamble.native_preamble_rx.clone();
            hashes_2_combined_rx.add_assign(&pcd.proof.error.native_error_m_rx);
            hashes_2_combined_rx.add_assign(&pcd.proof.error.native_error_n_rx);
            hashes_2_combined_rx.add_assign(&pcd.proof.internal_circuits.hashes_2_rx);

            verifier.check_internal_circuit(
                &hashes_2_combined_rx,
                internal_circuits::hashes_2::CIRCUIT_ID,
                unified_ky,
            )
        };

        // Ky circuit verification with ky.
        // Ky's final stage is error_n, so combine preamble_rx + error_m_rx + error_n_rx with ky_rx.
        let ky_circuit_valid = {
            let mut ky_combined_rx = pcd.proof.preamble.native_preamble_rx.clone();
            ky_combined_rx.add_assign(&pcd.proof.error.native_error_m_rx);
            ky_combined_rx.add_assign(&pcd.proof.error.native_error_n_rx);
            ky_combined_rx.add_assign(&pcd.proof.internal_circuits.ky_rx);

            verifier.check_internal_circuit(
                &ky_combined_rx,
                internal_circuits::ky::CIRCUIT_ID,
                unified_ky,
            )
        };

        // Application verification
        let left_header = FixedVec::<_, ConstLen<HEADER_SIZE>>::try_from(
            pcd.proof.application.left_header.clone(),
        )
        .map_err(|_| Error::MalformedEncoding("left_header has incorrect size".into()))?;
        let right_header = FixedVec::<_, ConstLen<HEADER_SIZE>>::try_from(
            pcd.proof.application.right_header.clone(),
        )
        .map_err(|_| Error::MalformedEncoding("right_header has incorrect size".into()))?;

        let application_ky = {
            let adapter = Adapter::<C, StubStep<H>, R, HEADER_SIZE>::new(StubStep::new());
            let instance = (left_header, right_header, pcd.data.clone());
            crate::components::ky::emulate(&adapter, instance, verifier.y)?
        };

        let application_valid = verifier.check_circuit(
            &pcd.proof.application.rx,
            pcd.proof.application.circuit_id,
            application_ky,
        );

        Ok(preamble_valid
            && error_m_valid
            && error_n_valid
            && query_valid
            && eval_valid
            && c_stage_valid
            && v_stage_valid
            && ky_stage_valid
            && hashes_1_stage_valid
            && hashes_2_stage_valid
            && c_circuit_valid
            && v_circuit_valid
            && hashes_1_valid
            && hashes_2_valid
            && ky_circuit_valid
            && application_valid)
    }
}

struct Verifier<'a, F: PrimeField, R: Rank> {
    circuit_mesh: &'a Mesh<'a, F, R>,
    num_application_steps: usize,
    y: F,
    z: F,
    tz: structured::Polynomial<F, R>,
}

impl<'a, F: PrimeField, R: Rank> Verifier<'a, F, R> {
    fn new<RNG: Rng>(
        circuit_mesh: &'a Mesh<'a, F, R>,
        num_application_steps: usize,
        rng: &mut RNG,
    ) -> Self {
        let y = F::random(&mut *rng);
        let z = F::random(&mut *rng);
        let tz = R::tz(z);
        Self {
            circuit_mesh,
            num_application_steps,
            y,
            z,
            tz,
        }
    }

    /// Check an rx polynomial for a stage (empty ky).
    fn check_stage(
        &self,
        rx: &structured::Polynomial<F, R>,
        staging_id: InternalCircuitIndex,
    ) -> bool {
        let circuit_id = staging_id.circuit_index(self.num_application_steps);
        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);

        rx.revdot(&sy) == F::ZERO
    }

    /// Check an rx polynomial for an internal circuit with computed ky.
    fn check_internal_circuit(
        &self,
        rx: &structured::Polynomial<F, R>,
        internal_id: InternalCircuitIndex,
        ky: F,
    ) -> bool {
        let circuit_id = internal_id.circuit_index(self.num_application_steps);
        self.check_circuit(rx, circuit_id, ky)
    }

    /// Check an rx polynomial for a circuit with computed ky.
    fn check_circuit(
        &self,
        rx: &structured::Polynomial<F, R>,
        circuit_id: CircuitIndex,
        ky: F,
    ) -> bool {
        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);

        let mut rhs = rx.clone();
        rhs.dilate(self.z);
        rhs.add_assign(&sy);
        rhs.add_assign(&self.tz);

        rx.revdot(&rhs) == ky
    }
}
