//! This module provides the [`Application::verify`] method implementation.

use arithmetic::Cycle;
use ff::PrimeField;
use ragu_circuits::{
    mesh::{CircuitIndex, Mesh},
    polynomials::{Rank, structured},
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::Element;
use rand::Rng;

use crate::{
    Application, Pcd,
    header::Header,
    internal_circuits::{self, InternalCircuitIndex, stages::native::preamble::ProofInputs},
};

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
            &pcd.proof.preamble.stage_rx,
            internal_circuits::stages::native::preamble::STAGING_ID,
        );

        // Error_m stage verification (Layer 1).
        let error_m_valid = verifier.check_stage(
            &pcd.proof.error_m.stage_rx,
            internal_circuits::stages::native::error_m::STAGING_ID,
        );

        // Error_n stage verification (Layer 2).
        let error_n_valid = verifier.check_stage(
            &pcd.proof.error_n.stage_rx,
            internal_circuits::stages::native::error_n::STAGING_ID,
        );

        // Query verification.
        let query_valid = verifier.check_stage(
            &pcd.proof.query.stage_rx,
            internal_circuits::stages::native::query::STAGING_ID,
        );

        // Eval verification.
        let eval_valid = verifier.check_stage(
            &pcd.proof.eval.stage_rx,
            internal_circuits::stages::native::eval::STAGING_ID,
        );

        // Internal circuit hashes_1 stage verification
        let hashes_1_stage_valid = verifier.check_stage(
            &pcd.proof.circuits.hashes_1_rx,
            internal_circuits::hashes_1::STAGED_ID,
        );

        // Internal circuit hashes_2 stage verification
        let hashes_2_stage_valid = verifier.check_stage(
            &pcd.proof.circuits.hashes_2_rx,
            internal_circuits::hashes_2::STAGED_ID,
        );

        // Internal circuit partial_collapse stage verification
        let partial_collapse_stage_valid = verifier.check_stage(
            &pcd.proof.circuits.partial_collapse_rx,
            internal_circuits::partial_collapse::STAGED_ID,
        );

        // Internal circuit full_collapse verification
        let full_collapse_stage_valid = verifier.check_stage(
            &pcd.proof.circuits.full_collapse_rx,
            internal_circuits::full_collapse::STAGED_ID,
        );

        // Internal circuit compute_v verification
        let v_stage_valid = verifier.check_stage(
            &pcd.proof.circuits.compute_v_rx,
            internal_circuits::compute_v::STAGED_ID,
        );

        // Compute unified k(Y), unified_bridge k(Y), and application k(Y).
        let (unified_ky, unified_bridge_ky, application_ky) = Emulator::emulate_wireless(
            (&pcd.proof, pcd.data.clone(), verifier.y),
            |dr, witness| {
                let (proof, data, y) = witness.cast();
                let y = Element::alloc(dr, y)?;
                let proof_inputs =
                    ProofInputs::<_, C, HEADER_SIZE>::alloc_for_verify::<R, H>(dr, proof, data)?;

                let (unified_ky, unified_bridge_ky) = proof_inputs.unified_ky_values(dr, &y)?;
                let unified_ky = *unified_ky.value().take();
                let unified_bridge_ky = *unified_bridge_ky.value().take();
                let application_ky = *proof_inputs.application_ky(dr, &y)?.value().take();

                Ok((unified_ky, unified_bridge_ky, application_ky))
            },
        )?;

        // See `internal_circuits::hashes_1` documentation.
        let hashes_1_circuit_valid = {
            let mut rx = pcd.proof.circuits.hashes_1_rx.clone();
            rx.add_assign(&pcd.proof.preamble.stage_rx);
            // NB: pcd.proof.error_m.stage_rx is skipped.
            rx.add_assign(&pcd.proof.error_n.stage_rx);

            verifier.check_internal_circuit(
                &rx,
                internal_circuits::hashes_1::CIRCUIT_ID,
                // Note: The hashes_1 circuit uses unified_bridge_ky, unlike the
                // other internal circuits.
                unified_bridge_ky,
            )
        };

        // See `internal_circuits::hashes_2` documentation.
        let hashes_2_circuit_valid = {
            let mut rx = pcd.proof.circuits.hashes_2_rx.clone();
            // NB: pcd.proof.preamble.stage_rx is skipped.
            // NB: pcd.proof.error_m.stage_rx is skipped.
            rx.add_assign(&pcd.proof.error_n.stage_rx);

            verifier.check_internal_circuit(
                &rx,
                internal_circuits::hashes_2::CIRCUIT_ID,
                unified_ky,
            )
        };

        // See `internal_circuits::partial_collapse` documentation.
        let partial_collapse_circuit_valid = {
            let mut rx = pcd.proof.circuits.partial_collapse_rx.clone();
            // NB: pcd.proof.preamble.stage_rx is skipped.
            rx.add_assign(&pcd.proof.error_m.stage_rx);
            rx.add_assign(&pcd.proof.error_n.stage_rx);

            verifier.check_internal_circuit(
                &rx,
                internal_circuits::partial_collapse::CIRCUIT_ID,
                unified_ky,
            )
        };

        // See `internal_circuits::full_collapse` documentation.
        let full_collapse_circuit_valid = {
            let mut rx = pcd.proof.circuits.full_collapse_rx.clone();
            rx.add_assign(&pcd.proof.preamble.stage_rx);
            rx.add_assign(&pcd.proof.error_m.stage_rx);
            rx.add_assign(&pcd.proof.error_n.stage_rx);

            verifier.check_internal_circuit(
                &rx,
                internal_circuits::full_collapse::CIRCUIT_ID,
                unified_ky,
            )
        };

        // See `internal_circuits::compute_v` documentation.
        let v_circuit_valid = {
            let rx = pcd.proof.circuits.compute_v_rx.clone();
            // NB: pcd.proof.preamble.stage_rx is skipped.
            // NB: pcd.proof.query.stage_rx is skipped.
            // NB: pcd.proof.eval.stage_rx is skipped.

            verifier.check_internal_circuit(
                &rx,
                internal_circuits::compute_v::CIRCUIT_ID,
                unified_ky,
            )
        };

        // Application (Step circuit) verification.
        let application_circuit_valid = verifier.check_circuit(
            &pcd.proof.application.rx,
            pcd.proof.application.circuit_id,
            application_ky,
        );

        Ok(preamble_valid
            && error_m_valid
            && error_n_valid
            && query_valid
            && eval_valid
            && hashes_1_stage_valid
            && hashes_2_stage_valid
            && partial_collapse_stage_valid
            && full_collapse_stage_valid
            && v_stage_valid
            && hashes_1_circuit_valid
            && hashes_2_circuit_valid
            && partial_collapse_circuit_valid
            && full_collapse_circuit_valid
            && v_circuit_valid
            && application_circuit_valid)
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
        if !self.circuit_mesh.circuit_in_domain(circuit_id) {
            return false;
        }

        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);

        let mut rhs = rx.clone();
        rhs.dilate(self.z);
        rhs.add_assign(&sy);
        rhs.add_assign(&self.tz);

        rx.revdot(&rhs) == ky
    }
}
