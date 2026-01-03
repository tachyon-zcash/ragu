//! This module provides the [`Application::verify`] method implementation.

use arithmetic::Cycle;
use ff::{Field, PrimeField};
use ragu_circuits::{
    mesh::{CircuitIndex, Mesh},
    polynomials::{Rank, structured},
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::Element;
use rand::Rng;

use alloc::{borrow::Cow, vec::Vec};
use core::iter::{once, repeat, repeat_n};

use crate::{
    Application, Pcd,
    header::Header,
    internal_circuits::{
        self, InternalCircuitIndex, partial_collapse::NUM_UNIFIED_CIRCUITS,
        stages::native::preamble::ProofInputs,
    },
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Verifies some [`Pcd`] for the provided [`Header`].
    pub fn verify<RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<'_, C, R, H>,
        mut rng: RNG,
    ) -> Result<bool> {
        // Sample verification challenges y and z.
        let y = C::CircuitField::random(&mut rng);
        let z = C::CircuitField::random(&mut rng);

        // Validate that the application circuit_id is within the mesh domain.
        // (Internal circuit IDs are constants and don't need this check.)
        if !self
            .circuit_mesh
            .circuit_in_domain(pcd.proof.application.circuit_id)
        {
            return Ok(false);
        }

        // Validate that the `left_header` and `right_header` lengths match
        // `HEADER_SIZE`. Alternatively, the `Proof` structure could be
        // parameterized on the `HEADER_SIZE`, but this appeared to be simpler.
        if pcd.proof.application.left_header.len() != HEADER_SIZE
            || pcd.proof.application.right_header.len() != HEADER_SIZE
        {
            return Ok(false);
        }

        // Compute unified k(y), unified_bridge k(y), and application k(y).
        let (unified_ky, unified_bridge_ky, application_ky) =
            Emulator::emulate_wireless((&pcd.proof, pcd.data.clone(), y), |dr, witness| {
                let (proof, data, y) = witness.cast();
                let y = Element::alloc(dr, y)?;
                let proof_inputs =
                    ProofInputs::<_, C, HEADER_SIZE>::alloc_for_verify::<R, H>(dr, proof, data)?;

                let (unified_ky, unified_bridge_ky) = proof_inputs.unified_ky_values(dr, &y)?;
                let unified_ky = *unified_ky.value().take();
                let unified_bridge_ky = *unified_bridge_ky.value().take();
                let application_ky = *proof_inputs.application_ky(dr, &y)?.value().take();

                Ok((unified_ky, unified_bridge_ky, application_ky))
            })?;

        // Build a and b polynomials for each revdot claim.
        let mut verifier = Verifier::new(&self.circuit_mesh, self.num_application_steps, y, z);

        // Circuit checks.
        {
            // ABProof raw claim (a revdot b = c)
            verifier.raw_claim(&pcd.proof.ab.a_poly, &pcd.proof.ab.b_poly);

            verifier.circuit(pcd.proof.application.circuit_id, &pcd.proof.application.rx);
            verifier.internal_circuit(
                internal_circuits::hashes_1::CIRCUIT_ID,
                &[
                    &pcd.proof.circuits.hashes_1_rx,
                    &pcd.proof.preamble.stage_rx,
                    &pcd.proof.error_n.stage_rx,
                ],
            );
            verifier.internal_circuit(
                internal_circuits::hashes_2::CIRCUIT_ID,
                &[&pcd.proof.circuits.hashes_2_rx, &pcd.proof.error_n.stage_rx],
            );
            verifier.internal_circuit(
                internal_circuits::partial_collapse::CIRCUIT_ID,
                &[
                    &pcd.proof.circuits.partial_collapse_rx,
                    &pcd.proof.preamble.stage_rx,
                    &pcd.proof.error_m.stage_rx,
                    &pcd.proof.error_n.stage_rx,
                ],
            );
            verifier.internal_circuit(
                internal_circuits::full_collapse::CIRCUIT_ID,
                &[
                    &pcd.proof.circuits.full_collapse_rx,
                    &pcd.proof.preamble.stage_rx,
                    &pcd.proof.error_m.stage_rx,
                    &pcd.proof.error_n.stage_rx,
                ],
            );
            verifier.internal_circuit(
                internal_circuits::compute_v::CIRCUIT_ID,
                &[
                    &pcd.proof.circuits.compute_v_rx,
                    &pcd.proof.preamble.stage_rx,
                    &pcd.proof.query.stage_rx,
                    &pcd.proof.eval.stage_rx,
                ],
            );
        }

        // Stage checks.
        {
            // Circuit masks:
            verifier.stage(
                InternalCircuitIndex::ErrorNFinalStaged,
                &[
                    &pcd.proof.circuits.hashes_1_rx,
                    &pcd.proof.circuits.hashes_2_rx,
                    &pcd.proof.circuits.partial_collapse_rx,
                    &pcd.proof.circuits.full_collapse_rx,
                ],
            );
            verifier.stage(
                InternalCircuitIndex::EvalFinalStaged,
                &[&pcd.proof.circuits.compute_v_rx],
            );

            // Stage masks:
            verifier.stage(
                internal_circuits::stages::native::preamble::STAGING_ID,
                &[&pcd.proof.preamble.stage_rx],
            );
            verifier.stage(
                internal_circuits::stages::native::error_m::STAGING_ID,
                &[&pcd.proof.error_m.stage_rx],
            );
            verifier.stage(
                internal_circuits::stages::native::error_n::STAGING_ID,
                &[&pcd.proof.error_n.stage_rx],
            );
            verifier.stage(
                internal_circuits::stages::native::query::STAGING_ID,
                &[&pcd.proof.query.stage_rx],
            );
            verifier.stage(
                internal_circuits::stages::native::eval::STAGING_ID,
                &[&pcd.proof.eval.stage_rx],
            );
        }

        // Check all revdot claims.
        let revdot_claims = {
            let ky_values = once(pcd.proof.ab.c)
                .chain(once(application_ky))
                .chain(once(unified_bridge_ky))
                .chain(repeat_n(unified_ky, NUM_UNIFIED_CIRCUITS))
                .chain(repeat(C::CircuitField::ZERO));

            ky_values
                .zip(verifier.a.iter().zip(verifier.b.iter()))
                .all(|(ky, (a, b))| a.revdot(b) == ky)
        };

        // Check polynomial evaluation claim.
        let p_eval_claim = pcd.proof.p.poly.eval(pcd.proof.challenges.u) == pcd.proof.p.v;

        Ok(revdot_claims && p_eval_claim)
    }
}

struct Verifier<'m, 'rx, F: PrimeField, R: Rank> {
    circuit_mesh: &'m Mesh<'m, F, R>,
    num_application_steps: usize,
    y: F,
    z: F,
    tz: structured::Polynomial<F, R>,
    a: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
    b: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
}

impl<'m, 'rx, F: PrimeField, R: Rank> Verifier<'m, 'rx, F, R> {
    fn new(circuit_mesh: &'m Mesh<'m, F, R>, num_application_steps: usize, y: F, z: F) -> Self {
        Self {
            circuit_mesh,
            num_application_steps,
            y,
            z,
            tz: R::tz(z),
            a: Vec::new(),
            b: Vec::new(),
        }
    }

    fn circuit(&mut self, circuit_id: CircuitIndex, rx: &'rx structured::Polynomial<F, R>) {
        self.circuit_impl(circuit_id, Cow::Borrowed(rx));
    }

    fn circuit_impl(
        &mut self,
        circuit_id: CircuitIndex,
        rx: Cow<'rx, structured::Polynomial<F, R>>,
    ) {
        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);
        let mut b = rx.as_ref().clone();
        b.dilate(self.z);
        b.add_assign(&sy);
        b.add_assign(&self.tz);

        self.a.push(rx);
        self.b.push(Cow::Owned(b));
    }

    fn internal_circuit(
        &mut self,
        id: InternalCircuitIndex,
        rxs: &[&'rx structured::Polynomial<F, R>],
    ) {
        assert!(!rxs.is_empty(), "must provide at least one rx polynomial");
        let circuit_id = id.circuit_index(self.num_application_steps);

        let rx = if rxs.len() == 1 {
            Cow::Borrowed(rxs[0])
        } else {
            let mut sum = rxs[0].clone();
            for rx in &rxs[1..] {
                sum.add_assign(rx);
            }
            Cow::Owned(sum)
        };

        self.circuit_impl(circuit_id, rx);
    }

    fn stage(&mut self, id: InternalCircuitIndex, rxs: &[&'rx structured::Polynomial<F, R>]) {
        assert!(!rxs.is_empty(), "must provide at least one rx polynomial");

        let circuit_id = id.circuit_index(self.num_application_steps);
        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);

        let a = if rxs.len() == 1 {
            Cow::Borrowed(rxs[0])
        } else {
            Cow::Owned(structured::Polynomial::fold(rxs.iter().copied(), self.z))
        };

        self.a.push(a);
        self.b.push(Cow::Owned(sy));
    }

    /// Add a raw claim without any mesh polynomial transformation.
    ///
    /// Used for ABProof claims where k(y) = c (the revdot product).
    fn raw_claim(
        &mut self,
        a: &'rx structured::Polynomial<F, R>,
        b: &'rx structured::Polynomial<F, R>,
    ) {
        self.a.push(Cow::Borrowed(a));
        self.b.push(Cow::Borrowed(b));
    }
}
