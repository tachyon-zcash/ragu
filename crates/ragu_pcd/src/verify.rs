//! This module provides the [`Application::verify`] method implementation.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    mesh::CircuitIndex,
    polynomials::{Rank, structured},
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::Element;
use rand::Rng;

use core::iter::{once, repeat, repeat_n};

use crate::{
    Application, Pcd, Proof,
    components::claim_builder::{self, ClaimBuilder, ClaimSource, RxComponent},
    header::Header,
    internal_circuits::partial_collapse::NUM_UNIFIED_CIRCUITS,
    internal_circuits::stages::native::preamble::ProofInputs,
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
        let source = SingleProofSource { proof: &pcd.proof };
        let mut builder = ClaimBuilder::new(&self.circuit_mesh, self.num_application_steps, y, z);
        claim_builder::build_claims(&source, &mut builder)?;

        // Check all revdot claims.
        let revdot_claims = {
            let ky_values = once(pcd.proof.ab.c)
                .chain(once(application_ky))
                .chain(once(unified_bridge_ky))
                .chain(repeat_n(unified_ky, NUM_UNIFIED_CIRCUITS))
                .chain(repeat(C::CircuitField::ZERO));

            ky_values
                .zip(builder.a.iter().zip(builder.b.iter()))
                .all(|(ky, (a, b))| a.revdot(b) == ky)
        };

        // Check polynomial evaluation claim.
        let p_eval_claim = pcd.proof.p.poly.eval(pcd.proof.challenges.u) == pcd.proof.p.v;

        Ok(revdot_claims && p_eval_claim)
    }
}

/// Wraps a single proof for use with `ClaimSource`.
struct SingleProofSource<'rx, C: Cycle, R: Rank> {
    proof: &'rx Proof<C, R>,
}

impl<'rx, C: Cycle, R: Rank> ClaimSource for SingleProofSource<'rx, C, R> {
    type Rx = &'rx structured::Polynomial<C::CircuitField, R>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
        let poly = match component {
            RxComponent::AbA => &self.proof.ab.a_poly,
            RxComponent::AbB => &self.proof.ab.b_poly,
            RxComponent::Application => &self.proof.application.rx,
            RxComponent::Hashes1 => &self.proof.circuits.hashes_1_rx,
            RxComponent::Hashes2 => &self.proof.circuits.hashes_2_rx,
            RxComponent::PartialCollapse => &self.proof.circuits.partial_collapse_rx,
            RxComponent::FullCollapse => &self.proof.circuits.full_collapse_rx,
            RxComponent::ComputeV => &self.proof.circuits.compute_v_rx,
            RxComponent::PreambleStage => &self.proof.preamble.stage_rx,
            RxComponent::ErrorMStage => &self.proof.error_m.stage_rx,
            RxComponent::ErrorNStage => &self.proof.error_n.stage_rx,
            RxComponent::QueryStage => &self.proof.query.stage_rx,
            RxComponent::EvalStage => &self.proof.eval.stage_rx,
        };
        core::iter::once(poly)
    }

    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
        core::iter::once(self.proof.application.circuit_id)
    }
}
