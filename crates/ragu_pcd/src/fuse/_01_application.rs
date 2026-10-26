//! Evaluate the [`Step`] circuit.
//!
//! This creates a witness for the step circuit given the two input [`Pcd`]s and
//! the step witness and fills the proof's application polynomials: the step's
//! own trace and the application stage, committed once per fuse. This sets the
//! application fields on the [`ProofBuilder`] and returns the child proofs
//! along with the output data from the step circuit.

use ragu_circuits::{CircuitExt, polynomials::Rank, staging};
use ragu_core::{Cycle, Error, Result};
use ragu_primitives::shared::Shared;
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, Header, Pcd, Proof,
    proof::ProofBuilder,
    step::{Step, internal::adapter::Adapter},
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn compute_application_proof<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        Proof<C, R>,
        Proof<C, R>,
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
    )> {
        let (left_proof, left_data) = left.into_parts();
        let (right_proof, right_data) = right.into_parts();
        let circuit = S::INDEX.circuit_index(self.num_application_steps)?;
        let (trace, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step, self.shared_size)?
            .trace((left_data, right_data, witness))?
            .into_parts();
        let rx = self.native_registry.assemble(&trace, circuit, &mut *rng)?;

        let ((left_header, right_header), output_data, step_aux, shared) = aux;
        if shared.len() != S::Shared::num_values()? || shared.len() > self.shared_size {
            return Err(Error::InvalidWitness(
                "the shared gadget does not fit the application stage".into(),
            ));
        }
        // The application stage, committed once: the step's claim adds it to
        // the step's own polynomial, so a trace against other staged values
        // would not satisfy the circuit.
        let stage_rx = staging::stage_rx::<_, R>(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            1,
            self.shared_size,
            &shared,
        )?;

        builder.set_circuit_id(circuit);
        builder.set_left_header(left_header.into_inner());
        builder.set_right_header(right_header.into_inner());
        builder.set_native_application_rx(rx);
        builder.set_native_application_stage_rx(stage_rx);

        Ok((left_proof, right_proof, output_data, step_aux))
    }
}
