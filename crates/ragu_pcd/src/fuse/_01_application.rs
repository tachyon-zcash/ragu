//! Evaluate the [`Step`] circuit.
//!
//! This creates a witness for the step circuit given the two input [`Pcd`]s and
//! the step witness. This produces the [`proof::Application`] component of the
//! proof. The inputs are all consumed, and the `left` and `right proofs are
//! returned to the caller along with the output data from the step circuit.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{CircuitExt, polynomials::Rank};
use ragu_core::Result;
use rand::CryptoRng;

use crate::{
    Application, Header, Pcd, Proof, proof,
    step::{Step, internal::adapter::Adapter},
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_application_proof<RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
    ) -> Result<(
        Proof<C, R>,
        Proof<C, R>,
        proof::Application<C, R>,
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux,
    )> {
        let (trace, aux) =
            Adapter::<C, S, R, HEADER_SIZE>::new(step).rx((left.data, right.data, witness))?;
        let rx = self
            .native_registry
            .assemble(&trace, S::INDEX.circuit_index(self.num_application_steps)?)?;
        let blind = C::CircuitField::random(&mut *rng);
        let commitment = rx.commit_to_affine(C::host_generators(self.params), blind);

        let ((left_header, right_header), output_data, step_aux) = aux;

        Ok((
            left.proof,
            right.proof,
            proof::Application {
                circuit_id: S::INDEX.circuit_index(self.num_application_steps)?,
                left_header: left_header.into_inner(),
                right_header: right_header.into_inner(),
                rx,
                blind,
                commitment,
            },
            output_data,
            step_aux,
        ))
    }
}
