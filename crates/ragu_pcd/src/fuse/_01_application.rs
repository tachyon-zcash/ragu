//! Evaluate the [`Step`] circuit.
//!
//! This creates a witness for the step circuit given the two input [`Pcd`]s and
//! the step witness. This produces the [`proof::Application`] component of the
//! proof. The inputs are all consumed, and the `left` and `right proofs are
//! returned to the caller along with the auxiliary data from the application
//! synthesis.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Committable, Rank},
};
use ragu_core::Result;
use rand::CryptoRng;

use crate::{
    Application, Pcd, Proof, proof,
    step::{Step, internal::adapter::Adapter},
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_application_proof<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(
        Proof<C, R>,
        Proof<C, R>,
        proof::Application<C, R>,
        S::Aux<'source>,
    )> {
        let (trace, aux) =
            Adapter::<C, S, R, HEADER_SIZE>::new(step).rx((left.data, right.data, witness))?;
        let circuit_id = S::INDEX.circuit_index(self.num_application_steps)?;
        let rx = self
            .native_registry
            .assemble(&trace, circuit_id)?
            .commit(C::host_generators(self.params), rng);

        let ((left_header, right_header), aux) = aux;

        Ok((
            left.proof,
            right.proof,
            proof::Application {
                circuit_id,
                left_header: left_header.into_inner(),
                right_header: right_header.into_inner(),
                rx,
            },
            aux,
        ))
    }
}
