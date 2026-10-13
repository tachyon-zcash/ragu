//! Evaluate the [`Step`] circuit and fill the application slots.
//!
//! This creates a witness for the step circuit given the two input [`Pcd`]s and
//! the step witness and fills the proof's application polynomials: the shared
//! stage, committed once per fuse, and the slots. A step registered on its
//! own fills every slot with its one claim over an empty stage. It returns
//! the child proofs along with the output data from the step circuit.

use ragu_circuits::{CircuitExt, polynomials::Rank, staging};
use ragu_core::{Cycle, Result};
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, Header, Pcd, Proof,
    proof::{ProofBuilder, builder::ApplicationRxs},
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
        let bundle = S::INDEX.bundle(&self.application_bundles)?;
        let (left_proof, left_data) = left.into_parts();
        let (right_proof, right_data) = right.into_parts();
        let (trace, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step, bundle)
            .trace((left_data, right_data, witness))?
            .into_parts();
        let rx = self.native_registry.assemble(
            &trace,
            S::INDEX.circuit_index(self.num_application_steps)?,
            &mut *rng,
        )?;

        // The shared stage, committed once per proof and added to every
        // slot's claim: empty until a bundle shares data through it.
        let stage_rx = staging::stage_rx::<_, R>(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            1,
            0,
            &[],
        )?;

        let ((left_header, right_header), output_data, step_aux) = aux;

        builder.set_circuit_ids(bundle);
        builder.set_left_header(left_header.into_inner());
        builder.set_right_header(right_header.into_inner());
        builder.set_native_application_rxs(ApplicationRxs::Repeated(rx));
        builder.set_native_application_stage_rx(stage_rx);

        Ok((left_proof, right_proof, output_data, step_aux))
    }
}
