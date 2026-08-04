//! Evaluate the [`Step`] circuit.
//!
//! This creates a witness for the step circuit given the two input [`Pcd`]s and
//! the step witness and fills the proof's application polynomials: the step's
//! own trace and the application stage, committed once per fuse. This sets the
//! application fields on the [`ProofBuilder`] and returns the child proofs
//! along with the output data from the step circuit.
//!
//! Nothing about a poly-query is re-checked here. This is where the hooks'
//! coefficient vectors become polynomials at the application's rank, that being
//! the first place the rank is in scope.

use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, sparse},
    staging,
};
use ragu_core::{Cycle, Error, Result};
use ragu_primitives::{shared::Shared, vec::Len};
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, Header, Pcd, Proof,
    framework_hooks::{FrameworkAux, HookConfig},
    proof::ProofBuilder,
    step::{
        Step,
        internal::adapter::{Adapter, AdapterAux},
    },
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, J, B>
{
    pub(super) fn compute_application_proof<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
        builder: &mut ProofBuilder<'_, C, R, J, B>,
    ) -> Result<(
        Proof<C, R>,
        Proof<C, R>,
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
    )> {
        let polys = J::PolyWitnesses::len();
        let (left_proof, left_data) = left.into_parts();
        let (right_proof, right_data) = right.into_parts();
        let circuit = S::INDEX.circuit_index(self.num_application_steps, polys)?;
        let stage_size = self.stage_size();
        let (trace, aux) =
            Adapter::<C, S, R, HEADER_SIZE, J>::new(step, stage_size, self.params)?
                .trace((left_data, right_data, witness))?
                .into_parts();
        let rx = self.native_registry.assemble(&trace, circuit, &mut *rng)?;

        let AdapterAux {
            left_header,
            right_header,
            output_data,
            step_aux,
            shared,
            framework:
                FrameworkAux {
                    witness_polys: witnessed,
                    poly_queries,
                },
        } = aux;
        if shared.len() != self.hook_layout().stage_len(S::Shared::num_values()?)
            || shared.len() > stage_size
        {
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
            stage_size,
            &shared,
        )?;

        let witness_polys = witnessed
            .iter()
            .map(|coefficients| sparse::Polynomial::<_, R>::from_coeffs(coefficients.to_vec()))
            .collect();

        builder.set_circuit_id(circuit);
        builder.set_left_header(left_header.into_inner());
        builder.set_right_header(right_header.into_inner());

        builder.set_native_application_rx(rx);
        builder.set_native_application_stage_rx(stage_rx);
        builder.set_application_polys(witness_polys);
        builder.set_application_poly_queries(poly_queries);

        Ok((left_proof, right_proof, output_data, step_aux))
    }
}
