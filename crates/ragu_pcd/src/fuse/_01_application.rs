//! Evaluate the [`Step`] circuit.
//!
//! This creates a witness for the step circuit given the two input [`Pcd`]s and
//! the step witness. This sets the application fields on the [`ProofBuilder`]
//! and returns the child proofs along with the output data from the step circuit.
//!
//! This is where the hooks' coefficient vectors become polynomials at the
//! application's rank, that being the first place the rank is in scope.

use ragu_arithmetic::{CryptoRngCore, Cycle};
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, sparse},
};
use ragu_core::Result;

use crate::{
    Application, Header, Pcd, Proof,
    framework_hooks::{FrameworkAux, HookConfig},
    proof::ProofBuilder,
    step::{
        Step,
        internal::adapter::{Adapter, AdapterAux},
    },
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    Application<'_, C, R, HEADER_SIZE, J>
{
    pub(super) fn compute_application_proof<'source, RNG: CryptoRngCore, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
        builder: &mut ProofBuilder<'_, C, R, J>,
    ) -> Result<(
        Proof<C, R>,
        Proof<C, R>,
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
    )> {
        let (left_proof, left_data) = left.into_parts();
        let (right_proof, right_data) = right.into_parts();
        let (trace, aux) = Adapter::<C, S, R, HEADER_SIZE, J>::new(step, self.params)
            .trace((left_data, right_data, witness))?
            .into_parts();
        let rx = self.native_registry.assemble(
            &trace,
            S::INDEX.circuit_index(self.num_application_steps)?,
            &mut *rng,
        )?;

        let AdapterAux {
            left_header,
            right_header,
            output_data,
            step_aux,
            framework:
                FrameworkAux {
                    witness_polys: witnessed,
                },
        } = aux;

        let witness_polys = witnessed
            .iter()
            .map(|coefficients| sparse::Polynomial::<_, R>::from_coeffs(coefficients.to_vec()))
            .collect();

        builder.set_circuit_id(S::INDEX.circuit_index(self.num_application_steps)?);
        builder.set_left_header(left_header.into_inner());
        builder.set_right_header(right_header.into_inner());

        builder.set_native_application_rx(rx);
        builder.set_application_polys(witness_polys);

        Ok((left_proof, right_proof, output_data, step_aux))
    }
}
