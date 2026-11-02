//! Evaluate the [`Step`] circuit.
//!
//! This creates a witness for the step circuit given the two input [`Pcd`]s and
//! the step witness. This sets the application fields on the [`ProofBuilder`]
//! and returns the child proofs along with the output data from the step circuit.
//!
//! The trace is the step's own application trace, which this step folds and
//! opens itself, so it is returned as ephemeral [`NativeApplication`] data
//! rather than carried in the proof. Its commitment enters the transcript in
//! the `s_prime` bridge stage, before the $y$ the claim is folded at.

use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{Cycle, Result};
use rand::CryptoRng;

use crate::{
    Application, Header, Pcd, Proof,
    profile::ProfiledCycle,
    proof::ProofBuilder,
    step::{Step, internal::adapter::Adapter},
};

/// The step's own application trace, used only during the fuse step: the
/// step folds its claim and opens it in its own batch.
pub(super) struct NativeApplication<C: Cycle, R: Rank> {
    /// The step's application circuit.
    pub(super) circuit_id: CircuitIndex,
    /// The step's application trace.
    pub(super) rx: sparse::Polynomial<C::CircuitField, R>,
    /// The trace's commitment, carried by the `s_prime` bridge stage.
    pub(super) commitment: C::HostCurve,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    #[allow(clippy::type_complexity)]
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
        NativeApplication<C, R>,
    )> {
        let (left_proof, left_data) = left.into_parts();
        let (right_proof, right_data) = right.into_parts();
        let (trace, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step)
            .trace((left_data, right_data, witness))?
            .into_parts();
        let circuit_id = S::INDEX.circuit_index::<C::Profile>(self.num_application_steps)?;
        let rx = self
            .native_registry
            .assemble(&trace, circuit_id, &mut *rng)?;
        let commitment = B::sparse_commit_to_affine(&rx, C::host_generators(self.params));

        let ((left_header, right_header, output_header), output_data, step_aux) = aux;

        builder.set_circuit_id(circuit_id);
        builder.set_left_header(left_header.into_inner());
        builder.set_right_header(right_header.into_inner());
        builder.set_output_header(output_header.into_inner());

        Ok((
            left_proof,
            right_proof,
            output_data,
            step_aux,
            NativeApplication {
                circuit_id,
                rx,
                commitment,
            },
        ))
    }
}
