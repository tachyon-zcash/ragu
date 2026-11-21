//! Nested eval prover phase.

use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::Result;
use udon::field::Field;

use crate::{
    Application, fuse::prover::proof_builder::ProofBuilder, profile::ProfiledCycle,
    protocol::nested,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Commits the nested challenge stage: the lifts of this step's
    /// challenges, the base-case sign and the lift of `pre_beta`, unblinded,
    /// so that its nested-curve commitment is the fixed linear combination
    /// of generators the binding circuits recompute. Completes the witness
    /// used for the eval stage's binding partials with beta's lift and returns
    /// it for the nested circuits that load the stage.
    pub(in crate::fuse::prover) fn commit_nested_challenges(
        &self,
        mut challenges: crate::protocol::nested::stages::challenges::Witness<C::ScalarField>,
        pre_beta: C::CircuitField,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<crate::protocol::nested::stages::challenges::Witness<C::ScalarField>> {
        challenges.beta = nested::challenge::<C>(pre_beta)?;
        builder.set_nested_challenges_rx(crate::protocol::nested::stages::challenges::Stage::<
            C::HostCurve,
            R,
            C::Profile,
        >::rx(C::ScalarField::ZERO, &challenges)?);
        Ok(challenges)
    }
}
