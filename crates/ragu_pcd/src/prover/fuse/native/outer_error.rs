//! Native outer-error prover phase.
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::Result;
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, profile::ProfiledCycle, protocol::native, prover::proof_builder::ProofBuilder,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn compute_native_outer_error<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native_outer_error_witness: &crate::verifier::recursive::native::stages::outer_error::Witness<
            C,
            native::RevdotParameters<C::Profile>,
        >,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let rx = crate::verifier::recursive::native::stages::outer_error::Stage::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters<C::Profile>,
        >::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            native_outer_error_witness,
        )?;

        builder.set_native_outer_error_rx(rx);

        Ok(())
    }
}
