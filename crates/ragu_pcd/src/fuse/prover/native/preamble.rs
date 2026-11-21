//! Native preamble prover phase.
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::Result;
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, Proof, fuse::prover::proof_builder::ProofBuilder, profile::ProfiledCycle,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::fuse::prover) fn compute_native_preamble<'a, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<crate::protocol::native::stages::preamble::Witness<'a, C, R, HEADER_SIZE>> {
        let preamble_witness = crate::protocol::native::stages::preamble::Witness::new(
            left,
            right,
            builder.left_header(),
            builder.right_header(),
        )?;

        let rx = crate::protocol::native::stages::preamble::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &preamble_witness,
        )?;

        builder.set_native_preamble_rx(rx);

        Ok(preamble_witness)
    }
}
