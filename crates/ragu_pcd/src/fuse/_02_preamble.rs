//! Commit to the preamble.
//!
//! This sets the preamble fields on the [`ProofBuilder`], which commits to the
//! instance and trace polynomials used in the fuse step.

use ragu_arithmetic::{CryptoRngCore, Cycle, ff::Field};
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::Result;

use crate::{
    Application, Proof,
    internal::{native, nested},
    proof::ProofBuilder,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_preamble<'a, RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<native::stages::preamble::Witness<'a, C, R, HEADER_SIZE>> {
        let preamble_witness = self.compute_native_preamble(rng, left, right, builder)?;
        self.compute_bridge_preamble(rng, left, right, builder)?;
        Ok(preamble_witness)
    }

    fn compute_native_preamble<'a, RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<native::stages::preamble::Witness<'a, C, R, HEADER_SIZE>> {
        let preamble_witness = native::stages::preamble::Witness::new(
            left,
            right,
            builder.left_header(),
            builder.right_header(),
        )?;

        let rx = native::stages::preamble::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(&mut *rng),
            &preamble_witness,
        )?;

        builder.set_native_preamble_rx(rx);

        Ok(preamble_witness)
    }

    fn compute_bridge_preamble<RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<()> {
        let bridge_rx = nested::stages::preamble::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::random(&mut *rng),
            &nested::stages::preamble::Witness {
                native_preamble: builder.native_preamble_commitment(),
                left: nested::stages::preamble::ChildWitness::from_proof(left),
                right: nested::stages::preamble::ChildWitness::from_proof(right),
            },
        )?;
        let bridge_commitment = bridge_rx.commit_to_affine(C::nested_generators(self.params));
        builder.set_bridge_preamble_rx(bridge_rx, bridge_commitment);
        Ok(())
    }
}
