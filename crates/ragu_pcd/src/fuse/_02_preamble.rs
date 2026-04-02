//! Commit to the preamble.
//!
//! This creates the [`proof::Preamble`] component of the proof, which commits
//! to the instance and trace polynomials used in the fuse step.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::Result;
use rand::CryptoRng;

use crate::{
    Application, PcdConfig, Proof,
    internal::{native, nested},
    proof,
};

impl<C: Cycle, R: Rank, Cfg: PcdConfig> Application<'_, C, R, Cfg> {
    pub(super) fn compute_preamble<'a, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        application: &proof::Application<C, R>,
    ) -> Result<(
        proof::Preamble<C, R>,
        native::stages::preamble::Witness<'a, C, R, Cfg::HeaderSize>,
    )> {
        let (native, preamble_witness) =
            self.compute_native_preamble(rng, left, right, application)?;

        let bridge = proof::Bridge::commit(
            self.params,
            nested::stages::preamble::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::random(&mut *rng),
                &nested::stages::preamble::Witness {
                    native_preamble: native.commitment,
                    left: nested::stages::preamble::ChildWitness::from_proof(left),
                    right: nested::stages::preamble::ChildWitness::from_proof(right),
                },
            )?,
        );

        Ok((proof::Preamble { native, bridge }, preamble_witness))
    }

    fn compute_native_preamble<'a, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        application: &proof::Application<C, R>,
    ) -> Result<(
        proof::RxTriple<C, R>,
        native::stages::preamble::Witness<'a, C, R, Cfg::HeaderSize>,
    )> {
        let preamble_witness = native::stages::preamble::Witness::new(
            left,
            right,
            &application.left_header,
            &application.right_header,
        )?;

        let rx = native::stages::preamble::Stage::<C, R, Cfg::HeaderSize>::rx(
            C::CircuitField::random(&mut *rng),
            &preamble_witness,
        )?;
        let commitment = rx.commit_to_affine(C::host_generators(self.params));

        Ok((proof::RxTriple { rx, commitment }, preamble_witness))
    }
}
