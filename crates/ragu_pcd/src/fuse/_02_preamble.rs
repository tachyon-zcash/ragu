//! Commit to the preamble.
//!
//! This creates the [`proof::Preamble`] component of the proof, which commits
//! to the instance and trace polynomials used in the fuse step.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{CommittedPolynomial, Rank},
    staging::StageExt,
};
use ragu_core::Result;
use rand::CryptoRng;

use crate::{
    Application, Proof,
    circuits::{native::stages::preamble as native_preamble, nested},
    proof,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_preamble<'a, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        application: &proof::Application<C, R>,
    ) -> Result<(
        proof::Preamble<C, R>,
        native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    )> {
        let preamble_witness = native_preamble::Witness::new(
            left,
            right,
            &application.left_header,
            &application.right_header,
        )?;

        let native_poly = native_preamble::Stage::<C, R, HEADER_SIZE>::rx(&preamble_witness)?;
        let blind = C::CircuitField::random(rng);
        let commitment = native_poly.commit_to_affine(C::host_generators(self.params), blind);
        let native_rx = CommittedPolynomial::from_parts(native_poly, blind, commitment);

        let nested_preamble_witness = nested::stages::preamble::Witness {
            native_preamble: native_rx.commitment(),
            left: nested::stages::preamble::ChildWitness::from_proof(left),
            right: nested::stages::preamble::ChildWitness::from_proof(right),
        };

        let nested_poly =
            nested::stages::preamble::Stage::<C::HostCurve, R>::rx(&nested_preamble_witness)?;
        let blind = C::ScalarField::random(rng);
        let commitment = nested_poly.commit_to_affine(C::nested_generators(self.params), blind);
        let nested_rx = CommittedPolynomial::from_parts(nested_poly, blind, commitment);

        Ok((
            proof::Preamble {
                native_rx,
                nested_rx,
            },
            preamble_witness,
        ))
    }
}
