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
    Application, Proof,
    internal::{native, nested},
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
        native::stages::preamble::Witness<'a, C, R, HEADER_SIZE>,
    )> {
        // Compute child bridges first — the points commitment is needed by
        // the native preamble witness for the k(Y) constraint.
        let child_bridges = |child: &Proof<C, R>| proof::ChildBridges {
            inner_error: child.inner_error.bridge.clone(),
            outer_error: child.outer_error.bridge.clone(),
            ab: child.ab.bridge.clone(),
            query: child.query.bridge.clone(),
            eval: child.eval.bridge.clone(),
            points: proof::Bridge::commit(self.params, child.circuits.points_rx.clone()),
        };
        let left_child_bridges = child_bridges(left);
        let right_child_bridges = child_bridges(right);

        let (native, preamble_witness) = self.compute_native_preamble(
            rng,
            left,
            right,
            application,
            left_child_bridges.points.commitment,
            right_child_bridges.points.commitment,
        )?;

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

        Ok((
            proof::Preamble {
                native,
                bridge,
                left_child_bridges,
                right_child_bridges,
            },
            preamble_witness,
        ))
    }

    fn compute_native_preamble<'a, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        application: &proof::Application<C, R>,
        left_points_commitment: C::NestedCurve,
        right_points_commitment: C::NestedCurve,
    ) -> Result<(
        proof::RxTriple<C, R>,
        native::stages::preamble::Witness<'a, C, R, HEADER_SIZE>,
    )> {
        let preamble_witness = native::stages::preamble::Witness::new(
            left,
            right,
            &application.left_header,
            &application.right_header,
            left_points_commitment,
            right_points_commitment,
        )?;

        let rx = native::stages::preamble::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(&mut *rng),
            &preamble_witness,
        )?;
        let commitment = rx.commit_to_affine(C::host_generators(self.params));

        Ok((proof::RxTriple { rx, commitment }, preamble_witness))
    }
}
