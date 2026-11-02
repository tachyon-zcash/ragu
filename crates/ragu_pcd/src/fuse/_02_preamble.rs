//! Commit to the preamble.
//!
//! This sets the preamble fields on the [`ProofBuilder`], which commits to the
//! instance and trace polynomials used in the fuse step.
//!
//! The children's nested-curve commitments are committed here as well, in
//! the native points binding and children stages the endoscaling walk reads
//! them from; the preamble bridge carries those stages' commitments, so the
//! points are fixed before $w$ is squeezed. The step's own online
//! polynomials' commitments and its application stage's go into the preamble
//! bridge directly, beside the children's exported ones it stashes, for the
//! same reason.
//!
//! The native preamble stage is committed later, after the step's circuit
//! ran: it holds the step's own output header and online openings, which the
//! circuit fixes at $\zeta = w$ (see [`native::stages::preamble`]). The
//! `s_prime` bridge carries its commitment.

use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::Result;
use rand::CryptoRng;
use udon::field::Field;

use super::_01_application::NativeApplicationStage;
use crate::{
    Application, Proof,
    header::NUM_ONLINE_POLYNOMIALS,
    internal::{native, nested},
    profile::ProfiledCycle,
    proof::ProofBuilder,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Commits the native points children stage and the bridge preamble
    /// stage, which carries `stage`'s commitment, returning the bridge
    /// witness for the nested fold and circuits.
    pub(super) fn compute_preamble<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        stage: &NativeApplicationStage<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<nested::stages::preamble::Witness<C::HostCurve, C::Profile>> {
        self.commit_native_points_children(rng, left, right, builder)?;
        self.compute_bridge_preamble(rng, left, right, stage, builder)
    }

    /// Commits the native preamble stage from the children's output headers
    /// and the step's own output header, circuit id and online openings,
    /// all on the builder by now, returning its witness for the native
    /// circuits.
    pub(super) fn compute_native_preamble<'a, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<native::stages::preamble::Witness<'a, C, R, HEADER_SIZE>> {
        let preamble_witness = native::stages::preamble::Witness::new(
            left,
            right,
            builder.left_header(),
            builder.right_header(),
            builder.output_header(),
            builder.circuit_id(),
            *builder.online_openings(),
        )?;

        let rx = native::stages::preamble::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &preamble_witness,
        )?;

        builder.set_native_preamble_rx(rx);

        Ok(preamble_witness)
    }

    fn compute_bridge_preamble<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        stage: &NativeApplicationStage<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<nested::stages::preamble::Witness<C::HostCurve, C::Profile>> {
        let bridge_witness = nested::stages::preamble::Witness {
            native_points_binding: builder.native_points_binding_commitment(),
            native_points_children: builder.native_points_children_commitment(),
            online_commitments: builder.online_commitments(),
            application_stage: stage.commitment,
            left: nested::stages::preamble::ChildWitness::from_proof(left)?,
            right: nested::stages::preamble::ChildWitness::from_proof(right)?,
        };
        let bridge_rx = nested::stages::preamble::Stage::<C::HostCurve, R, C::Profile>::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &bridge_witness,
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_preamble_rx(bridge_rx, bridge_commitment);

        // The bridge-hash stage: the own last online commitment, unblinded,
        // so its commitment is the digest the step's instance carries.
        let o1 = builder.online_commitments()[NUM_ONLINE_POLYNOMIALS - 1];
        let hash_rx = nested::stages::bridge_hash::rx::<C::HostCurve, R>(o1)?;
        let hash_commitment =
            B::sparse_commit_to_affine(&hash_rx, C::nested_generators(self.params));
        builder.set_bridge_hash_rx(hash_rx, hash_commitment);
        Ok(bridge_witness)
    }
}
