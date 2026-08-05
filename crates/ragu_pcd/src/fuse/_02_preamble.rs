//! Commit to the preamble.
//!
//! This sets the preamble fields on the [`ProofBuilder`], which commits to the
//! instance and trace polynomials used in the fuse step.
//!
//! The children's nested-curve commitments are committed here as well, in
//! the native points binding and children stages the endoscaling walk reads
//! them from; the preamble bridge carries those stages' commitments, so the
//! points are fixed before $w$ is squeezed.

use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{Cycle, Result};
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, Proof,
    internal::{native, nested},
    proof::ProofBuilder,
};

impl<
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    J: crate::framework_hooks::HookConfig,
    B: crate::SelectableBackend,
> Application<'_, C, R, HEADER_SIZE, J, B>
{
    /// Commits the native and bridge preamble stages, returning both
    /// witnesses: the native one for the native circuits, the bridge one for
    /// the nested fold and circuits.
    pub(super) fn compute_preamble<'a, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, J, B>,
    ) -> Result<(
        native::stages::preamble::Witness<'a, C, R, HEADER_SIZE>,
        nested::stages::preamble::Witness<C::HostCurve, J::PolyWitnesses>,
    )> {
        let preamble_witness = self.compute_native_preamble(rng, left, right, builder)?;
        self.commit_native_points_children(rng, left, right, builder)?;
        let bridge_witness = self.compute_bridge_preamble(rng, left, right, builder)?;
        Ok((preamble_witness, bridge_witness))
    }

    fn compute_native_preamble<'a, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, J, B>,
    ) -> Result<native::stages::preamble::Witness<'a, C, R, HEADER_SIZE>> {
        let preamble_witness = native::stages::preamble::Witness::new(
            left,
            right,
            builder.left_header(),
            builder.right_header(),
        )?;

        let rx = native::stages::preamble::Stage::<C, R, HEADER_SIZE, J>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &preamble_witness,
        )?;

        builder.set_native_preamble_rx(rx);

        // The derived challenges are their own stage, below `outer_error`, and
        // take the same witness the preamble does — they are a different
        // region of the same children's instances, not different data. The
        // preamble bridge carries its commitment, so it is fixed before $w$.
        let challenges_rx = native::stages::challenges::Stage::<
            C,
            R,
            HEADER_SIZE,
            J,
            native::RevdotParameters,
        >::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &preamble_witness,
        )?;
        builder.set_native_challenges_rx(challenges_rx);

        Ok(preamble_witness)
    }

    fn compute_bridge_preamble<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, J, B>,
    ) -> Result<nested::stages::preamble::Witness<C::HostCurve, J::PolyWitnesses>> {
        let bridge_witness = nested::stages::preamble::Witness {
            native_preamble: builder.native_preamble_commitment(),
            native_points_binding: builder.native_points_binding_commitment(),
            native_points_children: builder.native_points_children_commitment(),
            native_challenges: builder.native_challenges_commitment(),
            left: nested::stages::preamble::ChildWitness::from_proof(left)?,
            right: nested::stages::preamble::ChildWitness::from_proof(right)?,
        };
        let bridge_rx = nested::stages::preamble::Stage::<C::HostCurve, R, J::PolyWitnesses>::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &bridge_witness,
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_preamble_rx(bridge_rx, bridge_commitment);
        Ok(bridge_witness)
    }
}
