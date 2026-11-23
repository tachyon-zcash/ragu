//! Commit to the preamble.
//!
//! This sets the preamble fields on the [`ProofBuilder`], which commits to the
//! instance and trace polynomials used in the fuse step.
//!
//! The children's nested-curve commitments are committed here as well, in
//! the native points binding and preamble stages the endoscaling walk reads
//! them from; the preamble bridge carries those stages' commitments, so the
//! points are fixed before $w$ is squeezed. The step's own online Fp
//! polynomials' commitments and its application stage's go into the preamble
//! bridge directly, beside the children's exported ones it stashes, for the
//! same reason.
//!
//! The native preamble stage is committed later, after the step's circuit
//! ran: it holds the step's own output header and online openings, which the
//! circuit fixes at $\zeta = w$ (see [`native::stages::preamble`]). The
//! `s_prime` bridge carries its commitment.

use alloc::vec::Vec;

use ragu_circuits::{Blind, polynomials::Rank, staging::StageExt};
use ragu_core::Result;
use ragu_primitives::vec::FixedVec;
use rand::CryptoRng;

use super::_01_application::NativeApplicationStage;
use crate::{
    Application, Proof,
    header::NUM_ONLINE_FP_POLYS,
    internal::{
        native::{self, stages::points as native_points},
        nested,
    },
    profile::{Profile, ProfiledCycle},
    proof::ProofBuilder,
};

impl<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'params, C, R, HEADER_SIZE, B>
{
    /// Commits the native points preamble stage and the bridge preamble
    /// stage, which carries `stage`'s commitment, returning the bridge
    /// witness for the nested fold and circuits. `source` is what the step
    /// supplies the profile's prover, which commits its online Fq
    /// polynomials here.
    pub(super) fn compute_preamble<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        stage: &NativeApplicationStage<C, R>,
        source: Option<&crate::profile::Source<'params, C, R, B>>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<nested::stages::preamble::Witness<C::HostCurve, C::Profile>> {
        self.commit_native_points_preamble(rng, left, right, source, builder)?;
        self.compute_bridge_preamble(rng, left, right, stage, builder)
    }

    /// Commits the native preamble stage from the children's output headers
    /// and the step's own output header, circuit id, online openings and
    /// bridge-hash commitment, all on the builder by now. The stage's
    /// commitment is carried by `BridgeSPrime` before the step's $y$.
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
            builder.bridge_hash_commitment(),
        )?;

        let rx = native::stages::preamble::Stage::<C, R, HEADER_SIZE>::rx(
            Blind::random(rng),
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
            online_points: builder.native_online_phase::<0>(),
            online_stage: ragu_primitives::vec::FixedVec::from_fn(|_| {
                builder.native_online_stage_commitment(0)
            }),
            native_points_binding: builder.native_points_binding_commitment(),
            native_points_preamble: builder.native_points_preamble_commitment(),
            online_commitments: builder.online_commitments(),
            application_stage: stage.commitment,
            left: nested::stages::preamble::ChildWitness::from_proof(left)?,
            right: nested::stages::preamble::ChildWitness::from_proof(right)?,
        };
        let bridge_rx = nested::stages::preamble::Stage::<C::HostCurve, R, C::Profile>::rx(
            Blind::random(rng),
            &bridge_witness,
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_preamble_rx(bridge_rx, bridge_commitment);

        // The bridge-hash stage: the own last online commitment, with a
        // zero alpha, so its commitment is the digest the step's instance
        // carries.
        let o1 = builder.online_commitments()[NUM_ONLINE_FP_POLYS - 1];
        let hash_rx = nested::stages::bridge_hash::rx::<C::HostCurve, R>(o1)?;
        let hash_commitment =
            B::sparse_commit_to_affine(&hash_rx, C::nested_generators(self.params));
        builder.set_bridge_hash_rx(hash_rx, hash_commitment);
        Ok(bridge_witness)
    }

    /// Commits the native points binding and preamble stages over the
    /// children's nested commitments and the step's own online Fq
    /// commitments, before $w$ is squeezed; the preamble bridge carries
    /// their commitments.
    pub(crate) fn commit_native_points_preamble<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        source: Option<&crate::profile::Source<'params, C, R, B>>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        // The profile's prover supplies its online Fq polynomials: a
        // placeholder in every slot by default.
        let polynomials =
            C::Profile::online_fq_polynomials::<C::Base, R, B>(&self.context, source)?;
        if polynomials.len() != C::Profile::ONLINE_FQ_POLYS {
            return Err(ragu_core::Error::Initialization(
                "the profile's prover did not supply its online Fq polynomials".into(),
            ));
        }
        builder.set_online_fq_polynomials(polynomials);

        // The step's own online Fq commitments, which the preamble stage
        // holds.
        let mut online_fq = builder.online_fq_commitments().to_vec();
        online_fq.extend_from_slice(&builder.nested_online_phase::<0>());
        let online_fq = &online_fq;

        // Test hook: this runs on the thread that calls `fuse`, outside its
        // parallel jobs, as the hook's thread-local requires.
        #[cfg(test)]
        let online_fq = &crate::online_fq_oracles_tests::mutate_stage_commitments(online_fq);

        let (binding, preamble) = native_points::preamble_witnesses::<_, C::Profile>(
            &nested::pcs::child_commitments(left).collect::<Vec<_>>(),
            &nested::pcs::child_commitments(right).collect::<Vec<_>>(),
            [&left.online_fq_commitments, &right.online_fq_commitments],
            online_fq,
            FixedVec::from_fn(|_| builder.nested_online_stage_commitment(0)),
        );
        builder.set_native_points_binding_rx(<native_points::BindingStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            Blind::random(rng), &binding
        )?);
        builder.set_native_points_preamble_rx(<native_points::PreambleStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            Blind::random(rng), &preamble
        )?);
        Ok(())
    }
}
