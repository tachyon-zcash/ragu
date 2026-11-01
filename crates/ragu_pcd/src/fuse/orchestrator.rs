//! Interleave both curve-side fusers with the shared transcript and bridges.
//!
//! The round order here is also replayed by the native hash circuits. A side
//! computes field-local data, then yields so its stage and bridge commitments
//! can be fixed before the next challenge. Application proving stays at the
//! public entry point; recursive circuit tracing finishes this coordinator.

use ragu_circuits::polynomials::Rank;
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{EndoscalarChallenge, GadgetExt, Point, vec::CollectFixed};
use rand::CryptoRng;

use super::{
    claims::{NativeFuseProofSource, NestedFuseProofSource},
    side::{CurveSideFuse, NativeSideFuse, NestedSideFuse},
};
use crate::{
    Application, Proof, RAGU_TAG,
    internal::{nested, transcript::Transcript},
    profile::ProfiledCycle,
    proof::ProofBuilder,
};

/// Coordinates one pair of child proofs across the two curve sides.
pub(super) struct FuseOrchestrator<
    'app,
    'params,
    'rx,
    C: ProfiledCycle,
    R: Rank,
    const HEADER_SIZE: usize,
    B: crate::SelectableBackend,
> {
    application: &'app Application<'params, C, R, HEADER_SIZE, B>,
    pub(super) native: NativeSideFuse<'app, 'rx, C, R>,
    pub(super) nested: NestedSideFuse<'app, 'rx, C, R>,
}

impl<
    'app,
    'params,
    'rx,
    C: ProfiledCycle,
    R: Rank,
    const HEADER_SIZE: usize,
    B: crate::SelectableBackend,
> FuseOrchestrator<'app, 'params, 'rx, C, R, HEADER_SIZE, B>
{
    pub(super) fn new(
        application: &'app Application<'params, C, R, HEADER_SIZE, B>,
        left: &'rx Proof<C, R>,
        right: &'rx Proof<C, R>,
    ) -> Self {
        Self {
            application,
            native: NativeSideFuse {
                registry: &application.native_registry,
                generators: C::host_generators(application.params),
                source: NativeFuseProofSource { left, right },
            },
            nested: NestedSideFuse {
                registry: &application.nested_registry,
                generators: C::nested_generators(application.params),
                source: NestedFuseProofSource { left, right },
            },
        }
    }

    pub(super) fn fuse<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        mut builder: ProofBuilder<'params, C, R, B>,
    ) -> Result<Proof<C, R>> {
        let app = self.application;
        let left = self.native.source.left;
        let right = self.native.source.right;
        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(app.params), RAGU_TAG)?;

        let (preamble_witness, nested_preamble) =
            app.compute_preamble(rng, left, right, &mut builder)?;
        let bridge_preamble_commitment =
            Point::constant(&mut dr, builder.bridge_preamble_commitment())?;
        bridge_preamble_commitment.write(&mut dr, &mut transcript)?;
        let w = transcript.challenge(&mut dr)?;
        let native_registry = self.native.registry_at(*w.value().take())?;
        let nested_registry = self.nested.registry_at(*w.value().take())?;

        let (native_s_prime, nested_s_prime) = app.compute_s_prime(
            rng,
            &native_registry,
            &nested_registry,
            &self.native,
            &self.nested,
            &mut builder,
        )?;
        let bridge_s_prime_commitment =
            Point::constant(&mut dr, builder.bridge_s_prime_commitment())?;
        bridge_s_prime_commitment.write(&mut dr, &mut transcript)?;
        let y = transcript.challenge(&mut dr)?;
        let z = transcript.challenge(&mut dr)?;

        let (
            native_inner_error_witness,
            native_claims,
            registry_wy,
            nested_inner_error_witness,
            nested_claims,
            nested_registry_wy,
        ) = app.inner_error_terms(
            rng,
            &native_registry,
            &nested_registry,
            &y,
            &z,
            &self.native,
            &self.nested,
            &mut builder,
        )?;
        let bridge_inner_error_commitment =
            Point::constant(&mut dr, builder.bridge_inner_error_commitment())?;
        bridge_inner_error_commitment.write(&mut dr, &mut transcript)?;

        // Clone-then-save: `save_state` consumes the transcript, but we need
        // the original to keep squeezing. Both paths apply the same permutation.
        let saved_transcript_state = transcript
            .clone()
            .save_state(&mut dr)
            .expect("save_state should succeed after absorbing")
            .into_elements()
            .into_iter()
            .map(|e| *e.value().take())
            .collect_fixed()?;

        let mu = transcript.challenge(&mut dr)?;

        let (
            native_outer_error_witness,
            native_a,
            native_b,
            nested_outer_error_witness,
            nested_a,
            nested_b,
        ) = app.outer_error_terms(
            rng,
            &preamble_witness,
            &native_inner_error_witness,
            native_claims,
            &nested_inner_error_witness,
            nested_claims,
            &self.native,
            &self.nested,
            &nested_preamble,
            &y,
            &mu,
            saved_transcript_state,
            &mut builder,
        )?;
        let bridge_outer_error_commitment =
            Point::constant(&mut dr, builder.bridge_outer_error_commitment())?;
        bridge_outer_error_commitment.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.challenge(&mut dr)?;

        app.compute_ab(
            rng,
            native_a,
            native_b,
            nested_a,
            nested_b,
            &nested_registry_wy,
            &self.native,
            &self.nested,
            &mu_prime,
            &mut builder,
        )?;
        let bridge_ab_commitment = Point::constant(&mut dr, builder.bridge_ab_commitment()?)?;
        bridge_ab_commitment.write(&mut dr, &mut transcript)?;
        let x = transcript.challenge(&mut dr)?;

        let (query_witness, nested_query) = app.compute_query(
            rng,
            &w,
            &x,
            &y,
            &z,
            &registry_wy,
            &nested_registry_wy,
            left,
            right,
            &mut builder,
        )?;
        let bridge_query_commitment = Point::constant(&mut dr, builder.bridge_query_commitment())?;
        bridge_query_commitment.write(&mut dr, &mut transcript)?;
        let alpha = transcript.challenge(&mut dr)?;

        let (native_f, nested_f) = app.compute_f(
            rng,
            &w,
            &y,
            &z,
            &x,
            &alpha,
            &native_s_prime,
            &registry_wy,
            &nested_s_prime,
            &nested_registry_wy,
            &mut builder,
            left,
            right,
        )?;
        let bridge_f_commitment = Point::constant(&mut dr, builder.bridge_f_commitment())?;
        bridge_f_commitment.write(&mut dr, &mut transcript)?;
        let u = transcript.challenge(&mut dr)?;

        let bound_challenges =
            [&w, &y, &z, &mu, &mu_prime, &x, &alpha, &u].map(|challenge| *challenge.value().take());
        let (eval_witness, nested_eval, nested_challenges_witness) = app.compute_eval(
            &bound_challenges,
            left,
            right,
            &native_s_prime,
            &registry_wy,
            &nested_s_prime,
            &nested_registry_wy,
            &builder,
        )?;
        builder.set_nested_challenges_partial(eval_witness.partials.binding);

        // Rejection-sample the eval-stage blinding until the squeezed `pre_beta`
        // lands in range as an endoscalar challenge. Unlike the single-shot
        // challenges above, `pre_beta` must be ground: each attempt re-blinds the
        // eval commitment and re-derives `pre_beta` from a fresh transcript
        // clone, retrying until `EndoscalarChallenge::sample` accepts. Baking the
        // grind into `sample` means a challenge cannot be produced without it.
        //
        // `pre_beta` is the terminal native Fiat-Shamir challenge (`v` is
        // computed, not squeezed), so the accepted transcript clone is dropped
        // rather than threaded onward; the internal circuits re-derive every
        // challenge in-circuit from the values recorded on the builder.
        let (pre_beta, (eval_rx, bridge_eval_rx, bridge_eval_commitment)) =
            EndoscalarChallenge::sample(&mut dr, |dr| {
                // Fresh eval-stage blindings each attempt: re-deriving the eval
                // commitment is what makes `pre_beta` independent across
                // retries.
                let (eval_rx, bridge_eval_rx, bridge_eval_commitment) =
                    app.sample_eval_commitment(rng, &eval_witness, &nested_eval)?;

                let mut transcript = transcript.clone();
                let bridge_eval_commitment_point = Point::constant(dr, bridge_eval_commitment)?;
                bridge_eval_commitment_point.write(dr, &mut transcript)?;
                let pre_beta = transcript.challenge(dr)?;

                Ok((pre_beta, (eval_rx, bridge_eval_rx, bridge_eval_commitment)))
            })?;
        builder.set_native_eval_rx(eval_rx);
        builder.set_bridge_eval_rx(bridge_eval_rx, bridge_eval_commitment);

        // Every nested challenge is now known: commit the nested challenge
        // stage, unblinded. Its expected commitment is computed by this
        // step's native binders and completed with beta by the parent's.
        let nested_challenges = app.commit_nested_challenges(
            nested_challenges_witness,
            *pre_beta.element().value().take(),
            &mut builder,
        )?;

        let (points, native_points, native_walk) = app.compute_p(
            rng,
            &pre_beta,
            left,
            right,
            &native_s_prime,
            &registry_wy,
            &native_f,
            &nested_s_prime,
            &nested_registry_wy,
            &nested_f,
            &mut builder,
        )?;

        // Set challenges on builder.
        builder.set_w(*w.value().take());
        builder.set_y(*y.value().take());
        builder.set_z(*z.value().take());
        builder.set_mu(*mu.value().take());
        builder.set_mu_prime(*mu_prime.value().take());
        builder.set_x(*x.value().take());
        builder.set_alpha(*alpha.value().take());
        builder.set_u(*u.value().take());
        builder.set_pre_beta(*pre_beta.element().value().take());

        app.compute_native_internal_circuits(
            rng,
            &preamble_witness,
            &native_outer_error_witness,
            &native_inner_error_witness,
            &query_witness,
            &eval_witness,
            &native_points,
            &native_walk,
            &mut builder,
        )?;

        let nested_s_prime_witness = nested::stages::s_prime::Witness {
            registry_wx0: native_s_prime.registry_wx0_commitment,
            registry_wx1: native_s_prime.registry_wx1_commitment,
            native_points_registry_wx: builder.native_points_registry_wx_commitment(),
        };
        let nested_ab_witness = nested::stages::ab::Witness {
            a: builder.native_a_commitment(),
            b: builder.native_b_commitment(),
            native_points_ab: builder.native_points_ab_commitment(),
        };
        let nested_query_witness = nested::stages::query::Witness {
            native_query: builder.native_query_commitment(),
            registry_xy: builder.native_registry_xy_commitment(),
            nested: nested_query,
        };
        let nested_f_witness = nested::stages::f::Witness {
            native_f: native_f.commitment,
            native_points_f: builder.native_points_f_commitment(),
        };
        let nested_eval_witness = nested::stages::eval::Witness {
            native_eval: builder.native_eval_commitment(),
            nested: nested_eval,
        };

        app.compute_nested_internal_circuits(
            rng,
            pre_beta.extract_native(),
            &points,
            &nested_preamble,
            &nested_s_prime_witness,
            &nested_inner_error_witness,
            &nested_outer_error_witness,
            &nested_ab_witness,
            &nested_query_witness,
            &nested_f_witness,
            &nested_eval_witness,
            &nested_challenges,
            &mut builder,
        )?;

        let proof = builder.build()?;
        Ok(proof)
    }
}
