//! Proof fusion implementation for combining child proofs.
//!
//! Implements the core [`Application::fuse`] operation that takes two child
//! proofs and produces a new proof, computing each proof component in sequence.

mod _01_application;
mod _02_preamble;
mod _03_s_prime;
mod _04_inner_error;
mod _05_outer_error;
mod _06_ab;
mod _07_query;
mod _08_f;
mod _09_eval;
mod _10_p;
mod _11_circuits;
pub(crate) mod claims;
// PCS and folding properties use private fuse internals. The proof-binding
// properties live under `proof` for direct access to cached fields.
#[cfg(test)]
#[path = "../../tests/pcs.rs"]
mod pcs_tests;
// The patcher seam (see `crate::fuzzing`). Its source lives with the rest of
// the fuzzing surface in `src/fuzzing/`, but it is mounted here because it
// calls this pipeline's `pub(super)` steps. The file gates itself behind
// `unstable-fuzzing` with an inner `#![cfg]`, so no feature attribute appears
// here.
#[path = "../fuzzing/patcher.rs"]
pub(crate) mod patcher;

use claims::{NativeFuseProofSource, NestedFuseProofSource};
use ragu_circuits::polynomials::Rank;
use ragu_core::{Error, Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{EndoscalarChallenge, GadgetExt, Point, vec::CollectFixed};
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    Application, Pcd, RAGU_TAG,
    internal::{nested, transcript::Transcript},
    profile::{Decompressed, ProfiledCycle},
    proof::ProofBuilder,
    step::Step,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Fuse two [`Pcd`] into one using a provided [`Step`].
    ///
    /// The provided `step` must have been previously registered with this
    /// [`Application`] via [`ApplicationBuilder::register`](crate::ApplicationBuilder::register).
    ///
    /// ## Parameters
    ///
    /// * `rng`: a random number generator used to sample randomness during
    ///   proof generation. The fact that this method takes a random number
    ///   generator is not an indication that the resulting proof-carrying data
    ///   is zero-knowledge. [`Application::rerandomize`] is intended to provide
    ///   that property, but the current construction does not yet establish it.
    /// * `step`: the [`Step`] instance that has been registered in this
    ///   [`Application`].
    /// * `witness`: the witness input for the [`Step`]
    /// * `left`: the left [`Pcd`] to fuse in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right [`Pcd`] to fuse in this step; must correspond to
    ///   the [`Step::Right`] header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if either child proof does not have
    /// this application's profile's shape, which the verifier rejects too,
    /// and propagates the step's and the prover's errors otherwise.
    pub fn fuse<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        self.fuse_with_source(rng, step, witness, left, right, None)
    }

    /// [`fuse`](Self::fuse) with `source`, the compressed proof the
    /// profile's extension decompresses when the step decompresses one;
    /// without, the extension runs over the context's canonical proof.
    pub(crate) fn fuse_with_source<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
        source: Option<&Decompressed<C::Base>>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        // The children's polynomials are read by this profile's layout
        // below; a child of another shape is refused, as the verifier
        // refuses it, rather than read past its ends.
        if !left.proof().well_formed::<HEADER_SIZE>() || !right.proof().well_formed::<HEADER_SIZE>()
        {
            return Err(Error::InvalidWitness(
                "a child proof does not have this profile's shape".into(),
            ));
        }

        let mut builder = ProofBuilder::<C, R, B>::new(
            self.params,
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
        );

        let (left, right, application_data, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right, &mut builder)?;

        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(self.params), RAGU_TAG)?;

        let (preamble_witness, nested_preamble) =
            self.compute_preamble(rng, &left, &right, &mut builder)?;
        let bridge_preamble_commitment =
            Point::constant(&mut dr, builder.bridge_preamble_commitment())?;
        bridge_preamble_commitment.write(&mut dr, &mut transcript)?;
        let w = transcript.challenge(&mut dr)?;
        let native_registry = self.native_registry.at(*w.value().take());
        let nested_registry = self
            .nested_registry
            .at(nested::challenge::<C>(*w.value().take())?);

        let (native_s_prime, nested_s_prime) = self.compute_s_prime(
            rng,
            &native_registry,
            &nested_registry,
            &left,
            &right,
            &mut builder,
        )?;
        let bridge_s_prime_commitment =
            Point::constant(&mut dr, builder.bridge_s_prime_commitment())?;
        bridge_s_prime_commitment.write(&mut dr, &mut transcript)?;
        let y = transcript.challenge(&mut dr)?;
        let z = transcript.challenge(&mut dr)?;

        let native_source = NativeFuseProofSource {
            left: &left,
            right: &right,
        };
        let nested_source = NestedFuseProofSource {
            left: &left,
            right: &right,
        };

        let (
            native_inner_error_witness,
            native_claims,
            registry_wy,
            nested_inner_error_witness,
            nested_claims,
            nested_registry_wy,
        ) = self.inner_error_terms(
            rng,
            &native_registry,
            &nested_registry,
            &y,
            &z,
            &native_source,
            &nested_source,
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
        ) = self.outer_error_terms(
            rng,
            &preamble_witness,
            &native_inner_error_witness,
            native_claims,
            &nested_inner_error_witness,
            nested_claims,
            &nested_source,
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

        self.compute_ab(
            rng,
            native_a,
            native_b,
            nested_a,
            nested_b,
            &nested_registry_wy,
            &native_source,
            &mu_prime,
            &mut builder,
        )?;
        let bridge_ab_commitment = Point::constant(&mut dr, builder.bridge_ab_commitment()?)?;
        bridge_ab_commitment.write(&mut dr, &mut transcript)?;
        let x = transcript.challenge(&mut dr)?;

        let (query_witness, nested_query) = self.compute_query(
            rng,
            &w,
            &x,
            &y,
            &z,
            &registry_wy,
            &nested_registry_wy,
            &left,
            &right,
            &mut builder,
        )?;
        let bridge_query_commitment = Point::constant(&mut dr, builder.bridge_query_commitment())?;
        bridge_query_commitment.write(&mut dr, &mut transcript)?;
        let alpha = transcript.challenge(&mut dr)?;

        let (native_f, nested_f) = self.compute_f(
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
            &left,
            &right,
        )?;
        let bridge_f_commitment = Point::constant(&mut dr, builder.bridge_f_commitment())?;
        bridge_f_commitment.write(&mut dr, &mut transcript)?;
        let u = transcript.challenge(&mut dr)?;

        let bound_challenges =
            [&w, &y, &z, &mu, &mu_prime, &x, &alpha, &u].map(|challenge| *challenge.value().take());
        let (eval_witness, nested_eval, nested_challenges_witness) = self.compute_eval(
            &bound_challenges,
            &left,
            &right,
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
                    self.sample_eval_commitment(rng, &eval_witness, &nested_eval)?;

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
        let nested_challenges = self.commit_nested_challenges(
            nested_challenges_witness,
            *pre_beta.element().value().take(),
            &mut builder,
        )?;

        let (points, native_points, native_walk) = self.compute_p(
            rng,
            &pre_beta,
            &left,
            &right,
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

        self.compute_native_internal_circuits(
            rng,
            &preamble_witness,
            &native_outer_error_witness,
            &native_inner_error_witness,
            &query_witness,
            &eval_witness,
            &native_points,
            &native_walk,
            source,
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

        self.compute_nested_internal_circuits(
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
            source,
            &mut builder,
        )?;

        let proof = builder.build()?;

        Ok((proof.carry(application_data), application_aux))
    }
}
