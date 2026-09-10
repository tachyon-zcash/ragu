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
#[cfg(test)]
mod tests;
// The patcher seam (see `crate::fuzzing`). Its source lives with the rest of
// the fuzzing surface in `src/fuzzing/`, but it is mounted here because it
// calls this pipeline's `pub(super)` steps. The file gates itself behind
// `unstable-fuzzing` with an inner `#![cfg]`, so no feature attribute appears
// here.
#[path = "../fuzzing/patcher.rs"]
pub(crate) mod patcher;

use _11_circuits::NestedWitnesses;
use claims::{NativeFuseProofSource, NestedFuseProofSource};
use ragu_arithmetic::{Cycle, ff::Field, rand::CryptoRng};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::{
    Result,
    drivers::{
        Driver,
        emulator::{Emulator, Wireless},
    },
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, EndoscalarChallenge, GadgetExt, Point, vec::CollectFixed};

use crate::{
    Application, Pcd, Proof, RAGU_TAG,
    internal::{
        nested::{self, pcs},
        transcript::Transcript,
    },
    proof::ProofBuilder,
    step::Step,
};

/// Ephemeral native-field data for $f(X)$, used only during the fuse step.
struct NativeF<C: Cycle, R: Rank> {
    poly: sparse::Polynomial<C::CircuitField, R>,
    commitment: C::HostCurve,
}

/// Ephemeral $m(w, X, y)$ registry restriction, used only during the fuse step.
struct RegistryWy<C: Cycle, R: Rank> {
    poly: sparse::Polynomial<C::CircuitField, R>,
    commitment: C::HostCurve,
}

/// Ephemeral native-field data for $s'(X)$, used only during the fuse step.
struct NativeSPrime<C: Cycle, R: Rank> {
    registry_wx0_poly: sparse::Polynomial<C::CircuitField, R>,
    registry_wx0_commitment: C::HostCurve,
    registry_wx1_poly: sparse::Polynomial<C::CircuitField, R>,
    registry_wx1_commitment: C::HostCurve,
}

/// Ephemeral nested-field data for $f_n(X)$, used only during the fuse step.
struct NestedF<C: Cycle, R: Rank> {
    poly: sparse::Polynomial<C::ScalarField, R>,
    commitment: C::NestedCurve,
}

/// Ephemeral $m_n(w_n, X, y_n)$ nested registry restriction, used only
/// during the fuse step.
struct NestedRegistryWy<C: Cycle, R: Rank> {
    poly: sparse::Polynomial<C::ScalarField, R>,
    commitment: C::NestedCurve,
}

/// Ephemeral nested-field data for the $m_n(w_n, x_{i,n}, Y)$ restrictions,
/// used only during the fuse step.
struct NestedSPrime<C: Cycle, R: Rank> {
    registry_wx0_poly: sparse::Polynomial<C::ScalarField, R>,
    registry_wx0_commitment: C::NestedCurve,
    registry_wx1_poly: sparse::Polynomial<C::ScalarField, R>,
    registry_wx1_commitment: C::NestedCurve,
}

/// Witnesses of the nested challenge and beta stages, kept for the nested
/// circuits that load them.
pub(super) struct NestedChallengeWitnesses<F> {
    pub(super) challenges: nested::stages::challenges::Witness<F>,
    pub(super) beta: nested::stages::beta::Witness<F>,
}

type NativeFuseEmulator<C> = Emulator<Wireless<Always<()>, <C as Cycle>::CircuitField>>;
type NestedFuseEmulator<C> = Emulator<Wireless<Always<()>, <C as Cycle>::ScalarField>>;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Whether this step is a base case: both children carry the trivial
    /// header, whose last element is one.
    fn is_base_case(&self, builder: &ProofBuilder<'_, C, R, B>) -> bool {
        let is_trivial = |header: &[C::CircuitField]| {
            header.len() == HEADER_SIZE && header[HEADER_SIZE - 1] == C::CircuitField::ONE
        };
        is_trivial(builder.left_header()) && is_trivial(builder.right_header())
    }

    /// The nested batch this step opens, over the nested polynomials the
    /// builder has committed so far.
    fn nested_batch<'a>(
        &self,
        builder: &'a ProofBuilder<'_, C, R, B>,
        nested_s_prime: &'a NestedSPrime<C, R>,
        nested_registry_wy: &'a NestedRegistryWy<C, R>,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
    ) -> pcs::Batch<'a, C, R> {
        pcs::Batch {
            left,
            right,
            registry_wx0: &nested_s_prime.registry_wx0_poly,
            registry_wx1: &nested_s_prime.registry_wx1_poly,
            registry_wy: &nested_registry_wy.poly,
            registry_xy: builder.nested_registry_xy_poly(),
            a: builder.nested_a_poly(),
            b: builder.nested_b_poly(),
        }
    }

    /// Commits the nested challenge and beta stages: the lifts of this
    /// step's challenges (and the base-case sign), unblinded, so that their
    /// nested-curve commitments are the fixed linear combinations of
    /// generators the binding circuits recompute. Returns the stage
    /// witnesses for the nested circuits that load them.
    fn commit_nested_challenges(
        &self,
        challenges: nested::Challenges<C::CircuitField>,
        is_base_case: bool,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<NestedChallengeWitnesses<C::ScalarField>> {
        let lifts = challenges.lifts::<C>()?;
        let (challenge_lifts, beta_lift) = lifts.split_at(nested::stages::challenges::NUM);
        let challenges = nested::stages::challenges::Witness::new(
            challenge_lifts.try_into().expect("NUM challenge lifts"),
            is_base_case,
        );
        let beta = nested::stages::beta::Witness { lift: beta_lift[0] };
        builder.set_nested_challenges_rx(nested::stages::challenges::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::ZERO,
            &challenges,
        )?);
        builder.set_nested_beta_rx(nested::stages::beta::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::ZERO,
            beta,
        )?);
        Ok(NestedChallengeWitnesses { challenges, beta })
    }

    /// The nested challenges this step's openings are at, derived from the
    /// native ones (see [`nested::challenge`]).
    fn nested_challenges<'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<pcs::Challenges<C::ScalarField>> {
        Ok(pcs::Challenges {
            w: nested::challenge::<C>(*w.value().take())?,
            x: nested::challenge::<C>(*x.value().take())?,
            y: nested::challenge::<C>(*y.value().take())?,
            z: nested::challenge::<C>(*z.value().take())?,
            left: pcs::ChildChallenges::of(left)?,
            right: pcs::ChildChallenges::of(right)?,
        })
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
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
    ///   is zero-knowledge; that must be ensured by performing
    ///   [`Application::rerandomize`] at a later point.
    /// * `step`: the [`Step`] instance that has been registered in this
    ///   [`Application`].
    /// * `witness`: the witness input for the [`Step`]
    /// * `left`: the left [`Pcd`] to fuse in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right [`Pcd`] to fuse in this step; must correspond to
    ///   the [`Step::Right`] header.
    pub fn fuse<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        let mut builder =
            ProofBuilder::<C, R, B>::new(self.params, C::ScalarField::random(&mut *rng));

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
        let nu = transcript.challenge(&mut dr)?;

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
            &nu,
            saved_transcript_state,
            &mut builder,
        )?;
        let bridge_outer_error_commitment =
            Point::constant(&mut dr, builder.bridge_outer_error_commitment())?;
        bridge_outer_error_commitment.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.challenge(&mut dr)?;
        let nu_prime = transcript.challenge(&mut dr)?;

        self.compute_ab(
            native_a,
            native_b,
            nested_a,
            nested_b,
            &native_source,
            &mu_prime,
            &nu_prime,
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

        let bound_challenges = [&w, &y, &z, &mu, &nu, &mu_prime, &nu_prime, &x, &alpha, &u]
            .map(|challenge| *challenge.value().take());
        // Whether both children are trivial: the base-case flag the native
        // circuits read off the headers, bound for the nested side through
        // the challenge stage.
        let is_base_case = self.is_base_case(&builder);
        let (eval_witness, nested_eval) = self.compute_eval(
            &bound_challenges,
            is_base_case,
            &left,
            &right,
            &native_s_prime,
            &registry_wy,
            &nested_s_prime,
            &nested_registry_wy,
            &builder,
        )?;

        // The nested batch's commitments, into the native points inputs stage
        // before beta is squeezed; the eval bridge carries its commitment.
        let native_points = self.prepare_native_points(
            rng,
            &nested_f,
            &nested_s_prime,
            &nested_registry_wy,
            &left,
            &right,
            &mut builder,
        )?;
        let native_points_inputs_commitment = builder.native_points_inputs_commitment();

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
                let (eval_rx, bridge_eval_rx, bridge_eval_commitment) = self
                    .sample_eval_commitment(
                        rng,
                        &eval_witness,
                        &nested_eval,
                        native_points_inputs_commitment,
                    )?;

                let mut transcript = transcript.clone();
                let bridge_eval_commitment_point = Point::constant(dr, bridge_eval_commitment)?;
                bridge_eval_commitment_point.write(dr, &mut transcript)?;
                let pre_beta = transcript.challenge(dr)?;

                Ok((pre_beta, (eval_rx, bridge_eval_rx, bridge_eval_commitment)))
            })?;
        builder.set_native_eval_rx(eval_rx);
        builder.set_bridge_eval_rx(bridge_eval_rx, bridge_eval_commitment);

        // Every nested challenge is now known: commit the nested challenge
        // and beta stages, unblinded, which the binding circuits tie to the
        // transcript (the beta stage by the parent's).
        let nested_challenges = self.commit_nested_challenges(
            nested::Challenges {
                w: bound_challenges[0],
                y: bound_challenges[1],
                z: bound_challenges[2],
                mu: bound_challenges[3],
                nu: bound_challenges[4],
                mu_prime: bound_challenges[5],
                nu_prime: bound_challenges[6],
                x: bound_challenges[7],
                alpha: bound_challenges[8],
                u: bound_challenges[9],
                pre_beta: *pre_beta.element().value().take(),
            },
            is_base_case,
            &mut builder,
        )?;

        let (points, _native_interstitials) = self.compute_p(
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
            &native_points,
            &mut builder,
        )?;

        // Set challenges on builder.
        builder.set_w(*w.value().take());
        builder.set_y(*y.value().take());
        builder.set_z(*z.value().take());
        builder.set_mu(*mu.value().take());
        builder.set_nu(*nu.value().take());
        builder.set_mu_prime(*mu_prime.value().take());
        builder.set_nu_prime(*nu_prime.value().take());
        builder.set_x(*x.value().take());
        builder.set_alpha(*alpha.value().take());
        builder.set_u(*u.value().take());
        builder.set_pre_beta(*pre_beta.element().value().take());

        self.compute_internal_circuits(
            rng,
            &preamble_witness,
            &native_outer_error_witness,
            &native_inner_error_witness,
            &query_witness,
            &eval_witness,
            &mut builder,
        )?;

        // The nested circuits: the export circuit pins the nested unified
        // instance to the bridge stages it was read from.
        self.compute_nested_circuits(
            rng,
            &NestedWitnesses {
                endoscalar: pre_beta.extract_native(),
                points: &points,
                preamble: nested_preamble,
                s_prime: nested::stages::s_prime::Witness {
                    registry_wx0: native_s_prime.registry_wx0_commitment,
                    registry_wx1: native_s_prime.registry_wx1_commitment,
                },
                inner_error: nested_inner_error_witness,
                outer_error: nested_outer_error_witness,
                ab: nested::stages::ab::Witness {
                    a: builder.native_a_commitment(),
                    b: builder.native_b_commitment(),
                },
                query: nested::stages::query::Witness {
                    native_query: builder.native_query_commitment(),
                    registry_xy: builder.native_registry_xy_commitment(),
                    nested: nested_query,
                },
                f: nested::stages::f::Witness {
                    native_f: native_f.commitment,
                },
                eval: nested::stages::eval::Witness {
                    native_eval: builder.native_eval_commitment(),
                    native_points_inputs: native_points_inputs_commitment,
                    nested: nested_eval,
                },
                challenges: nested_challenges,
            },
            &mut builder,
        )?;

        let proof = builder.build()?;

        Ok((proof.carry(application_data), application_aux))
    }
}
