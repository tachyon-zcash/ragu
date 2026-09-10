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

type NativeFuseEmulator<C> = Emulator<Wireless<Always<()>, <C as Cycle>::CircuitField>>;
type NestedFuseEmulator<C> = Emulator<Wireless<Always<()>, <C as Cycle>::ScalarField>>;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
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
    /// step's challenges, unblinded, so that their nested-curve commitments
    /// are the fixed linear combinations of generators the binding circuits
    /// recompute.
    fn commit_nested_challenges(
        &self,
        challenges: nested::Challenges<C::CircuitField>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let lifts = challenges.lifts::<C>()?;
        let (challenge_lifts, beta_lift) = lifts.split_at(nested::stages::challenges::NUM);
        builder.set_nested_challenges_rx(nested::stages::challenges::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::ZERO,
            &nested::stages::challenges::Witness::new(
                challenge_lifts.try_into().expect("NUM challenge lifts"),
            ),
        )?);
        builder.set_nested_beta_rx(nested::stages::beta::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::ZERO,
            nested::stages::beta::Witness { lift: beta_lift[0] },
        )?);
        Ok(())
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

        let preamble_witness = self.compute_preamble(rng, &left, &right, &mut builder)?;
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

        let (native_outer_error_witness, native_a, native_b, nested_a, nested_b) = self
            .outer_error_terms(
                rng,
                &preamble_witness,
                &native_inner_error_witness,
                native_claims,
                &nested_inner_error_witness,
                nested_claims,
                &nested_source,
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

        // The nested query values ride in the bridge; a nested `compute_v`
        // circuit will consume them once it exists.
        let (query_witness, _nested_query) = self.compute_query(
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
        let (eval_witness, nested_eval) = self.compute_eval(
            &bound_challenges,
            &left,
            &right,
            &native_s_prime,
            &registry_wy,
            &nested_s_prime,
            &nested_registry_wy,
            &builder,
        )?;

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
        // and beta stages, unblinded, which the binding circuits tie to the
        // transcript (the beta stage by the parent's).
        self.commit_nested_challenges(
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
            &mut builder,
        )?;

        self.compute_p(
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
        builder.set_nu(*nu.value().take());
        builder.set_mu_prime(*mu_prime.value().take());
        builder.set_nu_prime(*nu_prime.value().take());
        builder.set_x(*x.value().take());
        builder.set_alpha(*alpha.value().take());
        builder.set_u(*u.value().take());
        builder.set_pre_beta(*pre_beta.element().value().take());

        // Store children's stage rx polynomials for copying circuit claims.
        builder.set_child_left_stage_rx(left.as_child_stage_rx());
        builder.set_child_right_stage_rx(right.as_child_stage_rx());

        self.compute_internal_circuits(
            rng,
            &preamble_witness,
            &native_outer_error_witness,
            &native_inner_error_witness,
            &query_witness,
            &eval_witness,
            &mut builder,
        )?;

        let proof = builder.build()?;

        Ok((proof.carry(application_data), application_aux))
    }
}
