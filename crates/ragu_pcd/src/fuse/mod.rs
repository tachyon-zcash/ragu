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

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt, Point, vec::CollectFixed};
use rand::CryptoRng;

use crate::{
    Application, Pcd, Proof, RAGU_TAG, internal::transcript::Transcript, proof, step::Step,
};

use claims::FuseProofSource;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
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
    /// * `witness`: the witness data for the [`Step`]
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
        let (left, right, application, application_data, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right)?;

        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(self.params), RAGU_TAG)?;

        let (preamble, preamble_witness) =
            self.compute_preamble(rng, &left, &right, &application)?;
        let preamble_commitment = Point::constant(&mut dr, preamble.bridge.commitment)?;
        preamble_commitment.write(&mut dr, &mut transcript)?;
        let w = transcript.challenge(&mut dr)?;
        let native_registry = self.native_registry.at(*w.value().take());

        let s_prime = self.compute_s_prime(rng, &native_registry, &left, &right)?;
        let s_prime_commitment = Point::constant(&mut dr, s_prime.bridge.commitment)?;
        s_prime_commitment.write(&mut dr, &mut transcript)?;
        let y = transcript.challenge(&mut dr)?;
        let z = transcript.challenge(&mut dr)?;

        let source = FuseProofSource {
            left: &left,
            right: &right,
        };

        let (inner_error, inner_error_witness, claims) =
            self.inner_error_terms(rng, &native_registry, &y, &z, &source, &preamble)?;
        let inner_error_commitment = Point::constant(&mut dr, inner_error.bridge.commitment)?;
        inner_error_commitment.write(&mut dr, &mut transcript)?;

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

        let (outer_error, outer_error_witness, a, b) = self.outer_error_terms(
            rng,
            &preamble_witness,
            &inner_error_witness,
            claims,
            &y,
            &mu,
            &nu,
            saved_transcript_state,
        )?;
        let outer_error_commitment = Point::constant(&mut dr, outer_error.bridge.commitment)?;
        outer_error_commitment.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.challenge(&mut dr)?;
        let nu_prime = transcript.challenge(&mut dr)?;

        let ab = self.compute_ab(rng, a, b, &source, &mu_prime, &nu_prime)?;
        let ab_commitment = Point::constant(&mut dr, ab.bridge.commitment)?;
        ab_commitment.write(&mut dr, &mut transcript)?;
        let x = transcript.challenge(&mut dr)?;

        let (query, query_witness) =
            self.compute_query(rng, &w, &x, &y, &z, &inner_error, &left, &right)?;
        let query_commitment = Point::constant(&mut dr, query.bridge.commitment)?;
        query_commitment.write(&mut dr, &mut transcript)?;
        let alpha = transcript.challenge(&mut dr)?;

        let f = self.compute_f(
            rng,
            &w,
            &y,
            &z,
            &x,
            &alpha,
            &s_prime,
            &inner_error,
            &ab,
            &query,
            &left,
            &right,
        )?;
        let f_commitment = Point::constant(&mut dr, f.bridge.commitment)?;
        f_commitment.write(&mut dr, &mut transcript)?;
        let u = transcript.challenge(&mut dr)?;

        let (eval, eval_witness) =
            self.compute_eval(rng, &u, &left, &right, &s_prime, &inner_error, &ab, &query)?;
        let eval_commitment = Point::constant(&mut dr, eval.bridge.commitment)?;
        eval_commitment.write(&mut dr, &mut transcript)?;
        let pre_beta = transcript.challenge(&mut dr)?;

        let (p, beta_endo, points_witness) = self.compute_p(
            &pre_beta,
            &u,
            &left,
            &right,
            &s_prime,
            &inner_error,
            &ab,
            &query,
            &f,
        )?;

        let challenges = proof::Challenges::new(
            &w, &y, &z, &mu, &nu, &mu_prime, &nu_prime, &x, &alpha, &u, &pre_beta,
        );

        let circuits = self.compute_internal_circuits(
            rng,
            &preamble,
            &s_prime,
            &outer_error,
            &inner_error,
            &ab,
            &query,
            &f,
            &eval,
            &p,
            &preamble_witness,
            &outer_error_witness,
            &inner_error_witness,
            &query_witness,
            &eval_witness,
            &challenges,
            beta_endo,
            &points_witness,
        )?;

        let proof = Proof {
            application,
            preamble,
            s_prime,
            inner_error,
            outer_error,
            ab,
            query,
            f,
            eval,
            p,
            challenges,
            circuits,
        };

        Ok((proof.carry(application_data), application_aux))
    }
}
