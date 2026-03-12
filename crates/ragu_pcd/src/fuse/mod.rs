//! Proof fusion implementation for combining child proofs.
//!
//! Implements the core [`Application::fuse`] operation that takes two child
//! proofs and produces a new proof, computing each proof component in sequence.

mod _01_application;
mod _02_preamble;
mod _03_s_prime;
mod _04_error_m;
mod _05_error_n;
mod _06_ab;
mod _07_query;
mod _08_f;
mod _09_eval;
mod _10_p;
mod _11_circuits;

use alloc::sync::Arc;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, structured},
    registry::CircuitIndex,
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt, Point, vec::CollectFixed};
use rand::CryptoRng;

use crate::{
    Application, Pcd, Proof, RAGU_TAG,
    components::claims::{Source, native::RxComponent},
    components::transcript::Transcript,
    proof,
    step::Step,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Fuse two [`Pcd`] into one using a provided [`Step`].
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
    pub fn fuse<RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux)> {
        let (left, right, application, application_data, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right)?;
        let left = Arc::new(left);
        let right = Arc::new(right);

        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(self.params), RAGU_TAG)?;

        let (preamble, preamble_witness) =
            self.compute_preamble(rng, Arc::clone(&left), Arc::clone(&right), &application)?;
        let preamble_commitment = Point::constant(&mut dr, preamble.nested_commitment)?;
        preamble_commitment.write(&mut dr, &mut transcript)?;
        let w = transcript.challenge(&mut dr)?;
        let registry_at_w = self.native_registry.at(*w.value().take());

        let s_prime = self.compute_s_prime(rng, &registry_at_w, &left, &right)?;
        let s_prime_commitment = Point::constant(&mut dr, s_prime.nested_s_prime_commitment)?;
        s_prime_commitment.write(&mut dr, &mut transcript)?;
        let y = transcript.challenge(&mut dr)?;
        let z = transcript.challenge(&mut dr)?;

        let (error_m, error_m_witness, claims) =
            self.compute_errors_m(rng, &registry_at_w, &y, &z, &left, &right)?;
        let error_m_commitment = Point::constant(&mut dr, error_m.nested_commitment)?;
        error_m_commitment.write(&mut dr, &mut transcript)?;

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

        let (error_n, error_n_witness, a, b) = self.compute_errors_n(
            rng,
            Arc::clone(&preamble_witness),
            Arc::clone(&error_m_witness),
            claims,
            &y,
            &mu,
            &nu,
            saved_transcript_state,
        )?;
        let error_n_commitment = Point::constant(&mut dr, error_n.nested_commitment)?;
        error_n_commitment.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.challenge(&mut dr)?;
        let nu_prime = transcript.challenge(&mut dr)?;

        let ab = self.compute_ab(rng, a, b, &mu_prime, &nu_prime)?;
        let ab_commitment = Point::constant(&mut dr, ab.nested_commitment)?;
        ab_commitment.write(&mut dr, &mut transcript)?;
        let x = transcript.challenge(&mut dr)?;

        let (query, query_witness) =
            self.compute_query(rng, &w, &x, &y, &z, &error_m, &left, &right)?;
        let query_commitment = Point::constant(&mut dr, query.nested_commitment)?;
        query_commitment.write(&mut dr, &mut transcript)?;
        let alpha = transcript.challenge(&mut dr)?;

        let f = self.compute_f(
            rng, &w, &y, &z, &x, &alpha, &s_prime, &error_m, &ab, &query, &left, &right,
        )?;
        let f_commitment = Point::constant(&mut dr, f.nested_commitment)?;
        f_commitment.write(&mut dr, &mut transcript)?;
        let u = transcript.challenge(&mut dr)?;

        let (eval, eval_witness) =
            self.compute_eval(rng, &u, &left, &right, &s_prime, &error_m, &ab, &query)?;
        let eval_commitment = Point::constant(&mut dr, eval.nested_commitment)?;
        eval_commitment.write(&mut dr, &mut transcript)?;
        let pre_beta = transcript.challenge(&mut dr)?;

        let p = self.compute_p(
            &pre_beta, &u, &left, &right, &s_prime, &error_m, &ab, &query, &f,
        )?;

        let challenges = proof::Challenges::new(
            &w, &y, &z, &mu, &nu, &mu_prime, &nu_prime, &x, &alpha, &u, &pre_beta,
        );

        let circuits = self.compute_internal_circuits(
            rng,
            &preamble,
            &s_prime,
            &error_n,
            &error_m,
            &ab,
            &query,
            &f,
            &eval,
            &p,
            preamble_witness,
            error_n_witness,
            error_m_witness,
            query_witness,
            eval_witness,
            &challenges,
        )?;

        let proof = Proof {
            application,
            preamble,
            s_prime,
            error_n,
            error_m,
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

pub(crate) struct FuseProofSource<'rx, C: Cycle, R: Rank> {
    pub(crate) left: &'rx Proof<C, R>,
    pub(crate) right: &'rx Proof<C, R>,
}

impl<'rx, C: Cycle, R: Rank> Source for FuseProofSource<'rx, C, R> {
    type RxComponent = RxComponent;
    type Rx = &'rx structured::Polynomial<C::CircuitField, R>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
        [
            self.left.native_rx(component),
            self.right.native_rx(component),
        ]
        .into_iter()
    }

    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
        [
            self.left.application.circuit_id,
            self.right.application.circuit_id,
        ]
        .into_iter()
    }
}
