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

use arithmetic::Cycle;
use ragu_circuits::{
    mesh::CircuitIndex,
    polynomials::{Rank, structured},
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt, Point, poseidon::Sponge, vec::CollectFixed};
use rand::Rng;

use crate::{
    Application, Pcd, Proof,
    components::claims::{Source, native::RxComponent},
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
    pub fn fuse<'source, RNG: Rng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        let (left, right, application, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right)?;

        let mut dr = Emulator::execute();
        let mut transcript = Sponge::new(&mut dr, C::circuit_poseidon(self.params));

        let (preamble, preamble_witness) =
            self.compute_preamble(rng, &left, &right, &application)?;
        Point::constant(&mut dr, preamble.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let w = transcript.squeeze(&mut dr)?;

        let s_prime = self.compute_s_prime(rng, &w, &left, &right)?;
        Point::constant(&mut dr, s_prime.nested_s_prime_commitment)?
            .write(&mut dr, &mut transcript)?;
        let y = transcript.squeeze(&mut dr)?;
        let z = transcript.squeeze(&mut dr)?;

        let (error_m, error_m_witness, claims) =
            self.compute_errors_m(rng, &w, &y, &z, &left, &right)?;
        Point::constant(&mut dr, error_m.nested_commitment)?.write(&mut dr, &mut transcript)?;

        let saved_transcript_state = transcript
            .clone()
            .save_state(&mut dr)
            .expect("save_state should succeed after absorbing")
            .into_elements()
            .into_iter()
            .map(|e| *e.value().take())
            .collect_fixed()?;

        let mu = transcript.squeeze(&mut dr)?;
        let nu = transcript.squeeze(&mut dr)?;

        let (error_n, error_n_witness, a, b) = self.compute_errors_n(
            rng,
            &preamble_witness,
            &error_m_witness,
            claims,
            &y,
            &mu,
            &nu,
            saved_transcript_state,
        )?;
        Point::constant(&mut dr, error_n.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.squeeze(&mut dr)?;
        let nu_prime = transcript.squeeze(&mut dr)?;

        let ab = self.compute_ab(rng, a, b, &mu_prime, &nu_prime)?;
        Point::constant(&mut dr, ab.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let x = transcript.squeeze(&mut dr)?;

        let (query, query_witness) =
            self.compute_query(rng, &w, &x, &y, &z, &error_m, &left, &right)?;
        Point::constant(&mut dr, query.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let alpha = transcript.squeeze(&mut dr)?;

        let f = self.compute_f(
            rng, &w, &y, &z, &x, &alpha, &s_prime, &error_m, &ab, &query, &left, &right,
        )?;
        Point::constant(&mut dr, f.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let u = transcript.squeeze(&mut dr)?;

        let (eval, eval_witness) =
            self.compute_eval(rng, &u, &left, &right, &s_prime, &error_m, &ab, &query)?;
        Point::constant(&mut dr, eval.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let pre_beta = transcript.squeeze(&mut dr)?;

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
            &preamble_witness,
            &error_n_witness,
            &error_m_witness,
            &query_witness,
            &eval_witness,
            &challenges,
        )?;

        Ok((
            Proof {
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
            },
            application_aux,
        ))
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
        use RxComponent::*;
        let (left_poly, right_poly) = match component {
            AbA => (&self.left.ab.a_poly, &self.right.ab.a_poly),
            AbB => (&self.left.ab.b_poly, &self.right.ab.b_poly),
            Application => (&self.left.application.rx, &self.right.application.rx),
            Hashes1 => (
                &self.left.circuits.hashes_1_rx,
                &self.right.circuits.hashes_1_rx,
            ),
            Hashes2 => (
                &self.left.circuits.hashes_2_rx,
                &self.right.circuits.hashes_2_rx,
            ),
            PartialCollapse => (
                &self.left.circuits.partial_collapse_rx,
                &self.right.circuits.partial_collapse_rx,
            ),
            FullCollapse => (
                &self.left.circuits.full_collapse_rx,
                &self.right.circuits.full_collapse_rx,
            ),
            ComputeV => (
                &self.left.circuits.compute_v_rx,
                &self.right.circuits.compute_v_rx,
            ),
            EndoscaleChallenges => (
                &self.left.circuits.endoscale_challenges_rx,
                &self.right.circuits.endoscale_challenges_rx,
            ),
            Preamble => (
                &self.left.preamble.native_rx,
                &self.right.preamble.native_rx,
            ),
            ErrorM => (&self.left.error_m.native_rx, &self.right.error_m.native_rx),
            ErrorN => (&self.left.error_n.native_rx, &self.right.error_n.native_rx),
            Query => (&self.left.query.native_rx, &self.right.query.native_rx),
            Eval => (&self.left.eval.native_rx, &self.right.eval.native_rx),
        };
        [left_poly, right_poly].into_iter()
    }

    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
        [
            self.left.application.circuit_id,
            self.right.application.circuit_id,
        ]
        .into_iter()
    }
}
