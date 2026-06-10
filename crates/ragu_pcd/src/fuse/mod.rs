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

use claims::FuseProofSource;
use ragu_arithmetic::{CryptoRngCore, Cycle, ff::Field};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt, Point, vec::CollectFixed};

use crate::{
    Application, Pcd, RAGU_TAG, internal::transcript::Transcript, proof::ProofBuilder, step::Step,
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
    pub fn fuse<'source, RNG: CryptoRngCore, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        let mut builder = ProofBuilder::new(self.params, C::ScalarField::random(&mut *rng));

        let (left, right, application_data, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right, &mut builder)?;

        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(self.params), RAGU_TAG)?;

        let preamble_witness = self.compute_preamble(rng, &left, &right, &mut builder)?;
        let preamble_commitment = Point::constant(&mut dr, builder.bridge_preamble_commitment())?;
        preamble_commitment.write(&mut dr, &mut transcript)?;
        let w = transcript.challenge(&mut dr)?;
        let native_registry = self.native_registry.at(*w.value().take());

        let native_s_prime =
            self.compute_s_prime(rng, &native_registry, &left, &right, &mut builder)?;
        let s_prime_commitment = Point::constant(&mut dr, builder.bridge_s_prime_commitment())?;
        s_prime_commitment.write(&mut dr, &mut transcript)?;
        let y = transcript.challenge(&mut dr)?;
        let z = transcript.challenge(&mut dr)?;

        let source = FuseProofSource {
            left: &left,
            right: &right,
        };

        let (inner_error_witness, claims, registry_wy) =
            self.inner_error_terms(rng, &native_registry, &y, &z, &source, &mut builder)?;
        let inner_error_commitment =
            Point::constant(&mut dr, builder.bridge_inner_error_commitment())?;
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

        let (outer_error_witness, a, b) = self.outer_error_terms(
            rng,
            &preamble_witness,
            &inner_error_witness,
            claims,
            &y,
            &mu,
            &nu,
            saved_transcript_state,
            &mut builder,
        )?;
        let outer_error_commitment =
            Point::constant(&mut dr, builder.bridge_outer_error_commitment()?)?;
        outer_error_commitment.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.challenge(&mut dr)?;
        let nu_prime = transcript.challenge(&mut dr)?;

        self.compute_ab(a, b, &source, &mu_prime, &nu_prime, &mut builder)?;
        let ab_commitment = Point::constant(&mut dr, builder.bridge_ab_commitment()?)?;
        ab_commitment.write(&mut dr, &mut transcript)?;
        let x = transcript.challenge(&mut dr)?;

        let query_witness = self.compute_query(
            rng,
            &w,
            &x,
            &y,
            &z,
            &registry_wy,
            &left,
            &right,
            &mut builder,
        )?;
        let query_commitment = Point::constant(&mut dr, builder.bridge_query_commitment()?)?;
        query_commitment.write(&mut dr, &mut transcript)?;
        let alpha = transcript.challenge(&mut dr)?;

        let native_f = self.compute_f(
            rng,
            &w,
            &y,
            &z,
            &x,
            &alpha,
            &native_s_prime,
            &registry_wy,
            &mut builder,
            &left,
            &right,
        )?;
        let f_commitment = Point::constant(&mut dr, builder.bridge_f_commitment())?;
        f_commitment.write(&mut dr, &mut transcript)?;
        let u = transcript.challenge(&mut dr)?;

        let eval_witness = self.compute_eval(
            rng,
            &u,
            &left,
            &right,
            &native_s_prime,
            &registry_wy,
            &mut builder,
        )?;
        let eval_commitment = Point::constant(&mut dr, builder.bridge_eval_commitment()?)?;
        eval_commitment.write(&mut dr, &mut transcript)?;
        let pre_beta = transcript.challenge(&mut dr)?;

        self.compute_p(
            rng,
            &pre_beta,
            &left,
            &right,
            &native_s_prime,
            &registry_wy,
            &native_f,
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
        builder.set_pre_beta(*pre_beta.value().take());

        // Store children's stage rx polynomials for copying circuit claims.
        builder.set_child_left_stage_rx(left.as_child_stage_rx());
        builder.set_child_right_stage_rx(right.as_child_stage_rx());

        self.compute_internal_circuits(
            rng,
            &preamble_witness,
            &outer_error_witness,
            &inner_error_witness,
            &query_witness,
            &eval_witness,
            &mut builder,
        )?;

        let proof = builder.build()?;

        Ok((proof.carry(application_data), application_aux))
    }
}
