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
mod orchestrator;
mod side;
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

use orchestrator::FuseOrchestrator;
use ragu_circuits::polynomials::Rank;
use ragu_core::{Error, Result};
use rand::CryptoRng;
use udon::field::Field;

use crate::{Application, Pcd, profile::ProfiledCycle, proof::ProofBuilder, step::Step};

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

        let proof = FuseOrchestrator::new(self, &left, &right).fuse(rng, builder)?;

        Ok((proof.carry(application_data), application_aux))
    }
}
