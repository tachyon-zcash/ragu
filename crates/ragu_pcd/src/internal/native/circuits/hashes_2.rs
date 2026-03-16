//! Second hash circuit for Fiat-Shamir derivations.
//!
//! ## Operations
//!
//! ### Hashes
//!
//! This circuit completes the Fiat-Shamir transcript started in
//! [`hashes_1`][super::hashes_1], invoking $5$ Poseidon permutations:
//! - Resume transcript from saved state via [`Transcript::resume_from_state`] using
//!   the state witnessed in [`error_n`]. (This state was computed by `hashes_1`
//!   after absorbing [`bridge_error_m_commitment`] and applying the permutation
//!   to move into squeeze mode.)
//! - Squeeze [$\mu$] and [$\nu$] challenges.
//! - Absorb [`bridge_error_n_commitment`].
//! - Squeeze [$\mu'$] and [$\nu'$] challenges.
//! - Absorb [`bridge_ab_commitment`].
//! - Squeeze [$x$] challenge.
//! - Absorb [`bridge_query_commitment`].
//! - Squeeze [$\alpha$] challenge.
//! - Absorb [`bridge_f_commitment`].
//! - Squeeze [$u$] challenge.
//! - Absorb [`bridge_eval_commitment`].
//! - Squeeze [$\beta$] challenge.
//!
//! The squeezed $\mu, \nu, \mu', \nu', x, \alpha, u, \beta$ challenges are set
//! in the unified instance by this circuit.
//!
//! ## Staging
//!
//! This circuit is a multi-stage circuit based on the
//! [`error_n`][super::super::stages::error_n] stage, which inherits in the
//! following chain:
//! - [`preamble`][super::super::stages::preamble] (skipped)
//! - [`error_n`][super::super::stages::error_n] (unenforced)
//!
//! ## Instance
//!
//! This circuit uses [`unified::Output`] as its instance, wrapped in a
//! [`WithSuffix`] with a zero element appended. This matches the format used by
//! [`hashes_1`][super::hashes_1] and ensures the instance serialization aligns
//! with the $k(y)$ computation for `unified_ky`.
//!
//! [`bridge_error_m_commitment`]: unified::Output::bridge_error_m_commitment
//! [$\mu$]: unified::Output::mu
//! [$\nu$]: unified::Output::nu
//! [`bridge_error_n_commitment`]: unified::Output::bridge_error_n_commitment
//! [$\mu'$]: unified::Output::mu_prime
//! [$\nu'$]: unified::Output::nu_prime
//! [`bridge_ab_commitment`]: unified::Output::bridge_ab_commitment
//! [$x$]: unified::Output::x
//! [`bridge_query_commitment`]: unified::Output::bridge_query_commitment
//! [$\alpha$]: unified::Output::alpha
//! [`bridge_f_commitment`]: unified::Output::bridge_f_commitment
//! [$u$]: unified::Output::u
//! [`bridge_eval_commitment`]: unified::Output::bridge_eval_commitment
//! [$\beta$]: unified::Output::pre_beta
//! [`error_n`]: super::super::stages::error_n
//! [`WithSuffix`]: crate::internal::suffix::WithSuffix
//! [`Transcript::resume_from_state`]: crate::internal::transcript::Transcript::resume_from_state

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::GadgetExt;

use core::marker::PhantomData;

use super::super::{
    stages::{error_n as native_error_n, preamble as native_preamble},
    unified::{self, OutputBuilder},
};
use crate::internal::fold_revdot;
use crate::internal::transcript::Transcript;

/// Second hash circuit for Fiat-Shamir challenge derivation.
///
/// The [module-level documentation] describes the operations performed by this
/// circuit.
///
/// [module-level documentation]: self
pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    params: &'params C::Params,
    _marker: PhantomData<(R, FP)>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<'params, C, R, HEADER_SIZE, FP>
{
    /// Creates a new multi-stage circuit.
    ///
    /// # Parameters
    ///
    /// - `params`: Curve cycle parameters providing Poseidon configuration.
    pub fn new(params: &'params C::Params) -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            params,
            _marker: PhantomData,
        })
    }
}

/// Witness data for the second hash circuit.
///
/// Combines the unified instance with the
/// [`error_n`](super::super::stages::error_n) stage witness needed to resume
/// the Fiat-Shamir transcript from the saved sponge state.
pub struct Witness<'a, C: Cycle, FP: fold_revdot::Parameters> {
    /// The unified instance containing expected challenge values and
    /// accumulated coverage from prior circuits.
    pub unified: unified::Instance<C>,

    /// Witness for the [`error_n`](super::super::stages::error_n) stage
    /// (unenforced).
    ///
    /// Provides the saved sponge state for transcript resumption.
    pub error_n_witness: &'a native_error_n::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, FP>
{
    type Last = native_error_n::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, FP>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        Bound<'dr, D, Self::Output>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let builder = builder.skip_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let error_n = error_n.unenforced(dr, witness.as_ref().map(|w| w.error_n_witness))?;

        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        // Resume transcript from saved state (error_m already absorbed in hashes_1)
        // and squeeze mu, nu (challenges from error_m absorption)
        let mut resumed =
            Transcript::resume_from_state(error_n.sponge_state, C::circuit_poseidon(self.params));
        let mu = resumed.challenge(dr)?;
        unified_output.mu.provide(mu);

        let nu = resumed.challenge(dr)?;
        unified_output.nu.provide(nu);

        // Transition back to absorb mode for the rest of the transcript
        let mut transcript = resumed.into_transcript();

        // Derive (mu_prime, nu_prime) by absorbing bridge_error_n_commitment
        let (mu_prime, nu_prime) = {
            let bridge_error_n_commitment = unified_output.bridge_error_n_commitment.receive(dr)?;
            bridge_error_n_commitment.write(dr, &mut transcript)?;
            let mu_prime = transcript.challenge(dr)?;
            let nu_prime = transcript.challenge(dr)?;
            (mu_prime, nu_prime)
        };
        unified_output.mu_prime.provide(mu_prime);
        unified_output.nu_prime.provide(nu_prime);

        // Derive x by absorbing bridge_ab_commitment and squeezing
        let x = {
            let bridge_ab_commitment = unified_output.bridge_ab_commitment.receive(dr)?;
            bridge_ab_commitment.write(dr, &mut transcript)?;
            transcript.challenge(dr)?
        };
        unified_output.x.provide(x);

        // Derive alpha by absorbing bridge_query_commitment and squeezing
        let alpha = {
            let bridge_query_commitment = unified_output.bridge_query_commitment.receive(dr)?;
            bridge_query_commitment.write(dr, &mut transcript)?;
            transcript.challenge(dr)?
        };
        unified_output.alpha.provide(alpha.clone());

        // Derive u by absorbing bridge_f_commitment and squeezing
        let u = {
            let bridge_f_commitment = unified_output.bridge_f_commitment.receive(dr)?;
            bridge_f_commitment.write(dr, &mut transcript)?;
            transcript.challenge(dr)?
        };
        unified_output.u.provide(u);

        // Derive pre_beta by absorbing bridge_eval_commitment and squeezing
        let pre_beta = {
            let bridge_eval_commitment = unified_output.bridge_eval_commitment.receive(dr)?;
            bridge_eval_commitment.write(dr, &mut transcript)?;
            transcript.challenge(dr)?
        };
        unified_output.pre_beta.provide(pre_beta);

        unified_output.finish(dr)
    }
}
