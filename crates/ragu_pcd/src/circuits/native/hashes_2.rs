//! Second hash circuit for Fiat-Shamir derivations.
//!
//! ## Operations
//!
//! ### Hashes
//!
//! This circuit completes the Fiat-Shamir transcript started in
//! [`hashes_1`][super::hashes_1], invoking $5$ Poseidon permutations:
//! - Resume sponge from saved state via [`Sponge::resume_and_squeeze`] using
//!   the state witnessed in [`error_n`]. (This state was computed by `hashes_1`
//!   after absorbing [`nested_error_m_commitment`] and applying the permutation
//!   to move into squeeze mode.)
//! - Squeeze [$\mu$] and [$\nu$] challenges.
//! - Absorb [`nested_error_n_commitment`].
//! - Squeeze [$\mu'$] and [$\nu'$] challenges.
//! - Absorb [`nested_ab_commitment`].
//! - Squeeze [$x$] challenge.
//! - Absorb [`nested_query_commitment`].
//! - Squeeze [$\alpha$] challenge.
//! - Absorb [`nested_f_commitment`].
//! - Squeeze [$u$] challenge.
//! - Absorb [`nested_eval_commitment`].
//! - Squeeze [$\beta$] challenge.
//!
//! The squeezed $\mu, \nu, \mu', \nu', x, \alpha, u, \beta$ challenges are set
//! in the unified instance by this circuit.
//!
//! ## Staging
//!
//! This circuit is a multi-stage circuit based on the
//! [`error_n`][super::stages::error_n] stage, which inherits in the
//! following chain:
//! - [`preamble`][super::stages::preamble] (skipped)
//! - [`error_n`][super::stages::error_n] (unenforced)
//!
//! ## Public Inputs
//!
//! This circuit uses the [`unified::Output`] as its public inputs, wrapped in a
//! [`WithSuffix`] with a zero element appended. This matches the format used by
//! [`hashes_1`][super::hashes_1] and ensures the public input serialization
//! aligns with the $k(y)$ computation for `unified_ky`.
//!
//! [`nested_error_m_commitment`]: unified::Output::nested_error_m_commitment
//! [$\mu$]: unified::Output::mu
//! [$\nu$]: unified::Output::nu
//! [`nested_error_n_commitment`]: unified::Output::nested_error_n_commitment
//! [$\mu'$]: unified::Output::mu_prime
//! [$\nu'$]: unified::Output::nu_prime
//! [`nested_ab_commitment`]: unified::Output::nested_ab_commitment
//! [$x$]: unified::Output::x
//! [`nested_query_commitment`]: unified::Output::nested_query_commitment
//! [$\alpha$]: unified::Output::alpha
//! [`nested_f_commitment`]: unified::Output::nested_f_commitment
//! [$u$]: unified::Output::u
//! [`nested_eval_commitment`]: unified::Output::nested_eval_commitment
//! [$\beta$]: unified::Output::pre_beta
//! [`error_n`]: super::stages::error_n
//! [`WithSuffix`]: crate::components::suffix::WithSuffix
//! [`Sponge::resume_and_squeeze`]: ragu_primitives::poseidon::Sponge::resume_and_squeeze

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};
use ragu_primitives::{GadgetExt, poseidon::Sponge};

use core::marker::PhantomData;

use super::{
    stages::{error_n as native_error_n, preamble as native_preamble},
    unified::{self, OutputBuilder},
};
use crate::components::fold_revdot;

pub(crate) use super::InternalCircuitIndex::Hashes2Circuit as CIRCUIT_ID;

/// Second hash circuit for Fiat-Shamir challenge derivation.
///
/// See the [module-level documentation] for details on the operations performed
/// by this circuit.
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
/// [`error_n`](super::stages::error_n) stage witness needed to resume
/// the Fiat-Shamir transcript from the saved sponge state.
pub struct Witness<'a, C: Cycle, FP: fold_revdot::Parameters> {
    /// The unified instance containing expected challenge values.
    pub unified_instance: &'a unified::Instance<C>,

    /// Witness for the [`error_n`](super::stages::error_n) stage
    /// (unenforced).
    ///
    /// Provides the saved sponge state for transcript resumption.
    pub error_n_witness: &'a native_error_n::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, FP>
{
    type Final = native_error_n::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, FP>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let builder = builder.skip_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let error_n = error_n.unenforced(dr, witness.view().map(|w| w.error_n_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Resume sponge from saved state (error_m already absorbed in hashes_1)
        // and squeeze mu (first challenge from error_m absorption)
        let (mu, mut sponge) =
            Sponge::resume_and_squeeze(dr, error_n.sponge_state, C::circuit_poseidon(self.params))?;
        unified_output.mu.set(mu);

        // Squeeze nu (second challenge from error_m absorption)
        let nu = sponge.squeeze(dr)?;
        unified_output.nu.set(nu);

        // Derive (mu_prime, nu_prime) by absorbing nested_error_n_commitment
        let (mu_prime, nu_prime) = {
            let nested_error_n_commitment = unified_output
                .nested_error_n_commitment
                .get(dr, unified_instance)?;
            nested_error_n_commitment.write(dr, &mut sponge)?;
            let mu_prime = sponge.squeeze(dr)?;
            let nu_prime = sponge.squeeze(dr)?;
            (mu_prime, nu_prime)
        };
        unified_output.mu_prime.set(mu_prime);
        unified_output.nu_prime.set(nu_prime);

        // Derive x by absorbing nested_ab_commitment and squeezing
        let x = {
            let nested_ab_commitment = unified_output
                .nested_ab_commitment
                .get(dr, unified_instance)?;
            nested_ab_commitment.write(dr, &mut sponge)?;
            sponge.squeeze(dr)?
        };
        unified_output.x.set(x);

        // Derive alpha by absorbing nested_query_commitment and squeezing
        let alpha = {
            let nested_query_commitment = unified_output
                .nested_query_commitment
                .get(dr, unified_instance)?;
            nested_query_commitment.write(dr, &mut sponge)?;
            sponge.squeeze(dr)?
        };
        unified_output.alpha.set(alpha.clone());

        // Derive u by absorbing nested_f_commitment and squeezing
        let u = {
            let nested_f_commitment = unified_output
                .nested_f_commitment
                .get(dr, unified_instance)?;
            nested_f_commitment.write(dr, &mut sponge)?;
            sponge.squeeze(dr)?
        };
        unified_output.u.set(u);

        // Derive pre_beta by absorbing nested_eval_commitment and squeezing
        let pre_beta = {
            let nested_eval_commitment = unified_output
                .nested_eval_commitment
                .get(dr, unified_instance)?;
            nested_eval_commitment.write(dr, &mut sponge)?;
            sponge.squeeze(dr)?
        };
        unified_output.pre_beta.set(pre_beta);

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
