//! Second hash circuit for Fiat-Shamir derivations (continuation of transcript).
//!
//! This circuit resumes the Fiat-Shamir transcript from the saved sponge state
//! (after hashes_1 absorbed nested_error_m_commitment) and derives:
//! - `(mu, nu)` - squeezed from saved state (error_m already absorbed)
//! - `(mu_prime, nu_prime) = H(nested_error_n_commitment)`
//! - `x = H(nested_ab_commitment)`
//! - `alpha = H(nested_query_commitment)`
//! - `u = H(nested_f_commitment)`
//! - `beta = H(nested_eval_commitment)`

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
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
    stages::native::{
        error_m as native_error_m, error_n as native_error_n, preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::components::fold_revdot;

pub use crate::internal_circuits::InternalCircuitIndex::Hashes2Circuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::Hashes2Staged as STAGED_ID;

pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    params: &'params C,
    _marker: PhantomData<(R, FP)>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<'params, C, R, HEADER_SIZE, FP>
{
    pub fn new(params: &'params C) -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            params,
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle, FP: fold_revdot::Parameters> {
    pub unified_instance: &'a unified::Instance<C>,
    pub error_n_witness: &'a native_error_n::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    StagedCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, FP>
{
    type Final = native_error_n::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, FP>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        OutputBuilder::new().finish(dr, &instance)
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
        let builder = builder.skip_stage::<native_error_m::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let error_n = error_n.unenforced(dr, witness.view().map(|w| w.error_n_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Resume sponge from saved state (error_m already absorbed in hashes_1)
        // and squeeze mu (first challenge from error_m absorption)
        let (mu, mut sponge) =
            Sponge::resume_and_squeeze(dr, error_n.sponge_state, self.params.circuit_poseidon())?;
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

        // Derive beta by absorbing nested_eval_commitment and squeezing
        let beta = {
            let nested_eval_commitment = unified_output
                .nested_eval_commitment
                .get(dr, unified_instance)?;
            nested_eval_commitment.write(dr, &mut sponge)?;
            sponge.squeeze(dr)?
        };
        unified_output.beta.set(beta);

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
