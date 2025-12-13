use crate::components::transcript;
use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind},
    maybe::Maybe,
};

use core::marker::PhantomData;

use super::stages::native::{
    eval as native_eval, preamble as native_preamble, query as native_query,
};
use super::unified::{self, OutputBuilder};

pub use crate::internal_circuits::InternalCircuitIndex::VCircuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::VStaged as STAGED_ID;

pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, const NUM_REVDOT_CLAIMS: usize> {
    params: &'params C,
    _marker: PhantomData<(C, R)>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, const NUM_REVDOT_CLAIMS: usize>
    Circuit<'params, C, R, HEADER_SIZE, NUM_REVDOT_CLAIMS>
{
    pub fn new(params: &'params C) -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            params,
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle> {
    pub unified_instance: &'a unified::Instance<C>,
    pub query_witness: &'a native_query::Witness<C::CircuitField>,
    pub eval_witness: &'a native_eval::Witness<C::CircuitField>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, const NUM_REVDOT_CLAIMS: usize>
    StagedCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, NUM_REVDOT_CLAIMS>
{
    type Final = native_eval::Stage<C, R, HEADER_SIZE>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C>;
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
        let (_, builder) = builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (query, builder) = builder.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
        let (eval, builder) = builder.add_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();

        let query = query.enforced(dr, witness.view().map(|w| w.query_witness))?;
        let eval = eval.enforced(dr, witness.view().map(|w| w.eval_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        let nested_f_commitment = unified_output
            .nested_f_commitment
            .get(dr, unified_instance)?;

        // Derive (mu, nu) = H(nested_error_commitment).
        let (mu, nu) = {
            let nested_error_commitment = unified_output
                .nested_error_commitment
                .get(dr, unified_instance)?;
            transcript::derive_mu_nu::<_, C>(dr, &nested_error_commitment, self.params)?
        };

        // Derive x = H(mu, nested_ab_commitment) and enforce query stage's x matches.
        {
            let nested_ab_commitment = unified_output
                .nested_ab_commitment
                .get(dr, unified_instance)?;
            let x = transcript::derive_x::<_, C>(dr, &mu, &nested_ab_commitment, self.params)?;
            x.enforce_equal(dr, &query.x)?;
        }

        unified_output.mu.set(mu);
        unified_output.nu.set(nu);

        // Derive alpha challenge.
        let alpha = {
            let nested_query_commitment = unified_output
                .nested_query_commitment
                .get(dr, unified_instance)?;
            transcript::derive_alpha::<_, C>(dr, &nested_query_commitment, self.params)?
        };
        unified_output.alpha.set(alpha.clone());

        // Derive u challenge.
        {
            let u = transcript::derive_u::<_, C>(dr, &alpha, &nested_f_commitment, self.params)?;

            // Eval stage's u must equal u.
            u.enforce_equal(dr, &eval.u)?;

            unified_output.u.set(u);
        }

        // TODO: Derive beta challenge.

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
