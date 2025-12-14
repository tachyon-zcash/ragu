use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, txz::Evaluate},
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind},
    maybe::Maybe,
};
use ragu_primitives::{GadgetExt, Sponge};

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
    pub query_witness: &'a native_query::Witness<C>,
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

        // Create transcript sponge for Fiat-Shamir challenge derivation.
        let mut transcript = Sponge::new(dr, self.params.circuit_poseidon());

        // Advance sponge state.
        {
            let nested_preamble_commitment = unified_output
                .nested_preamble_commitment
                .get(dr, unified_instance)?;
            nested_preamble_commitment.write(dr, &mut transcript)?;
            transcript.squeeze(dr)?;
        }

        // Derive (y, z) = H(w, nested_s_prime_commitment).
        let (y, z) = {
            let nested_s_prime_commitment = unified_output
                .nested_s_prime_commitment
                .get(dr, unified_instance)?;
            nested_s_prime_commitment.write(dr, &mut transcript)?;
            let y = transcript.squeeze(dr)?;
            let z = transcript.squeeze(dr)?;
            (y, z)
        };
        unified_output.y.set(y);
        unified_output.z.set(z.clone());

        // Derive (mu, nu) = H(nested_error_commitment).
        let (mu, nu) = {
            let nested_error_commitment = unified_output
                .nested_error_commitment
                .get(dr, unified_instance)?;
            nested_error_commitment.write(dr, &mut transcript)?;
            let mu = transcript.squeeze(dr)?;
            let nu = transcript.squeeze(dr)?;
            (mu, nu)
        };
        unified_output.mu.set(mu);
        unified_output.nu.set(nu.clone());

        // Derive x = H(nu, nested_ab_commitment) and enforce query stage's x matches.
        let x = {
            let nested_ab_commitment = unified_output
                .nested_ab_commitment
                .get(dr, unified_instance)?;
            nested_ab_commitment.write(dr, &mut transcript)?;
            let x = transcript.squeeze(dr)?;
            x.enforce_equal(dr, &query.x)?;
            x
        };
        unified_output.x.set(x.clone());

        // Query stage's nested_s_commitment must equal the one in unified output.
        unified_output
            .nested_s_commitment
            .set(query.nested_s_commitment);

        // Derive alpha = H(nested_query_commitment).
        let alpha = {
            let nested_query_commitment = unified_output
                .nested_query_commitment
                .get(dr, unified_instance)?;
            nested_query_commitment.write(dr, &mut transcript)?;
            transcript.squeeze(dr)?
        };
        unified_output.alpha.set(alpha);

        // Derive u = H(alpha, nested_f_commitment).
        let u = {
            let nested_f_commitment = unified_output
                .nested_f_commitment
                .get(dr, unified_instance)?;
            nested_f_commitment.write(dr, &mut transcript)?;
            let u = transcript.squeeze(dr)?;
            // Eval stage's u must equal u.
            u.enforce_equal(dr, &eval.u)?;
            u
        };
        unified_output.u.set(u);

        // Derive beta = H(nested_eval_commitment).
        let beta = {
            let nested_eval_commitment = unified_output
                .nested_eval_commitment
                .get(dr, unified_instance)?;
            nested_eval_commitment.write(dr, &mut transcript)?;
            transcript.squeeze(dr)?
        };
        unified_output.beta.set(beta);

        // TODO: what to do with txz? launder out as aux data?
        let evaluate_txz = Evaluate::new(R::RANK);
        let _txz = dr.routine(evaluate_txz, (x, z))?;

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
