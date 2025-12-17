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

use core::marker::PhantomData;

use super::{
    stages::native::{eval as native_eval, preamble as native_preamble, query as native_query},
    unified::{self, OutputBuilder},
};
use crate::components::{fold_revdot::Parameters, transcript};

pub use crate::internal_circuits::InternalCircuitIndex::VCircuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::VStaged as STAGED_ID;

pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, P: Parameters> {
    params: &'params C,
    _marker: PhantomData<(C, R, P)>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters>
    Circuit<'params, C, R, HEADER_SIZE, P>
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

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> StagedCircuit<C::CircuitField, R>
    for Circuit<'_, C, R, HEADER_SIZE, P>
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
        let builder = builder.skip_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
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

        // Get (mu, nu, mu', nu') from unified instance (derived by c circuit from error commitments).
        let _mu = unified_output.mu.get(dr, unified_instance)?;
        let _nu = unified_output.nu.get(dr, unified_instance)?;
        let _mu_prime = unified_output.mu_prime.get(dr, unified_instance)?;
        let nu_prime = unified_output.nu_prime.get(dr, unified_instance)?;

        // Derive x = H(nu', nested_ab_commitment) and enforce query stage's x matches.
        let x = {
            let nested_ab_commitment = unified_output
                .nested_ab_commitment
                .get(dr, unified_instance)?;
            let x =
                transcript::derive_x::<_, C>(dr, &nu_prime, &nested_ab_commitment, self.params)?;
            x.enforce_equal(dr, &query.x)?;
            x
        };

        unified_output.x.set(x.clone());

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

        // Derive beta = H(nested_eval_commitment).
        {
            let nested_eval_commitment = unified_output
                .nested_eval_commitment
                .get(dr, unified_instance)?;
            let beta = transcript::derive_beta::<_, C>(dr, &nested_eval_commitment, self.params)?;
            unified_output.beta.set(beta);
        }

        // TODO: what to do with txz? launder out as aux data?
        let z = unified_output.z.get(dr, unified_instance)?;
        let evaluate_txz = Evaluate::new(R::RANK);
        let _txz = dr.routine(evaluate_txz, (x, z))?;

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
