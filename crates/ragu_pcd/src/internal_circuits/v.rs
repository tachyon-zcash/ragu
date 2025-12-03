use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{GadgetExt, Sponge};

use core::marker::PhantomData;

use super::unified::{self, OutputBuilder};
use crate::stages::{native_eval, native_preamble, native_query};

pub const CIRCUIT_ID: usize = super::V_CIRCUIT_ID;

pub struct Circuit<'a, C: Cycle, R> {
    circuit_poseidon: &'a C::CircuitPoseidon,
    _marker: PhantomData<(C, R)>,
}

impl<'a, C: Cycle, R> Circuit<'a, C, R> {
    pub fn new(circuit_poseidon: &'a C::CircuitPoseidon) -> Self {
        Circuit {
            circuit_poseidon,
            _marker: PhantomData,
        }
    }
}

pub struct Witness<'a, C: Cycle> {
    pub unified_instance: &'a unified::Instance<C>,
    pub query_witness: &'a native_query::Witness<C::NestedCurve>,
    pub eval_witness: &'a native_eval::Witness<C::CircuitField>,
}

impl<C: Cycle, R: Rank> StagedCircuit<C::CircuitField, R> for Circuit<'_, C, R> {
    type Final = native_eval::Eval<C::NestedCurve, R>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C>;
    type Output = Kind![C::CircuitField; unified::Output<'_, _, C>];
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
        let (_, builder) = builder.add_stage::<native_preamble::Preamble<C::CircuitField, R>>()?;
        let (query, builder) = builder.add_stage::<native_query::Query<C::NestedCurve, R>>()?;
        let (eval, builder) = builder.add_stage::<native_eval::Eval<C::NestedCurve, R>>()?;
        let dr = builder.finish();

        let query = query.unenforced(witness.view().map(|w| w.query_witness))?;
        let eval = eval.unenforced(witness.view().map(|w| w.eval_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        let nested_f_commitment = unified_output.nested_f_commitment.get(dr, unified_instance);

        // Computation of (mu, nu)
        let (mu, nu) = {
            let nested_error_commitment = unified_output
                .nested_error_commitment
                .get(dr, unified_instance);
            let mut sponge = Sponge::new(dr, self.circuit_poseidon);
            nested_error_commitment.write(dr, &mut sponge)?;
            let mu = sponge.squeeze(dr)?;
            let nu = sponge.squeeze(dr)?;

            (mu, nu)
        };

        // Computation of x
        {
            let nested_ab_commitment = unified_output
                .nested_ab_commitment
                .get(dr, unified_instance);

            let mut sponge = Sponge::new(dr, self.circuit_poseidon);
            sponge.absorb(dr, &mu)?;
            nested_ab_commitment.write(dr, &mut sponge)?;
            let x = sponge.squeeze(dr)?;

            // Query stage's x must equal x.
            x.enforce_equal(dr, &query.x)?;
        }

        unified_output.mu.set(mu);
        unified_output.nu.set(nu);

        // Computation of alpha
        let alpha = {
            let nested_query_commitment = unified_output
                .nested_query_commitment
                .get(dr, unified_instance);
            let mut sponge = Sponge::new(dr, self.circuit_poseidon);
            nested_query_commitment.write(dr, &mut sponge)?;
            sponge.squeeze(dr)?
        };

        unified_output.alpha.set(alpha.clone());

        // Computation of u
        {
            let mut sponge = Sponge::new(dr, self.circuit_poseidon);
            sponge.absorb(dr, &alpha)?;
            nested_f_commitment.write(dr, &mut sponge)?;
            let u = sponge.squeeze(dr)?;

            // Eval stage's u must equal u.
            u.enforce_equal(dr, &eval.u)?;

            unified_output.u.set(u);
        }

        // Computation of beta
        {
            let nested_eval_commitment = unified_output
                .nested_eval_commitment
                .get(dr, unified_instance);
            let mut sponge = Sponge::new(dr, self.circuit_poseidon);
            nested_eval_commitment.write(dr, &mut sponge)?;
            let beta = sponge.squeeze(dr)?;
            unified_output.beta.set(beta);
        }

        unified_output
            .nested_s_commitment
            .set(query.nested_s_commitment);

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
