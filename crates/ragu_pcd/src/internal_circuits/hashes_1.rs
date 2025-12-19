//! First hash circuit for Fiat-Shamir derivations (claim-side challenges).
//!
//! This circuit derives the first part of the Fiat-Shamir transcript:
//! - `w = H(nested_preamble_commitment)`
//! - `(y, z) = H(w, nested_s_prime_commitment)`
//! - Absorbs `nested_error_m_commitment` and verifies saved sponge state
//!
//! The remaining challenges (mu, nu, mu_prime, nu_prime, x, alpha, u, beta) are
//! derived in hashes_2 by resuming from the saved sponge state.

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
use ragu_primitives::{GadgetExt, poseidon::Sponge};

use core::marker::PhantomData;

use super::{
    stages::native::{
        error_m as native_error_m, error_n as native_error_n, preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::components::fold_revdot::Parameters;

pub use crate::internal_circuits::InternalCircuitIndex::Hashes1Circuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::Hashes1Staged as STAGED_ID;

pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, P: Parameters> {
    params: &'params C,
    _marker: PhantomData<(R, P)>,
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

pub struct Witness<'a, C: Cycle, P: Parameters> {
    pub unified_instance: &'a unified::Instance<C>,
    pub error_n_witness: &'a native_error_n::Witness<C, P>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> StagedCircuit<C::CircuitField, R>
    for Circuit<'_, C, R, HEADER_SIZE, P>
{
    type Final = native_error_n::Stage<C, R, HEADER_SIZE, P>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, P>;
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
        let builder = builder.skip_stage::<native_error_m::Stage<C, R, HEADER_SIZE, P>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, P>>()?;
        let dr = builder.finish();

        let error_n = error_n.enforced(dr, witness.view().map(|w| w.error_n_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Create a single long-lived sponge for all challenge derivations
        let mut sponge = Sponge::new(dr, self.params.circuit_poseidon());

        // Derive w by absorbing nested_preamble_commitment and squeezing
        let w = {
            let nested_preamble_commitment = unified_output
                .nested_preamble_commitment
                .get(dr, unified_instance)?;
            nested_preamble_commitment.write(dr, &mut sponge)?;
            sponge.squeeze(dr)?
        };
        unified_output.w.set(w.clone());

        // Derive (y, z) by absorbing nested_s_prime_commitment and squeezing twice
        let (y, z) = {
            let nested_s_prime_commitment = unified_output
                .nested_s_prime_commitment
                .get(dr, unified_instance)?;
            nested_s_prime_commitment.write(dr, &mut sponge)?;
            let y = sponge.squeeze(dr)?;
            let z = sponge.squeeze(dr)?;
            (y, z)
        };
        unified_output.y.set(y);
        unified_output.z.set(z);

        // Absorb nested_error_m_commitment and verify saved sponge state
        // (mu, nu, mu_prime, nu_prime derivation moved to hashes_2)
        {
            let nested_error_m_commitment = unified_output
                .nested_error_m_commitment
                .get(dr, unified_instance)?;
            nested_error_m_commitment.write(dr, &mut sponge)?;

            // Save state and verify it matches the witnessed state from error_n
            sponge
                .save_state(dr)
                .expect("save_state should succeed after absorbing")
                .enforce_equal(dr, &error_n.sponge_state)?;
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
