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
use crate::stages::{native_error, native_preamble};

pub const CIRCUIT_ID: usize = super::C_CIRCUIT_ID;

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
    pub error_witness: &'a native_error::Witness<C::NestedCurve>,
}

impl<C: Cycle, R: Rank> StagedCircuit<C::CircuitField, R> for Circuit<'_, C, R> {
    type Final = native_error::Error<C::NestedCurve, R>;

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
        let (error, builder) = builder.add_stage::<native_error::Error<C::NestedCurve, R>>()?;
        let dr = builder.finish();

        let error = error.enforced(dr, witness.view().map(|w| w.error_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Computation of w
        let w = {
            let nested_preamble_commitment = unified_output
                .nested_preamble_commitment
                .get(dr, unified_instance);

            let mut sponge = Sponge::new(dr, self.circuit_poseidon);
            nested_preamble_commitment.write(dr, &mut sponge)?;
            sponge.squeeze(dr)?
        };

        // Computation of (y, z)
        let (y, z) = {
            let nested_s_prime_commitment = unified_output
                .nested_s_prime_commitment
                .get(dr, unified_instance);

            // Hash w and nested_s_prime_commitment to compute y, z.
            let mut sponge = Sponge::new(dr, self.circuit_poseidon);
            sponge.absorb(dr, &w)?;
            nested_s_prime_commitment.write(dr, &mut sponge)?;
            let y = sponge.squeeze(dr)?;
            let z = sponge.squeeze(dr)?;

            // Error stage's z must equal z.
            z.enforce_equal(dr, &error.z)?;

            (y, z)
        };

        unified_output.w.set(w);
        unified_output.y.set(y);
        unified_output.z.set(z);

        // Error stage's nested_s_doubleprime_commitment must equal the one in unified output
        unified_output
            .nested_s_doubleprime_commitment
            .set(error.nested_s_doubleprime_commitment);

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
