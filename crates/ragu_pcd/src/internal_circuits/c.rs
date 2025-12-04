use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{GadgetExt, Sponge};

use core::marker::PhantomData;

use super::unified::{self, OutputBuilder};
use crate::stages::native::preamble;

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
}

impl<C: Cycle, R: Rank> StagedCircuit<C::CircuitField, R> for Circuit<'_, C, R> {
    type Final = preamble::Stage<C, R>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C>;
    type Output = unified::OutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<unified::Output<'dr, D, C>> {
        OutputBuilder::new().finish(dr, &instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        unified::Output<'dr, D, C>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (_, builder) = builder.add_stage::<preamble::Stage<C, R>>()?;
        let dr = builder.finish();

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Computation of w
        {
            // Grab nested_preamble_commitment from the unified instance
            let nested_preamble_commitment = unified_output
                .nested_preamble_commitment
                .get(dr, unified_instance);

            let mut sponge = Sponge::new(dr, self.circuit_poseidon);
            nested_preamble_commitment.write(dr, &mut sponge)?;
            let w = sponge.squeeze(dr)?;

            // Use our local w value to impose upon the unified instance
            unified_output.w.set(w);
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
