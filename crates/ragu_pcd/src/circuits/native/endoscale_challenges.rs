//! Circuit for extracting and verifying challenge endoscalars.

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
use ragu_primitives::Endoscalar;

use core::marker::PhantomData;

use super::stages::{error_n as native_error_n, preamble as native_preamble};
use super::unified::{self, OutputBuilder};
use crate::components::fold_revdot;

pub(crate) use super::InternalCircuitIndex::EndoscaleChallengesCircuit as CIRCUIT_ID;

/// Circuit that extracts and verifies challenge endoscalars.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<C, R, HEADER_SIZE, FP>
{
    pub fn new() -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness for the endoscale_challenges circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    pub unified_instance: &'a unified::Instance<C>,
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    pub error_n_witness: &'a native_error_n::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    StagedCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
{
    type Final = native_error_n::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, FP>;
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
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let _preamble = preamble.unenforced(dr, witness.view().map(|w| w.preamble_witness))?;
        let _error_n = error_n.unenforced(dr, witness.view().map(|w| w.error_n_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Retrieve y and z challenges from the unified instance (more challenges added later).
        let y = unified_output.y.get(dr, unified_instance)?;
        let z = unified_output.z.get(dr, unified_instance)?;

        let y_endo = Endoscalar::extract(dr, y)?;
        let z_endo = Endoscalar::extract(dr, z)?;

        let _y_coeff = y_endo.field_scale(dr)?;
        let _z_coeff = z_endo.field_scale(dr)?;

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
