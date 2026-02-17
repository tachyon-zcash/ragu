//! Circuit for extracting and verifying challenge endoscalars.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, Endoscalar, io::Write};

use core::marker::PhantomData;

use super::stages::{error_n as native_error_n, preamble as native_preamble};
use super::unified::{self, OutputBuilder};
use crate::components::{fold_revdot, suffix::WithSuffix};

pub(crate) use super::InternalCircuitIndex::EndoscaleChallengesCircuit as CIRCUIT_ID;

/// Smuggled challenge coefficients for the nested side.
///
/// Each challenge is paired with a zero element to ensure challenges land
/// in a-coefficient positions when the witness polynomial is built. The
/// serialization order is: `[y_coeff, zero, z_coeff, zero, ...]`
#[derive(Gadget, Write)]
pub struct SmuggledChallenges<'dr, D: Driver<'dr>> {
    /// Field-scaled coefficient derived from the y challenge.
    #[ragu(gadget)]
    y_coeff: Element<'dr, D>,
    /// Zero element ensuring y_coeff lands in an a-position.
    #[ragu(gadget)]
    y_zero: Element<'dr, D>,
    /// Field-scaled coefficient derived from the z challenge.
    #[ragu(gadget)]
    z_coeff: Element<'dr, D>,
    /// Zero element ensuring z_coeff lands in an a-position.
    #[ragu(gadget)]
    z_zero: Element<'dr, D>,
    // TODO: Add more challenges (mu, nu, mu_prime, nu_prime, etc.) as needed.
}

/// Output of the endoscale_challenges circuit.
///
/// Combines the unified instance with smuggled challenge coefficients.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    /// The unified instance shared across internal circuits.
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
    /// Challenge coefficients smuggled into the witness polynomial.
    #[ragu(gadget)]
    pub smuggled: SmuggledChallenges<'dr, D>,
}

/// Circuit that extracts and verifies challenge endoscalars.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<C, R, HEADER_SIZE, FP>
{
    pub fn new() -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
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
    MultiStageCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
{
    type Last = native_error_n::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, FP>;
    type Output = Kind![C::CircuitField; WithSuffix<'_, _, Output<'_, _, C>>];
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
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
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

        // Retrieve y and z challenges from the unified instance.
        let y = unified_output.y.get(dr, unified_instance)?;
        let z = unified_output.z.get(dr, unified_instance)?;

        // Extract endoscalars from challenges and compute their field-scaled values.
        let y_endo = Endoscalar::extract(dr, y)?;
        let z_endo = Endoscalar::extract(dr, z)?;
        let y_coeff = y_endo.field_scale(dr)?;
        let z_coeff = z_endo.field_scale(dr)?;

        // Create zero elements for b-positions.
        // This ensures coefficients land in a-positions when rx is built.
        let zero = Element::zero(dr);

        // Build the smuggled challenges output.
        let smuggled = SmuggledChallenges {
            y_coeff,
            y_zero: zero.clone(),
            z_coeff,
            z_zero: zero.clone(),
        };

        let output = Output {
            unified: unified_output.finish_no_suffix(dr, unified_instance)?,
            smuggled,
        };

        // Wrap with zero suffix to distinguish from application circuits.
        Ok((WithSuffix::new(output, zero), D::just(|| ())))
    }
}
