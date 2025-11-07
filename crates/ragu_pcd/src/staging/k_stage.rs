//! K staging polynomial.

use crate::{ephemeral_stage, indirection_stage};
use arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging::Stage};
use ragu_core::Result;
use ragu_core::maybe::Maybe;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
};
use ragu_primitives::{
    Element, Point,
    vec::{ConstLen, FixedVec},
};

/// Maximum number of circuits we can handle (application + recursion).
pub const MAX_CIRCUITS: usize = 8;

/// Maximum ky degree.
pub const MAX_KY_DEGREE: usize = 32;

/// Total size of the ky coefficient array: MAX_CIRCUITS * MAX_KY_DEGREE.
pub const TOTAL_KY_COEFFS: usize = MAX_CIRCUITS * MAX_KY_DEGREE;

///////////////////////////////////////////////////////////////////////////////////////
// KY STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Ephemeral Stage: used to creating nested commitments.
ephemeral_stage!(EphemeralStageK);

// Indirection Stage: for resolving the "outer layer problem".
indirection_stage!(IndirectionStageK);

// K Stage.
#[derive(ragu_macros::Gadget)]
pub struct KStageOutput<'dr, D: Driver<'dr>, const TOTAL_KY_COEFFS: usize> {
    #[ragu(gadget)]
    pub ky_coefficients: FixedVec<Element<'dr, D>, ConstLen<{ TOTAL_KY_COEFFS }>>,
}

/// KY Stage: staging polynomial containing all ky coefficient data.
pub struct KStage<HostCurve, const TOTAL_KY_COEFFS: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const TOTAL_KY_COEFFS: usize> Stage<<HostCurve>::Base, R>
    for KStage<HostCurve, TOTAL_KY_COEFFS>
{
    type Parent = ();

    type Witness<'source> = [<HostCurve>::Base; TOTAL_KY_COEFFS];

    type OutputKind = Kind![<HostCurve>::Base; KStageOutput<'_, _, TOTAL_KY_COEFFS>];

    fn values() -> usize {
        TOTAL_KY_COEFFS
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
        // Allocate the ky coefficients.
        let mut ky_coefficients = Vec::with_capacity(TOTAL_KY_COEFFS);
        for i in 0..TOTAL_KY_COEFFS {
            ky_coefficients.push(Element::alloc(dr, witness.view().map(|w| w[i]))?);
        }
        let ky_coefficients = FixedVec::new(ky_coefficients).expect("ky coefficients length");

        Ok(KStageOutput { ky_coefficients })
    }
}
