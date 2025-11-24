//! G staging polynomial.
use alloc::vec::Vec;
use arithmetic::CurveAffine;

use crate::polynomials::Rank;
use crate::staging::Stage;
use crate::{ephemeral_stage, indirection_stage};
use ragu_core::Result;
use ragu_core::maybe::Maybe;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
};
use ragu_primitives::{
    Element, Point,
    vec::{ConstLen, FixedVec},
};

///////////////////////////////////////////////////////////////////////////////////////
// G STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

pub const NUM_FINAL_EVALS: usize = 16;
pub const NUM_V_QUERIES: usize = 28;

// Ephemeral stage used to create nested commitments.
ephemeral_stage!(EphemeralStageG);

// Indirection stage used for an extra layer of nesting.
indirection_stage!(IndirectionStageG);

// G Stage.
#[derive(Gadget)]
pub struct GStageOutput<'dr, D: Driver<'dr>, HostCurve: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, ConstLen<2>>,
    #[ragu(gadget)]
    pub nested_commitments: FixedVec<Point<'dr, D, HostCurve>, ConstLen<1>>,
    #[ragu(gadget)]
    pub evaluations: FixedVec<Element<'dr, D>, ConstLen<NUM_FINAL_EVALS>>,
}

/// G Stage: challenges (mu, nu, x), nested commitments (A and B, S), and evaluations.
pub struct GStage<HostCurve> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank> Stage<<HostCurve>::Base, R> for GStage<HostCurve> {
    type Parent = ();

    type Witness<'source> = (
        [<HostCurve>::Base; 2],
        [HostCurve; 1],
        [<HostCurve>::Base; NUM_FINAL_EVALS],
    );

    type OutputKind = Kind![<HostCurve>::Base; GStageOutput<'_, _, HostCurve>];

    fn values() -> usize {
        2 + 2 + NUM_FINAL_EVALS
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
        // Allocate the challenges (alpha, u, beta).
        let mut challenges = Vec::with_capacity(3);
        for i in 0..2 {
            challenges.push(Element::alloc(dr, witness.view().map(|w| w.0[i]))?);
        }
        let challenges = FixedVec::new(challenges).expect("challenges length");

        // Allocate the nested commitments (e3 nested commitment).
        let mut nested_commitments = Vec::with_capacity(2);
        for i in 0..1 {
            nested_commitments.push(Point::alloc(dr, witness.view().map(|w| w.1[i]))?);
        }
        let nested_commitments =
            FixedVec::new(nested_commitments).expect("nested commitments length");

        // Allocate the final (evals') evaluations.
        let mut evaluations = Vec::with_capacity(NUM_FINAL_EVALS);
        for i in 0..NUM_FINAL_EVALS {
            evaluations.push(Element::alloc(dr, witness.view().map(|w| w.2[i]))?);
        }
        let evaluations = FixedVec::new(evaluations).expect("error terms length");

        Ok(GStageOutput {
            challenges,
            nested_commitments,
            evaluations,
        })
    }
}

///////////////////////////////////////////////////////////////////////////////////////
// KY STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// K Stage.
#[derive(Gadget)]
pub struct KYStageOutput<'dr, D: Driver<'dr>, const HEADER_SIZE: usize> {
    #[ragu(gadget)]
    pub ky_coefficients: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>,
}

/// KY Stage: staging polynomial containing all ky coefficient data.
/// HEADER_SIZE is the number of field elements in the serialized header.
pub struct KYStage<HostCurve, const HEADER_SIZE: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const HEADER_SIZE: usize> Stage<<HostCurve>::Base, R>
    for KYStage<HostCurve, HEADER_SIZE>
{
    type Parent = ();

    type Witness<'source> = [<HostCurve>::Base; HEADER_SIZE];

    type OutputKind = Kind![<HostCurve>::Base; KYStageOutput<'_, _, HEADER_SIZE>];

    fn values() -> usize {
        HEADER_SIZE
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
        let mut ky_coefficients = Vec::with_capacity(HEADER_SIZE);
        for i in 0..HEADER_SIZE {
            ky_coefficients.push(Element::alloc(dr, witness.view().map(|w| w[i]))?);
        }
        let ky_coefficients = FixedVec::new(ky_coefficients).expect("ky coefficients length");

        Ok(KYStageOutput { ky_coefficients })
    }
}
