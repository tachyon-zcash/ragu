//! E staging polynomial.
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

/// Hardcoding the number of intermediary evaluations.
pub const NUM_EVALS: usize = 23;

///////////////////////////////////////////////////////////////////////////////////////
// E STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Ephemeral stage used to create nested commitments.
ephemeral_stage!(EphemeralStageE);

// Indirection stage used for an extra layer of nesting.
indirection_stage!(IndirectionStageE);

// E Stage.
#[derive(Gadget)]
pub struct EStageOutput<'dr, D: Driver<'dr>, HostCurve: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, ConstLen<3>>,
    #[ragu(gadget)]
    pub nested_commitments: FixedVec<Point<'dr, D, HostCurve>, ConstLen<2>>,
    #[ragu(gadget)]
    pub evaluations: FixedVec<Element<'dr, D>, ConstLen<NUM_EVALS>>,
}

/// E Stage: challenges (mu, nu, x), nested commitments (A and B, S), and evaluations.
pub struct EStage<HostCurve> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank> Stage<<HostCurve>::Base, R> for EStage<HostCurve> {
    type Parent = ();

    type Witness<'source> = (
        [<HostCurve>::Base; 3],
        [HostCurve; 2],
        [<HostCurve>::Base; NUM_EVALS],
    );

    type OutputKind = Kind![<HostCurve>::Base; EStageOutput<'_, _, HostCurve>];

    fn values() -> usize {
        3 + (2 * 2) + NUM_EVALS
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
        // Allocate the challenges (mu, nu, x).
        let mut challenges = Vec::with_capacity(3);
        for i in 0..3 {
            challenges.push(Element::alloc(dr, witness.view().map(|w| w.0[i]))?);
        }
        let challenges = FixedVec::new(challenges).expect("challenges length");

        // Allocate the nested commitments (A and B, S).
        let mut nested_commitments = Vec::with_capacity(2);
        for i in 0..2 {
            nested_commitments.push(Point::alloc(dr, witness.view().map(|w| w.1[i]))?);
        }
        let nested_commitments =
            FixedVec::new(nested_commitments).expect("nested commitments length");

        // Allocate the intermediate evaluations.
        let mut evaluations = Vec::with_capacity(NUM_EVALS);
        for i in 0..NUM_EVALS {
            evaluations.push(Element::alloc(dr, witness.view().map(|w| w.2[i]))?);
        }
        let evaluations = FixedVec::new(evaluations).expect("error terms length");

        Ok(EStageOutput {
            challenges,
            nested_commitments,
            evaluations,
        })
    }
}
