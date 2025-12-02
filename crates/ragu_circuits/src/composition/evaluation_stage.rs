//! Evaluation staging polynomial.

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
// EVALUATION STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

pub const NUM_FINAL_EVALS: usize = 13;
pub const NUM_V_QUERIES: usize = 19;

// Ephemeral stage used to create nested commitments.
ephemeral_stage!(EphemeralStageEvaluation);

// Indirection stage used for an extra layer of nesting.
indirection_stage!(IndirectionStageEvaluation);

// G Stage.
#[derive(Gadget)]
pub struct EvaluationStageOutput<'dr, D: Driver<'dr>, HostCurve: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, ConstLen<2>>,
    #[ragu(gadget)]
    pub nested_commitments: FixedVec<Point<'dr, D, HostCurve>, ConstLen<1>>,
    #[ragu(gadget)]
    pub evaluations: FixedVec<Element<'dr, D>, ConstLen<NUM_FINAL_EVALS>>,
}

/// G Stage: challenges (mu, nu, x), nested commitments (A and B, S), and evaluations.
pub struct EvaluationStage<HostCurve> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank> Stage<<HostCurve>::Base, R> for EvaluationStage<HostCurve> {
    type Parent = ();

    type Witness<'source> = (
        [<HostCurve>::Base; 2],
        [HostCurve; 1],
        [<HostCurve>::Base; NUM_FINAL_EVALS],
    );

    type OutputKind = Kind![<HostCurve>::Base; EvaluationStageOutput<'_, _, HostCurve>];

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

        Ok(EvaluationStageOutput {
            challenges,
            nested_commitments,
            evaluations,
        })
    }
}
