//! Error staging polynomial.

use alloc::vec::Vec;
use arithmetic::CurveAffine;

use crate::polynomials::{CrossProductsLen, Rank};
use crate::staging::Stage;
use ragu_core::Result;
use ragu_core::maybe::Maybe;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
};
use ragu_primitives::{
    Element, Point,
    vec::{ConstLen, FixedVec, Len},
};

use crate::{ephemeral_stage, indirection_stage};

///////////////////////////////////////////////////////////////////////////////////////
// ERROR STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Ephemeral stage used to create nested commitments.
ephemeral_stage!(EphemeralStageError);

// Indirection stage used for an extra layer of nesting.
indirection_stage!(IndirectionStageError);

// D Stage.
#[derive(Gadget)]
pub struct ErrorStageOutput<
    'dr,
    D: Driver<'dr>,
    HostCurve: CurveAffine<Base = D::F>,
    const NUM_CIRCUITS: usize,
> {
    /// Challenges (w, y, z) for the staged circuit.
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, ConstLen<3>>,
    /// Nested commitments (E1, E2) for cross-curve witnessing.
    #[ragu(gadget)]
    pub nested_commitments: FixedVec<Point<'dr, D, HostCurve>, ConstLen<2>>,
    /// Cross-product error terms from folding.
    #[ragu(gadget)]
    pub error_terms: FixedVec<Element<'dr, D>, CrossProductsLen<NUM_CIRCUITS>>,
}

/// Error Stage: challenges (w, y, z), nested commitments (E1, E2), and error terms.
/// NUM_CIRCUITS is the number of circuits being folded (1 app + 2 accumulators = 3).
pub struct ErrorStage<HostCurve, const NUM_CIRCUITS: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const NUM_CIRCUITS: usize> Stage<<HostCurve>::Base, R>
    for ErrorStage<HostCurve, NUM_CIRCUITS>
{
    type Parent = ();

    type Witness<'source> = (
        [<HostCurve>::Base; 3],
        [HostCurve; 2],
        Vec<<HostCurve>::Base>,
    );

    type OutputKind = Kind![<HostCurve>::Base; ErrorStageOutput<'_, _, HostCurve, NUM_CIRCUITS>];

    fn values() -> usize {
        3 + (2 * 2) + CrossProductsLen::<NUM_CIRCUITS>::len()
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
        let num_cross_products = CrossProductsLen::<NUM_CIRCUITS>::len();

        // Allocate the challenges.
        let mut challenges = Vec::with_capacity(3);
        for i in 0..3 {
            challenges.push(Element::alloc(dr, witness.view().map(|w| w.0[i]))?);
        }
        let challenges = FixedVec::new(challenges).expect("challenges length");

        // Allocate the nested commitments.
        let mut nested_commitments = Vec::with_capacity(2);
        for i in 0..2 {
            nested_commitments.push(Point::alloc(dr, witness.view().map(|w| w.1[i]))?);
        }
        let nested_commitments =
            FixedVec::new(nested_commitments).expect("nested commitments length");

        // Allocate the error terms.
        let mut error_terms = Vec::with_capacity(num_cross_products);
        for i in 0..num_cross_products {
            error_terms.push(Element::alloc(dr, witness.view().map(|w| w.2[i]))?);
        }
        let error_terms = FixedVec::new(error_terms).expect("error terms length");

        Ok(ErrorStageOutput {
            challenges,
            nested_commitments,
            error_terms,
        })
    }
}
