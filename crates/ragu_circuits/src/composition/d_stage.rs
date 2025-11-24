//! D staging polynomial.
use alloc::vec::Vec;
use arithmetic::CurveAffine;

use crate::polynomials::Rank;
use crate::staging::Stage;
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

use crate::{ephemeral_stage, indirection_stage};

///////////////////////////////////////////////////////////////////////////////////////
// D STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Ephemeral stage used to create nested commitments.
ephemeral_stage!(EphemeralStageD);

// Indirection stage used for an extra layer of nesting.
indirection_stage!(IndirectionStageD);

/// Number of cross-product error terms in the folding scheme.
/// L = 3 polynomials per fold (1 new witness + 2 incoming accumulators),
/// so NUM_CROSS_PRODUCTS = L * (L - 1) = 6 off-diagonal terms.
pub const NUM_CROSS_PRODUCTS: usize = 6;

// D Stage.
#[derive(Gadget)]
pub struct DStageOutput<'dr, D: Driver<'dr>, HostCurve: CurveAffine<Base = D::F>> {
    /// Challenges (w, y, z) for the staged circuit.
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, ConstLen<3>>,
    /// Nested commitments (D1, D2) for cross-curve witnessing.
    #[ragu(gadget)]
    pub nested_commitments: FixedVec<Point<'dr, D, HostCurve>, ConstLen<2>>,
    /// Cross-product error terms from folding.
    #[ragu(gadget)]
    pub error_terms: FixedVec<Element<'dr, D>, ConstLen<NUM_CROSS_PRODUCTS>>,
}

/// D Stage: challenges (w, y, z), nested commitments (D1, D2), and error terms.
pub struct DStage<HostCurve> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank> Stage<<HostCurve>::Base, R> for DStage<HostCurve> {
    type Parent = ();

    type Witness<'source> = (
        [<HostCurve>::Base; 3],
        [HostCurve; 2],
        [<HostCurve>::Base; NUM_CROSS_PRODUCTS],
    );

    type OutputKind = Kind![<HostCurve>::Base; DStageOutput<'_, _, HostCurve>];

    fn values() -> usize {
        3 + (2 * 2) + NUM_CROSS_PRODUCTS
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
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
        let mut error_terms = Vec::with_capacity(NUM_CROSS_PRODUCTS);
        for i in 0..NUM_CROSS_PRODUCTS {
            error_terms.push(Element::alloc(dr, witness.view().map(|w| w.2[i]))?);
        }
        let error_terms = FixedVec::new(error_terms).expect("error terms length");

        Ok(DStageOutput {
            challenges,
            nested_commitments,
            error_terms,
        })
    }
}
