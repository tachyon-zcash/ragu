//! Query stage for merge operations.

use arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging::Stage};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    vec::{FixedVec, Len},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

/// The number of query elements in the query stage.
pub struct Queries;

impl Len for Queries {
    fn len() -> usize {
        5
    }
}

/// Witness data for the query stage.
pub struct Witness<C: CurveAffine> {
    /// The x challenge derived from hashing mu and the nested A/B commitment.
    pub x: C::Base,
    /// The nested s commitment (mesh polynomial at (x, y)).
    pub nested_s_commitment: C,
    /// Query elements.
    pub queries: FixedVec<C::Base, Queries>,
}

/// Output gadget for the query stage.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine> {
    /// The x challenge element.
    #[ragu(gadget)]
    pub x: Element<'dr, D>,
    /// The nested s commitment point.
    #[ragu(gadget)]
    pub nested_s_commitment: Point<'dr, D, C>,
    /// Query elements.
    #[ragu(gadget)]
    pub queries: FixedVec<Element<'dr, D>, Queries>,
}

/// The query stage of the merge witness.
pub struct Query<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> Stage<C::Base, R> for Query<C, R> {
    type Parent = super::preamble::Preamble<C::Base, R>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        1 + 2 + Queries::len() // 1 for x + 2 for the point + query terms
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let x = Element::alloc(dr, witness.view().map(|w| w.x))?;
        let nested_s_commitment = Point::alloc(dr, witness.view().map(|w| w.nested_s_commitment))?;
        let queries = {
            let mut elems = Vec::with_capacity(Queries::len());
            for i in 0..Queries::len() {
                elems.push(Element::alloc(dr, witness.view().map(|w| w.queries[i]))?);
            }
            FixedVec::try_from(elems)?
        };
        Ok(Output {
            x,
            nested_s_commitment,
            queries,
        })
    }
}
