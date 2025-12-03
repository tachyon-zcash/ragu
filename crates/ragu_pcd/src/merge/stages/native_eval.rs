//! Eval stage for merge operations.

use arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging::Stage};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    vec::{FixedVec, Len},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

/// The number of eval elements in the eval stage.
pub struct Evals;

impl Len for Evals {
    fn len() -> usize {
        5
    }
}

/// Witness data for the eval stage.
pub struct Witness<F> {
    /// The u challenge derived from hashing alpha and the nested F commitment.
    pub u: F,
    /// Eval elements.
    pub evals: FixedVec<F, Evals>,
}

/// Output gadget for the eval stage.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>> {
    /// The witnessed u challenge element.
    #[ragu(gadget)]
    pub u: Element<'dr, D>,
    /// Eval elements.
    #[ragu(gadget)]
    pub evals: FixedVec<Element<'dr, D>, Evals>,
}

/// The eval stage of the merge witness.
pub struct Eval<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> Stage<C::Base, R> for Eval<C, R> {
    type Parent = super::native_query::Query<C, R>;
    type Witness<'source> = &'source Witness<C::Base>;
    type OutputKind = Kind![C::Base; Output<'_, _>];

    fn values() -> usize {
        1 + Evals::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let u = Element::alloc(dr, witness.view().map(|w| w.u))?;
        let evals = {
            let mut elems = Vec::with_capacity(Evals::len());
            for i in 0..Evals::len() {
                elems.push(Element::alloc(dr, witness.view().map(|w| w.evals[i]))?);
            }
            FixedVec::try_from(elems)?
        };
        Ok(Output { u, evals })
    }
}
