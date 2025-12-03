//! Error stage for merge operations.

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

/// The base constant for computing the number of error terms.
const C: usize = 3;

/// The number of error term elements in the error stage.
/// Computed as C^2 - C.
pub struct ErrorTerms;

impl Len for ErrorTerms {
    fn len() -> usize {
        C * C - C
    }
}

/// Witness data for the error stage.
pub struct Witness<C: CurveAffine> {
    /// The challenge derived from hashing w and nested_s_prime_commitment.
    pub z: C::Base,
    /// The nested s'' commitment point.
    pub nested_s_doubleprime_commitment: C,
    /// Error term elements.
    pub error_terms: FixedVec<C::Base, ErrorTerms>,
}

/// Output gadget for the error stage.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine> {
    /// The witnessed z challenge element.
    #[ragu(gadget)]
    pub z: Element<'dr, D>,
    /// The nested s'' commitment point.
    #[ragu(gadget)]
    pub nested_s_doubleprime_commitment: Point<'dr, D, C>,
    /// Error term elements.
    #[ragu(gadget)]
    pub error_terms: FixedVec<Element<'dr, D>, ErrorTerms>,
}

/// The error stage of the merge witness.
pub struct Error<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> Stage<C::Base, R> for Error<C, R> {
    type Parent = super::native_preamble::Preamble<C::Base, R>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        1 + 2 + ErrorTerms::len() // 1 for z + 2 for the point + error terms
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let z = Element::alloc(dr, witness.view().map(|w| w.z))?;
        let nested_s_doubleprime_commitment = Point::alloc(
            dr,
            witness.view().map(|w| w.nested_s_doubleprime_commitment),
        )?;
        let error_terms = {
            let mut elems = Vec::with_capacity(ErrorTerms::len());
            for i in 0..ErrorTerms::len() {
                elems.push(Element::alloc(
                    dr,
                    witness.view().map(|w| w.error_terms[i]),
                )?);
            }
            FixedVec::try_from(elems)?
        };
        Ok(Output {
            z,
            nested_s_doubleprime_commitment,
            error_terms,
        })
    }
}
