//! Error stage (layer 1) for merge operations.
//!
//! This stage handles N separate M-sized revdot claim reductions.

use arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
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

use core::marker::PhantomData;

pub use crate::internal_circuits::InternalCircuitIndex::ErrorMStage as STAGING_ID;

use crate::components::fold_revdot::{ErrorTermsLen, Parameters};

/// Witness data for the error_m stage (layer 1).
///
/// Contains N sets of M-sized error terms for the first layer of reduction.
pub struct Witness<C: Cycle, P: Parameters> {
    /// Error term elements for layer 1.
    /// Outer: N claims, Inner: M²-M error terms per claim.
    pub error_terms: FixedVec<FixedVec<C::CircuitField, ErrorTermsLen<P::M>>, P::N>,
}

/// Output gadget for the error_m stage.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>, P: Parameters> {
    /// Error term elements for layer 1.
    /// Outer: N claims, Inner: M²-M error terms per claim.
    #[ragu(gadget)]
    pub error_terms: FixedVec<FixedVec<Element<'dr, D>, ErrorTermsLen<P::M>>, P::N>,
}

/// The error_m stage (layer 1) of the merge witness.
#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, P: Parameters> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE, P>
{
    type Parent = super::preamble::Stage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source Witness<C, P>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, P>];

    fn values() -> usize {
        // N * (M² - M) error terms
        let error_terms_per_claim = ErrorTermsLen::<P::M>::len();
        P::N::len() * error_terms_per_claim
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        // Allocate nested error terms
        let error_terms = FixedVec::try_from_fn(|i| {
            FixedVec::try_from_fn(|j| {
                Element::alloc(dr, witness.view().map(|w| w.error_terms[i][j]))
            })
        })?;

        Ok(Output { error_terms })
    }
}
