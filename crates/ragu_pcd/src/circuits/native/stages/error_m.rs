//! Error stage (layer 1) for fuse operations.
//!
//! This stage handles N separate M-sized revdot claim reductions.

use arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Consistent, Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    vec::{FixedVec, Len},
};

use core::marker::PhantomData;

pub(crate) use crate::circuits::native::InternalCircuitIndex::ErrorMStage as STAGING_ID;

use crate::components::fold_revdot::{self, ErrorTermsLen};

/// Witness data for the error_m stage (layer 1).
///
/// Contains N sets of M-sized error terms for the first layer of reduction.
pub struct Witness<C: Cycle, FP: fold_revdot::Parameters> {
    /// Error term elements for layer 1.
    /// Outer: N claims, Inner: M²-M error terms per claim.
    pub error_terms: FixedVec<FixedVec<C::CircuitField, ErrorTermsLen<FP::M>>, FP::N>,
}

/// Output gadget for the error_m stage.
#[derive(Gadget, Consistent)]
pub struct Output<'dr, D: Driver<'dr>, FP: fold_revdot::Parameters> {
    /// Error term elements for layer 1.
    /// Outer: N claims, Inner: M²-M error terms per claim.
    #[ragu(gadget)]
    pub error_terms: FixedVec<FixedVec<Element<'dr, D>, ErrorTermsLen<FP::M>>, FP::N>,
}

/// The error_m stage (layer 1) of the fuse witness.
#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    staging::Stage<C::CircuitField, R> for Stage<C, R, HEADER_SIZE, FP>
{
    type Parent = super::error_n::Stage<C, R, HEADER_SIZE, FP>;
    type Witness<'source> = &'source Witness<C, FP>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, FP>];

    fn values() -> usize {
        // N * (M² - M) error terms
        let error_terms_per_claim = ErrorTermsLen::<FP::M>::len();
        FP::N::len() * error_terms_per_claim
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::native::stages::tests::{
        HEADER_SIZE, NativeParameters, R, assert_stage_values,
    };
    use ragu_pasta::Pasta;

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }, NativeParameters>::default());
    }
}
