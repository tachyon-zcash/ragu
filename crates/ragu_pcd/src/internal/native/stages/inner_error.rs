//! Inner error stage (layer 1) for fuse operations.
//!
//! This stage handles N separate M-sized revdot claim reductions.

use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    consistent::Consistent,
    vec::{FixedVec, Len},
};

use crate::{
    framework_hooks::HookConfig,
    internal::fold_revdot::{self, NumErrorTerms},
};

/// Witness data for the inner error stage (layer 1).
///
/// Contains N sets of M-sized error terms for the first layer of reduction.
pub struct Witness<C: Cycle, FP: fold_revdot::Parameters> {
    /// Error term elements for layer 1.
    /// Outer: N claims, Inner: M²-M error terms per claim.
    pub error_terms:
        FixedVec<FixedVec<C::CircuitField, NumErrorTerms<FP::GroupSize>>, FP::NumGroups>,
}

/// Prover-internal output gadget for the inner error stage.
///
/// This is stage communication data, not part of the circuit's public instance.
#[derive(Gadget, Consistent)]
pub struct Output<'dr, D: Driver<'dr>, FP: fold_revdot::Parameters> {
    /// Error term elements for layer 1.
    /// Outer: N claims, Inner: M²-M error terms per claim.
    #[ragu(gadget)]
    pub error_terms:
        FixedVec<FixedVec<Element<'dr, D>, NumErrorTerms<FP::GroupSize>>, FP::NumGroups>,
}

/// The inner error stage (layer 1) of the fuse witness.
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig, FP: fold_revdot::Parameters>
{
    _marker: PhantomData<(C, R, J, FP)>,
}

impl<C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig, FP: fold_revdot::Parameters> Default
    for Stage<C, R, HEADER_SIZE, J, FP>
{
    fn default() -> Self {
        Stage {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig, FP: fold_revdot::Parameters>
    staging::Stage<C::CircuitField, R> for Stage<C, R, HEADER_SIZE, J, FP>
{
    type Parent = super::outer_error::Stage<C, R, HEADER_SIZE, J, FP>;
    type Witness<'source> = &'source Witness<C, FP>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, FP>];

    fn values() -> usize {
        // N * (M² - M) error terms
        let error_terms_per_claim = NumErrorTerms::<FP::GroupSize>::len();
        FP::NumGroups::len() * error_terms_per_claim
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let allocator = &mut ();
        let error_terms = FixedVec::try_from_fn(|i| {
            FixedVec::try_from_fn(|j| {
                Element::alloc(dr, allocator, witness.as_ref().map(|w| w.error_terms[i][j]))
            })
        })?;

        Ok(Output { error_terms })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Pasta;

    use super::*;
    use crate::{
        AppHooks,
        internal::{
            native::RevdotParameters,
            tests::{HEADER_SIZE, R, assert_stage_values},
        },
    };

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<
            Pasta,
            R,
            { HEADER_SIZE },
            AppHooks<1, 1>,
            RevdotParameters,
        >::default());
    }
}
