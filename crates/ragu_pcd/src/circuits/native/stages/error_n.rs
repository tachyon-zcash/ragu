//! Error stage (layer 2) for fuse operations.
//!
//! This stage handles the final N-sized revdot claim reduction.

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
    poseidon::{PoseidonStateLen, SpongeState},
    vec::{CollectFixed, FixedVec, Len},
};

use core::marker::PhantomData;

pub(crate) use crate::circuits::native::InternalCircuitIndex::ErrorNStage as STAGING_ID;

use crate::components::fold_revdot::{self, ErrorTermsLen};

/// $k(Y)$ evaluation values for a single child proof.
pub struct ChildKyValues<F> {
    /// k(y) for the application circuit.
    pub application: F,
    /// k(y) for the unified circuit.
    pub unified: F,
    /// k(y) for the header-unified binding.
    pub unified_bridge: F,
}

/// $k(Y)$ evaluation values computed during fuse operation.
pub struct KyValues<F> {
    /// k(y) values for the left child proof.
    pub left: ChildKyValues<F>,
    /// k(y) values for the right child proof.
    pub right: ChildKyValues<F>,
}

/// Witness data for the error_n stage (layer 2).
///
/// Contains $N^2 - N$ error terms for the second layer of reduction, plus the
/// $N$ collapsed values from layer 1 folding, and the saved sponge state for
/// bridging the transcript between hashes_1 and hashes_2.
pub struct Witness<C: Cycle, FP: fold_revdot::Parameters> {
    /// Error term elements for layer 2.
    pub error_terms: FixedVec<C::CircuitField, ErrorTermsLen<FP::N>>,

    /// Collapsed values from layer 1 folding ($N$ values). These are the
    /// outputs of $N$ individual size-$M$ revdot reductions.
    pub collapsed: FixedVec<C::CircuitField, FP::N>,

    /// $k(y)$ evaluation values.
    pub ky: KyValues<C::CircuitField>,

    /// Sponge state elements saved after absorbing nested_error_m_commitment.
    /// Used to bridge the Fiat-Shamir transcript between hashes_1 and hashes_2.
    pub sponge_state_elements:
        FixedVec<C::CircuitField, PoseidonStateLen<C::CircuitField, C::CircuitPoseidon>>,
}

/// k(y) output gadgets for a single child proof.
#[derive(Gadget, Consistent)]
pub struct ChildKyOutputs<'dr, D: Driver<'dr>> {
    /// k(y) for the application circuit.
    #[ragu(gadget)]
    pub application: Element<'dr, D>,
    /// k(y) for the unified circuit.
    #[ragu(gadget)]
    pub unified: Element<'dr, D>,
    /// k(y) for the header-unified binding.
    #[ragu(gadget)]
    pub unified_bridge: Element<'dr, D>,
}

/// Output gadget for the error_n stage.
#[derive(Gadget, Consistent)]
pub struct Output<
    'dr,
    D: Driver<'dr>,
    FP: fold_revdot::Parameters,
    Poseidon: arithmetic::PoseidonPermutation<D::F>,
> {
    /// Error term elements for layer 2.
    #[ragu(gadget)]
    pub error_terms: FixedVec<Element<'dr, D>, ErrorTermsLen<FP::N>>,
    /// Collapsed values from layer 1 folding (N values).
    #[ragu(gadget)]
    pub collapsed: FixedVec<Element<'dr, D>, FP::N>,
    /// k(y) values for left child proof.
    #[ragu(gadget)]
    pub left: ChildKyOutputs<'dr, D>,
    /// k(y) values for right child proof.
    #[ragu(gadget)]
    pub right: ChildKyOutputs<'dr, D>,
    /// Sponge state saved after absorbing nested_error_m_commitment.
    /// Used to bridge the Fiat-Shamir transcript between hashes_1 and hashes_2.
    #[ragu(gadget)]
    pub sponge_state: SpongeState<'dr, D, Poseidon>,
}

/// The error_n stage (layer 2) of the fuse witness.
#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    staging::Stage<C::CircuitField, R> for Stage<C, R, HEADER_SIZE, FP>
{
    type Parent = super::preamble::Stage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source Witness<C, FP>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, FP, C::CircuitPoseidon>];

    fn values() -> usize {
        // N² - N error terms + N collapsed values + 6 ky values + sponge state elements
        ErrorTermsLen::<FP::N>::len()
            + FP::N::len()
            + 6
            + PoseidonStateLen::<C::CircuitField, C::CircuitPoseidon>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let error_terms = ErrorTermsLen::<FP::N>::range()
            .map(|i| Element::alloc(dr, witness.view().map(|w| w.error_terms[i])))
            .try_collect_fixed()?;
        let collapsed = FP::N::range()
            .map(|i| Element::alloc(dr, witness.view().map(|w| w.collapsed[i])))
            .try_collect_fixed()?;
        let left = ChildKyOutputs {
            application: Element::alloc(dr, witness.view().map(|w| w.ky.left.application))?,
            unified: Element::alloc(dr, witness.view().map(|w| w.ky.left.unified))?,
            unified_bridge: Element::alloc(dr, witness.view().map(|w| w.ky.left.unified_bridge))?,
        };
        let right = ChildKyOutputs {
            application: Element::alloc(dr, witness.view().map(|w| w.ky.right.application))?,
            unified: Element::alloc(dr, witness.view().map(|w| w.ky.right.unified))?,
            unified_bridge: Element::alloc(dr, witness.view().map(|w| w.ky.right.unified_bridge))?,
        };
        let sponge_state = SpongeState::from_elements(FixedVec::try_from_fn(|i| {
            Element::alloc(dr, witness.view().map(|w| w.sponge_state_elements[i]))
        })?);

        Ok(Output {
            error_terms,
            collapsed,
            left,
            right,
            sponge_state,
        })
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
