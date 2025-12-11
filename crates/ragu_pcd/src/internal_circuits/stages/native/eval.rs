//! Eval stage for merge operations.

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
    vec::{CollectFixed, FixedVec, Len},
};

use core::marker::PhantomData;

pub use crate::internal_circuits::InternalCircuitIndex::EvalStage as STAGING_ID;

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
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE>
{
    type Parent = super::query::Stage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source Witness<C::CircuitField>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _>];

    fn values() -> usize {
        // challenge u + evals
        1 + Evals::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let u = Element::alloc(dr, witness.view().map(|w| w.u))?;
        let evals = Evals::range()
            .map(|i| Element::alloc(dr, witness.view().map(|w| w.evals[i])))
            .try_collect_fixed()?;
        Ok(Output { u, evals })
    }
}
