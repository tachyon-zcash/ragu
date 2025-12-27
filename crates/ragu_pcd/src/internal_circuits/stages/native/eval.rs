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

/// The number of queries for V computation.
///
/// Each query represents a polynomial opening that
/// contributes to the batched verification.
///
/// Query breakdown (56 total):
/// - 2: A, B polynomials at x
/// - 2: Previous P polynomials at their u challenges
/// - 2: Previous S polynomials at w
/// - 18: Current mesh_xy at circuit IDs (2 app + 16 internal)
/// - 1: Current mesh_xy at w
/// - 4: S' polynomials at previous/current y
/// - 3: S'' polynomial at x0, x1, x
/// - 4: Application rx polynomials at x and xz
/// - 10: Internal circuit rx polynomials at x
/// - 10: Internal circuit rx polynomials at xz
pub struct Evals;

impl Len for Evals {
    fn len() -> usize {
        56
    }
}

/// Witness data for the eval stage.
pub struct Witness<F> {
    /// The u challenge derived from hashing alpha and the nested F commitment.
    pub u: F,
    /// Query points at which polynomials are opened: z_i.
    pub query_points: FixedVec<F, Evals>,
    /// Polynomial evaluations at query points: f_i(z_i).
    pub opening_evals: FixedVec<F, Evals>,
    /// Polynomial evaluations at challenge point u: f_i(u).
    pub challenge_evals: FixedVec<F, Evals>,
}

/// Output gadget for the eval stage.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>> {
    /// The witnessed u challenge element.
    #[ragu(gadget)]
    pub u: Element<'dr, D>,
    /// Query points at which polynomials are opened: z_i.
    #[ragu(gadget)]
    pub query_points: FixedVec<Element<'dr, D>, Evals>,
    /// Polynomial evaluations at query points: f_i(z_i).
    #[ragu(gadget)]
    pub opening_evals: FixedVec<Element<'dr, D>, Evals>,
    /// Polynomial evaluations at challenge point u: f_i(u).
    #[ragu(gadget)]
    pub challenge_evals: FixedVec<Element<'dr, D>, Evals>,
}

/// The eval stage of the merge witness.
#[derive(Default)]
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
        // u + query_points + opening_evals + challenge_evals
        1 + 3 * Evals::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let u = Element::alloc(dr, witness.view().map(|w| w.u))?;

        let query_points = Evals::range()
            .map(|i| Element::alloc(dr, witness.view().map(|w| w.query_points[i])))
            .try_collect_fixed()?;

        let opening_evals = Evals::range()
            .map(|i| Element::alloc(dr, witness.view().map(|w| w.opening_evals[i])))
            .try_collect_fixed()?;

        let challenge_evals = Evals::range()
            .map(|i| Element::alloc(dr, witness.view().map(|w| w.challenge_evals[i])))
            .try_collect_fixed()?;

        Ok(Output {
            u,
            query_points,
            opening_evals,
            challenge_evals,
        })
    }
}
