//! The online polynomial oracles a step queries while its circuit is
//! synthesized.
//!
//! A step's three headers carry [`HEADER_POLYNOMIALS`] polynomials each,
//! committed before the step's challenge $\zeta$ is squeezed: the
//! children's in their proofs, the step's own by its
//! [`polynomials`](super::Step::polynomials) phase. In the step's
//! [`witness`](super::Step::witness) phase, [`Oracles`] stands for those six
//! commitments. The step may [`query`](Oracles::query) each slot once, at
//! any wire, and receives a wire holding the polynomial's value there; the
//! opening $f_i(x_i) = y_i$ is not checked in the circuit but by Ragu's
//! polynomial commitment scheme, which folds it into the step's own batch
//! and whose verified openings the parent holds the step's instance to. A
//! slot the step does not query is opened at $\zeta$ to its value there.
//!
//! The slots are the headers' polynomials in order `[L0, L1, R0, R1, O0,
//! O1]`. Every slot holds whatever polynomial the step that produced the
//! header committed, the constant one where that step used fewer; what a
//! slot means is the application's convention for the header, which the
//! producing steps' circuits constrain, as they do the header's fields.

use core::marker::PhantomData;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, vec::FixedVec};
use udon::field::Field;

use crate::internal::online::{self, Queries, QueriesOutput, QueryOutput};
pub use crate::internal::online::{HEADER_POLYNOMIALS, Slot};

/// Evaluates a step's online polynomials: `evaluate(slot, x)` is the value
/// of the polynomial in slot `slot` at `x`.
pub(crate) trait Evaluate<F>: Sync {
    fn evaluate(&self, slot: usize, x: F) -> F;
}

/// What the fuse hands the adapter for a step's online slots: $\zeta$ and
/// the slots' polynomials, as prover data.
pub(crate) struct OnlineWitness<F, R: Rank> {
    pub(crate) zeta: F,
    pub(crate) polys: [sparse::Polynomial<F, R>; online::NUM_ONLINE_QUERIES],
}

impl<F: Field, R: Rank> Evaluate<F> for OnlineWitness<F, R> {
    fn evaluate(&self, slot: usize, x: F) -> F {
        self.polys[slot].eval(x)
    }
}

/// The online polynomial oracles of a step: $\zeta$ and the six slots, each
/// queryable once.
pub struct Oracles<'a, 'dr, D: Driver<'dr>> {
    zeta: Element<'dr, D>,
    evaluator: DriverValue<D, &'a dyn Evaluate<D::F>>,
    queries: [Option<QueryOutput<'dr, D>>; online::NUM_ONLINE_QUERIES],
    _marker: PhantomData<&'dr ()>,
}

impl<'a, 'dr, D: Driver<'dr>> Oracles<'a, 'dr, D> {
    /// Allocates $\zeta$ and prepares the slots from the fuse's witness.
    pub(crate) fn alloc<R: Rank>(
        dr: &mut D,
        witness: DriverValue<D, &'a OnlineWitness<D::F, R>>,
    ) -> Result<Self> {
        let zeta = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.zeta))?;
        Ok(Oracles {
            zeta,
            evaluator: witness.map(|w| w as &dyn Evaluate<D::F>),
            queries: core::array::from_fn(|_| None),
            _marker: PhantomData,
        })
    }

    /// The step's challenge $\zeta$: squeezed after every slot's polynomial
    /// was committed, so an opening at $\zeta$ is a random evaluation of a
    /// polynomial fixed beforehand.
    pub fn zeta(&self) -> &Element<'dr, D> {
        &self.zeta
    }

    /// Opens `slot` at `x`, returning a wire holding the polynomial's value
    /// there. The opening is proved by Ragu, not by this circuit: the
    /// returned wire is a witness the step may use in its constraints, and
    /// the pair $(x, y)$ enters the step's instance.
    ///
    /// # Errors
    ///
    /// Each slot may be queried once; a second query of the same slot is
    /// refused. Witness generation fails if the slot's polynomial cannot be
    /// evaluated, which no honest prover's can.
    pub fn query(
        &mut self,
        dr: &mut D,
        slot: Slot,
        x: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let i = slot.offset();
        if self.queries[i].is_some() {
            return Err(Error::Initialization(
                "an online slot may be queried once per step".into(),
            ));
        }
        let x_value = x.value();
        let y = Element::alloc(
            dr,
            &mut (),
            self.evaluator
                .as_ref()
                .map(|e| e.evaluate(i, *x_value.take())),
        )?;
        self.queries[i] = Some(QueryOutput {
            x: x.clone(),
            y: y.clone(),
        });
        Ok(y)
    }

    /// Opens `slot` at $\zeta$: [`query`](Self::query) at
    /// [`zeta`](Self::zeta).
    pub fn query_at_zeta(&mut self, dr: &mut D, slot: Slot) -> Result<Element<'dr, D>> {
        let zeta = self.zeta.clone();
        self.query(dr, slot, &zeta)
    }

    /// Opens every slot the step did not query at $\zeta$, and returns
    /// $\zeta$ with the six openings, in slot order, for the instance.
    pub(crate) fn finish(mut self, dr: &mut D) -> Result<(Element<'dr, D>, QueriesOutput<'dr, D>)> {
        for slot in Slot::all() {
            if self.queries[slot.offset()].is_none() {
                self.query_at_zeta(dr, slot)?;
            }
        }
        let queries = FixedVec::try_from(
            self.queries
                .into_iter()
                .map(|query| query.expect("every slot was queried"))
                .collect::<alloc::vec::Vec<_>>(),
        )?;
        Ok((self.zeta, queries))
    }
}

/// The values of a step's openings, read off the wires.
pub(crate) fn values<'dr, D: Driver<'dr>>(
    queries: &QueriesOutput<'dr, D>,
) -> DriverValue<D, Queries<D::F>> {
    D::just(|| {
        core::array::from_fn(|i| online::Query {
            x: *queries[i].x.value().take(),
            y: *queries[i].y.value().take(),
        })
    })
}
