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
//! [`Oracles`] also holds the step's [staged](super::Step::staged) values,
//! committed before $\zeta$ in the proof's application stage. A check at
//! $\zeta$ is sound only if every value it reads was fixed before $\zeta$:
//! an opening at $\zeta$ or at a point itself fixed before $\zeta$, an
//! input's header field, a staged value, or a wire computed from those; or
//! an in-circuit hash output, or a value from a small set. Any other wire the
//! circuit witnesses, the output header's fields included, is the prover's
//! choice given $\zeta$.
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
pub use crate::internal::online::{HEADER_POLYNOMIALS, Position, Slot};

/// Evaluates a step's online polynomials: `evaluate(slot, x)` is the value
/// of the polynomial in slot `slot` at `x`.
pub(crate) trait Evaluate<F>: Sync {
    fn evaluate(&self, slot: usize, x: F) -> F;
}

/// What the fuse hands the adapter for a step's online slots: $\zeta$, the
/// slots' polynomials and the step's staged values, as prover data.
pub(crate) struct OnlineWitness<F, R: Rank> {
    pub(crate) zeta: F,
    pub(crate) polys: [sparse::Polynomial<F, R>; online::NUM_ONLINE_QUERIES],
    pub(crate) staged: alloc::vec::Vec<F>,
    /// The coordinates of $H^{bridge}(O_1)$, fixed with $\zeta$.
    pub(crate) bridge_hash: [F; 2],
}

impl<F: Field, R: Rank> Evaluate<F> for OnlineWitness<F, R> {
    fn evaluate(&self, slot: usize, x: F) -> F {
        self.polys[slot].eval(x)
    }
}

/// The online polynomial oracles of a step: $\zeta$, the six slots, each
/// queryable once, and the staged values.
pub struct Oracles<'a, 'dr, D: Driver<'dr>> {
    zeta: Element<'dr, D>,
    bridge_hash: [Element<'dr, D>; 2],
    staged: alloc::vec::Vec<Element<'dr, D>>,
    evaluator: DriverValue<D, &'a dyn Evaluate<D::F>>,
    queries: [Option<QueryOutput<'dr, D>>; online::NUM_ONLINE_QUERIES],
    _marker: PhantomData<&'dr ()>,
}

impl<'a, 'dr, D: Driver<'dr>> Oracles<'a, 'dr, D> {
    /// Allocates $\zeta$ and prepares the slots from the fuse's witness,
    /// with the staged values the adapter allocated and bound.
    pub(crate) fn alloc<R: Rank>(
        dr: &mut D,
        witness: DriverValue<D, &'a OnlineWitness<D::F, R>>,
        staged: alloc::vec::Vec<Element<'dr, D>>,
    ) -> Result<Self> {
        let zeta = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.zeta))?;
        let bridge_hash = [
            Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.bridge_hash[0]))?,
            Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.bridge_hash[1]))?,
        ];
        Ok(Oracles {
            zeta,
            bridge_hash,
            staged,
            evaluator: witness.map(|w| w as &dyn Evaluate<D::F>),
            queries: core::array::from_fn(|_| None),
            _marker: PhantomData,
        })
    }

    /// The step's challenge $\zeta$: squeezed after every slot's polynomial
    /// and the staged values were committed, so an opening at $\zeta$ is a
    /// random evaluation of a polynomial fixed beforehand.
    ///
    /// A check at $\zeta$ must read only values fixed before it (see
    /// [`oracles`](self)): stage, rather than witness, any other value it
    /// reads.
    pub fn zeta(&self) -> &Element<'dr, D> {
        &self.zeta
    }

    /// $H^{bridge}(O_1)$, the digest of the step's own last online
    /// commitment, as its two coordinates: fixed with $\zeta$, and held by
    /// the parent to the commitment the step's transcript absorbed. A step
    /// that hashes its output polynomial's commitment into a header field,
    /// for instance into an anchor, reads it here.
    pub fn bridge_hash(&self) -> &[Element<'dr, D>; 2] {
        &self.bridge_hash
    }

    /// The step's [staged](super::Step::staged) values, in order: wires
    /// bound to the application stage, which the proof committed before
    /// $\zeta$ was drawn.
    pub fn staged(&self) -> &[Element<'dr, D>] {
        &self.staged
    }

    /// Opens `slot` at `x`, returning a wire holding the polynomial's value
    /// there. The opening is proved by Ragu, not by this circuit: the
    /// returned wire is a witness the step may use in its constraints, and
    /// the pair $(x, y)$ enters the step's instance.
    ///
    /// # Errors
    ///
    /// Each slot may be queried once; a second query of the same slot is
    /// refused. Allocating the opened value propagates the driver's error.
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
    /// $\zeta$ with the six openings, in slot order, and the bridge hash's
    /// coordinates, for the instance.
    #[allow(clippy::type_complexity)]
    pub(crate) fn finish(
        mut self,
        dr: &mut D,
    ) -> Result<(Element<'dr, D>, QueriesOutput<'dr, D>, [Element<'dr, D>; 2])> {
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
        Ok((self.zeta, queries, self.bridge_hash))
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
