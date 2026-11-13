//! The online polynomial oracles a step queries while its circuit is
//! synthesized.
//!
//! A step opens [`NUM_ONLINE_POLYNOMIALS`] polynomials from each child's proof
//! and from its own output proof, associated with the three headers. Their
//! commitments are stored in [`Proof`](crate::Proof) and fixed before the
//! step's challenge $\zeta$ is squeezed: the children's in their proofs,
//! the step's own by its [`prepare`](super::Step::prepare) phase. In the
//! step's [`witness`](super::Step::witness) phase, [`Oracles`] stands for
//! those six commitments. The step may open each of its headers'
//! polynomials once, by kind, through [`left`](Oracles::left),
//! [`right`](Oracles::right) and [`output`](Oracles::output), at any wire,
//! and receives a wire holding the polynomial's value there; the opening
//! $f_i(x_i) = y_i$ is not checked in the circuit but by Ragu's polynomial
//! commitment scheme, which folds it into the step's own batch and whose
//! verified openings the parent holds the step's instance to. An input slot
//! the step does not query is opened at $\zeta$ to its value there; an
//! output slot it does not query is opened at $\zeta$ and held to one, as
//! padding (see below).
//!
//! [`Oracles`] also holds the step's [staged](super::Step::prepare) values,
//! committed before $\zeta$ in the proof's application stage. A check at
//! $\zeta$ is sound when it evaluates a residual polynomial whose
//! coefficients were fixed before $\zeta$, whose degree is bounded, and
//! which is nonzero whenever the intended identity is false. The challenge
//! and the openings at it may evaluate that residual, but values derived
//! from them are not fixed coefficients or roots: a root computed in the
//! circuit from $\zeta$ and the openings is no safer than one witnessed
//! with $\zeta$ in hand. Input header fields, staged values and constants
//! are fixed before $\zeta$; in-circuit hash outputs and values from a
//! small set each need their own argument. Any other wire the circuit
//! witnesses, the output header's fields included, is the prover's choice
//! given $\zeta$.
//!
//! The slots are the proofs' polynomials in the order
//! `[L0, L1, R0, R1, O0, O1]`, the order of the step's instance; a step
//! never sees it. Every slot holds whatever polynomial the step that
//! produced the header committed, the constant one where that step used
//! fewer; what a slot means is the application's convention for the
//! header, which the producing steps' circuits constrain, as they do the
//! header's fields.
//!
//! An output slot is constrained only through its openings. The step's
//! [`prepare`](super::Step::prepare) phase is prover data, so a slot the
//! circuit opens without constraining the value holds whatever polynomial
//! the prover committed. An output slot the step does not open is padding:
//! after the step's circuit, Ragu opens it at $\zeta$ and holds the value
//! to one, so a step pins nothing by hand. If the step prepared a
//! polynomial other than one for that slot, the opening is not one, except
//! with negligible probability: the honest prover stops with [`Error::InvalidWitness`], and the verifier rejects a proof
//! that a modified prover makes. A step that leaves an output slot to the
//! steps that consume it, as a hint, opens it once and ignores the value.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, vec::FixedVec};
use udon::field::Field;

use super::Step;
use crate::{
    Header,
    header::{Has, slot},
    internal::online::{self, NUM_ONLINE_POLYNOMIALS, Queries, QueriesOutput, QueryOutput},
};

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
    /// The bridge-hash stage's commitment coordinates. They bind `O1` but
    /// need not be its canonical digest or be fixed before $\zeta$.
    pub(crate) bridge_hash: [F; 2],
}

impl<F: Field, R: Rank> Evaluate<F> for OnlineWitness<F, R> {
    fn evaluate(&self, slot: usize, x: F) -> F {
        self.polys[slot].eval(x)
    }
}

/// The online polynomial oracles of a step: $\zeta$, the six slots, each
/// to be opened once, and the staged values.
///
/// `S` is the step, whose left, right and output headers'
/// [`OnlinePolyCommit`](Header::OnlinePolyCommit) list the kinds of
/// polynomial the accessors accept, so a kind one header carries, named
/// at another header's position, does not compile, and a slot a header
/// leaves to padding cannot be opened.
pub struct Oracles<'a, 'dr, D: Driver<'dr>, C: Cycle, S: Step<C>> {
    zeta: Element<'dr, D>,
    bridge_hash: [Element<'dr, D>; 2],
    staged: Vec<Element<'dr, D>>,
    evaluator: DriverValue<D, &'a dyn Evaluate<D::F>>,
    queries: [Option<QueryOutput<'dr, D>>; online::NUM_ONLINE_QUERIES],
    _marker: PhantomData<(&'dr (), fn() -> (C, S))>,
}

impl<'a, 'dr, D: Driver<'dr>, C: Cycle, S: Step<C>> Oracles<'a, 'dr, D, C, S> {
    /// Allocates $\zeta$ and prepares the slots from the fuse's witness,
    /// with the staged values the adapter allocated and bound.
    pub(crate) fn alloc<R: Rank>(
        dr: &mut D,
        witness: DriverValue<D, &'a OnlineWitness<D::F, R>>,
        staged: Vec<Element<'dr, D>>,
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

    /// The bridge-hash stage's commitment, as its two coordinates. The
    /// stage holds the step's own last online commitment, and the parent
    /// binds this value to the stage it folds. A step that hashes its
    /// output polynomial's commitment into a header field, for instance
    /// into an anchor, reads it here.
    ///
    /// The digest covers the last slot of the output header only, whatever
    /// kind that slot holds. A header whose steps read it keeps the hashed
    /// kind last in its [`OnlinePolyCommit`](Header::OnlinePolyCommit), as
    /// `(Padding, TachygramSet)` does.
    ///
    /// This digest binds `O1` but is neither unique to it nor fixed before
    /// $\zeta$. [`Application::bridge_hash`](crate::Application::bridge_hash)
    /// recomputes the honest prover's unblinded encoding. Applications that
    /// use it in anchors must recompute advancement natively and compare
    /// against canonical-chain anchors.
    pub fn bridge_hash(&self) -> &[Element<'dr, D>; 2] {
        &self.bridge_hash
    }

    /// The step's [staged](super::Step::prepare) values, in order: wires
    /// bound to the application stage, which the proof committed before
    /// $\zeta$ was drawn.
    pub fn staged(&self) -> &[Element<'dr, D>] {
        &self.staged
    }

    /// Returns the oracle for the left input proof's polynomial of `kind`.
    pub fn left<P, I>(&mut self, kind: P) -> Oracle<'_, 'a, 'dr, D, C, S>
    where
        <S::Left as Header<C::CircuitField>>::OnlinePolyCommit: Has<P, I>,
    {
        self.left_at(slot::<
            <S::Left as Header<C::CircuitField>>::OnlinePolyCommit,
            P,
            I,
        >(kind))
    }

    /// Returns the oracle for the right input proof's polynomial of `kind`.
    pub fn right<P, I>(&mut self, kind: P) -> Oracle<'_, 'a, 'dr, D, C, S>
    where
        <S::Right as Header<C::CircuitField>>::OnlinePolyCommit: Has<P, I>,
    {
        self.right_at(slot::<
            <S::Right as Header<C::CircuitField>>::OnlinePolyCommit,
            P,
            I,
        >(kind))
    }

    /// Returns the oracle for the step's own output proof's polynomial of
    /// `kind`, as [`prepare`](super::Step::prepare) prepared it.
    pub fn output<P, I>(&mut self, kind: P) -> Oracle<'_, 'a, 'dr, D, C, S>
    where
        <S::Output as Header<C::CircuitField>>::OnlinePolyCommit: Has<P, I>,
    {
        self.output_at(slot::<
            <S::Output as Header<C::CircuitField>>::OnlinePolyCommit,
            P,
            I,
        >(kind))
    }

    /// Returns the oracle for the left input proof's `index`-th polynomial,
    /// whatever the header lists. Ragu's own steps, one circuit for every
    /// header, copy or pin every slot through these.
    pub(crate) fn left_at(&mut self, index: usize) -> Oracle<'_, 'a, 'dr, D, C, S> {
        Oracle {
            slot: offset(0, index),
            oracles: self,
        }
    }

    /// Returns the oracle for the right input proof's `index`-th polynomial;
    /// see [`left_at`](Self::left_at).
    pub(crate) fn right_at(&mut self, index: usize) -> Oracle<'_, 'a, 'dr, D, C, S> {
        Oracle {
            slot: offset(1, index),
            oracles: self,
        }
    }

    /// Returns the oracle for the output proof's `index`-th polynomial; see
    /// [`left_at`](Self::left_at).
    pub(crate) fn output_at(&mut self, index: usize) -> Oracle<'_, 'a, 'dr, D, C, S> {
        Oracle {
            slot: offset(2, index),
            oracles: self,
        }
    }

    /// Opens the slot at `i` at `x`.
    fn open_at(&mut self, dr: &mut D, i: usize, x: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        if self.queries[i].is_some() {
            return Err(Error::Initialization(
                "an online slot may be opened once per step".into(),
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

    /// Opens every slot the step did not query at $\zeta$: first each
    /// output slot, held to one, the padding a slot a step leaves unopened
    /// carries, then each input slot, to its value there. Returns $\zeta$
    /// with the six openings, in slot order, and the bridge hash's
    /// coordinates, for the instance.
    ///
    /// The output slots come first so that the circuit is the one a step
    /// pinning its padding by hand, after its own checks, would have.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] on a driver that carries a witness
    /// if an output slot the step did not open has a value other than one
    /// at $\zeta$: the step prepared a polynomial for it, and the proof
    /// would not verify.
    #[allow(clippy::type_complexity)]
    pub(crate) fn finish(
        mut self,
        dr: &mut D,
    ) -> Result<(Element<'dr, D>, QueriesOutput<'dr, D>, [Element<'dr, D>; 2])> {
        let zeta = self.zeta.clone();
        for index in 0..NUM_ONLINE_POLYNOMIALS {
            if self.queries[offset(2, index)].is_none() {
                let value = self.output_at(index).open(dr, &zeta)?;
                D::try_just(|| {
                    if *value.value().take() == D::F::ONE {
                        Ok(())
                    } else {
                        Err(Error::InvalidWitness(
                            "the step prepared a polynomial for an output slot it does not open"
                                .into(),
                        ))
                    }
                })?;
                value.enforce_equal(dr, &Element::one())?;
            }
        }
        for i in 0..online::NUM_ONLINE_QUERIES {
            if self.queries[i].is_none() {
                self.open_at(dr, i, &zeta)?;
            }
        }
        let queries = FixedVec::try_from(
            self.queries
                .into_iter()
                .map(|query| query.expect("every slot was queried"))
                .collect::<Vec<_>>(),
        )?;
        Ok((self.zeta, queries, self.bridge_hash))
    }
}

/// One polynomial of a step's [`Oracles`]: an input or output proof's
/// slot, to be opened once.
#[must_use = "an oracle does nothing until it is opened"]
pub struct Oracle<'o, 'a, 'dr, D: Driver<'dr>, C: Cycle, S: Step<C>> {
    oracles: &'o mut Oracles<'a, 'dr, D, C, S>,
    slot: usize,
}

/// Returns the slot of the `index`-th polynomial of proof `proof` (left,
/// right, output) among the step's six, in the instance's order.
const fn offset(proof: usize, index: usize) -> usize {
    assert!(
        index < NUM_ONLINE_POLYNOMIALS,
        "a proof carries at most NUM_ONLINE_POLYNOMIALS online polynomials"
    );
    proof * NUM_ONLINE_POLYNOMIALS + index
}

impl<'dr, D: Driver<'dr>, C: Cycle, S: Step<C>> Oracle<'_, '_, 'dr, D, C, S> {
    /// Opens the polynomial at `x`, returning a wire holding its value
    /// there. The opening is proved by Ragu, not by this circuit: the
    /// returned wire is a witness the step may use in its constraints, and
    /// the pair $(x, y)$ enters the step's instance.
    ///
    /// The point and value are public: the parent reads them into its
    /// preamble, and a compressed proof carries and absorbs them, so a
    /// point or value the step must keep secret cannot be opened through
    /// this oracle.
    ///
    /// # Errors
    ///
    /// Each polynomial may be opened once; a second opening of the same
    /// one is refused. Allocating the opened value propagates the driver's
    /// error.
    pub fn open(self, dr: &mut D, x: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        self.oracles.open_at(dr, self.slot, x)
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
