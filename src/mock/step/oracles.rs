use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt as _, Point};
use udon::field::Field;

pub use super::super::header::HEADER_POLYNOMIALS;
use super::{
    super::header::{Has, Header},
    Step,
};

/// Mirrors `ragu_pcd::step::Oracles`.
pub struct Oracles<'a, 'dr, D: Driver<'dr>, C: Cycle, S: Step<C>> {
    zeta: Element<'dr, D>,
    bridge_hash: [Element<'dr, D>; 2],
    staged: Vec<Element<'dr, D>>,
    slots: DriverValue<D, [&'a [Vec<D::F>; HEADER_POLYNOMIALS]; 3]>,
    queries: [bool; 3 * HEADER_POLYNOMIALS],
    _marker: PhantomData<fn() -> (C, S)>,
}

impl<'a, 'dr, D: Driver<'dr>, C: Cycle, S: Step<C>> Oracles<'a, 'dr, D, C, S> {
    pub(crate) fn alloc(
        dr: &mut D,
        zeta: D::F,
        bridge_hash: [D::F; 2],
        staged: Vec<D::F>,
        slots: [&'a [Vec<D::F>; HEADER_POLYNOMIALS]; 3],
    ) -> Result<Self> {
        let mut alloc = |value| Element::alloc(dr, &mut (), D::just(|| value));
        Ok(Self {
            zeta: alloc(zeta)?,
            bridge_hash: [alloc(bridge_hash[0])?, alloc(bridge_hash[1])?],
            staged: staged.into_iter().map(alloc).collect::<Result<_>>()?,
            slots: D::just(|| slots),
            queries: [false; 3 * HEADER_POLYNOMIALS],
            _marker: PhantomData,
        })
    }

    pub fn zeta(&self) -> &Element<'dr, D> {
        &self.zeta
    }

    /// The bridge-hash stage's commitment.
    pub fn bridge_hash(&self) -> Point<'dr, D, C::NestedCurve>
    where
        C: Cycle<CircuitField = D::F>,
    {
        let [x, y] = self.bridge_hash.clone();
        Point::new_unchecked(x, y)
    }

    pub fn staged(&self) -> &[Element<'dr, D>] {
        &self.staged
    }

    /// Mirrors `ragu_pcd::step::Oracles::left`.
    pub fn left<P, I>(&mut self, _kind: P) -> Oracle<'_, 'a, 'dr, D, C, S>
    where
        <S::Left as Header<C::CircuitField>>::OnlinePolyCommit: Has<P, I>,
    {
        self.left_at(<<S::Left as Header<C::CircuitField>>::OnlinePolyCommit as Has<P, I>>::INDEX)
    }

    /// Mirrors `ragu_pcd::step::Oracles::right`.
    pub fn right<P, I>(&mut self, _kind: P) -> Oracle<'_, 'a, 'dr, D, C, S>
    where
        <S::Right as Header<C::CircuitField>>::OnlinePolyCommit: Has<P, I>,
    {
        self.right_at(<<S::Right as Header<C::CircuitField>>::OnlinePolyCommit as Has<P, I>>::INDEX)
    }

    /// Mirrors `ragu_pcd::step::Oracles::output`.
    pub fn output<P, I>(&mut self, _kind: P) -> Oracle<'_, 'a, 'dr, D, C, S>
    where
        <S::Output as Header<C::CircuitField>>::OnlinePolyCommit: Has<P, I>,
    {
        self.output_at(
            <<S::Output as Header<C::CircuitField>>::OnlinePolyCommit as Has<P, I>>::INDEX,
        )
    }

    /// Mirrors `ragu_pcd`: every output slot the step left unopened is
    /// opened at zeta and held to one, the padding it carries. A slot whose
    /// value is not one fails with `Error::InvalidWitness`.
    pub(crate) fn finish(&mut self, dr: &mut D) -> Result<()> {
        let zeta = self.zeta.clone();
        for index in 0..HEADER_POLYNOMIALS {
            if !self.queries[slot(2, index)] {
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
        Ok(())
    }

    /// Mirrors `ragu_pcd`'s crate-private positional accessors, for the
    /// slots a header does not name.
    pub(crate) fn left_at(&mut self, index: usize) -> Oracle<'_, 'a, 'dr, D, C, S> {
        Oracle {
            slot: slot(0, index),
            oracles: self,
        }
    }

    pub(crate) fn right_at(&mut self, index: usize) -> Oracle<'_, 'a, 'dr, D, C, S> {
        Oracle {
            slot: slot(1, index),
            oracles: self,
        }
    }

    pub(crate) fn output_at(&mut self, index: usize) -> Oracle<'_, 'a, 'dr, D, C, S> {
        Oracle {
            slot: slot(2, index),
            oracles: self,
        }
    }

    /// Opens the slot at `i` at `x`. Each slot may be opened once per
    /// step; a second opening is refused, regardless of its point.
    fn open_at(&mut self, dr: &mut D, i: usize, x: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        if self.queries[i] {
            return Err(Error::Initialization(
                "an online slot may be opened once per step".into(),
            ));
        }
        let x = x.value();
        let slots = self.slots.as_ref();
        let y = D::just(|| {
            let x = *x.take();
            let slots = slots.take();
            let header = slots[i / HEADER_POLYNOMIALS];
            header[i % HEADER_POLYNOMIALS]
                .iter()
                .rev()
                .fold(D::F::ZERO, |acc, coefficient| acc * x + *coefficient)
        });
        let y = Element::alloc(dr, &mut (), y)?;
        self.queries[i] = true;
        Ok(y)
    }
}

/// Mirrors `ragu_pcd::step::Oracle`.
#[must_use = "an oracle does nothing until it is opened"]
pub struct Oracle<'o, 'a, 'dr, D: Driver<'dr>, C: Cycle, S: Step<C>> {
    oracles: &'o mut Oracles<'a, 'dr, D, C, S>,
    slot: usize,
}

/// The slot of the `index`-th polynomial of proof `proof` (left, right,
/// output) among the step's slots, in `ragu_pcd`'s order.
const fn slot(proof: usize, index: usize) -> usize {
    assert!(
        index < HEADER_POLYNOMIALS,
        "a header carries at most HEADER_POLYNOMIALS polynomials"
    );
    proof * HEADER_POLYNOMIALS + index
}

impl<'dr, D: Driver<'dr>, C: Cycle, S: Step<C>> Oracle<'_, '_, 'dr, D, C, S> {
    /// Mirrors `ragu_pcd::step::Oracle::open`.
    pub fn open(self, dr: &mut D, x: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        self.oracles.open_at(dr, self.slot, x)
    }
}
