use alloc::vec::Vec;

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::Element;
use udon::field::Field;

use super::super::header::HEADER_POLYNOMIALS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position {
    Left,
    Right,
    Output,
}

impl Position {
    pub const ALL: [Self; 3] = [Self::Left, Self::Right, Self::Output];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    position: Position,
    index: usize,
}

impl Slot {
    pub const fn new(position: Position, index: usize) -> Self {
        assert!(
            index < HEADER_POLYNOMIALS,
            "a header carries at most HEADER_POLYNOMIALS polynomials"
        );
        Self { position, index }
    }

    pub const fn left(index: usize) -> Self {
        Self::new(Position::Left, index)
    }

    pub const fn right(index: usize) -> Self {
        Self::new(Position::Right, index)
    }

    pub const fn output(index: usize) -> Self {
        Self::new(Position::Output, index)
    }

    pub const fn position(self) -> Position {
        self.position
    }

    pub const fn index(self) -> usize {
        self.index
    }

    pub const fn offset(self) -> usize {
        self.position as usize * HEADER_POLYNOMIALS + self.index
    }

    pub fn all() -> impl Iterator<Item = Self> {
        Position::ALL.into_iter().flat_map(|position| {
            (0..HEADER_POLYNOMIALS).map(move |index| Self::new(position, index))
        })
    }
}

pub struct Oracles<'a, 'dr, D: Driver<'dr>> {
    zeta: Element<'dr, D>,
    bridge_hash: [Element<'dr, D>; 2],
    staged: Vec<Element<'dr, D>>,
    slots: DriverValue<D, [&'a [Vec<D::F>; HEADER_POLYNOMIALS]; 3]>,
}

impl<'a, 'dr, D: Driver<'dr>> Oracles<'a, 'dr, D> {
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
        })
    }

    pub fn zeta(&self) -> &Element<'dr, D> {
        &self.zeta
    }

    pub fn bridge_hash(&self) -> &[Element<'dr, D>; 2] {
        &self.bridge_hash
    }

    pub fn staged(&self) -> &[Element<'dr, D>] {
        &self.staged
    }

    pub fn query(
        &mut self,
        dr: &mut D,
        slot: Slot,
        x: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let x = x.value();
        let y = self.slots.as_ref().map(|slots| {
            let header = slots[slot.offset() / HEADER_POLYNOMIALS];
            let x = *x.take();
            header[slot.index]
                .iter()
                .rev()
                .fold(D::F::ZERO, |acc, coefficient| acc * x + *coefficient)
        });
        Element::alloc(dr, &mut (), y)
    }

    pub fn query_at_zeta(&mut self, dr: &mut D, slot: Slot) -> Result<Element<'dr, D>> {
        let zeta = self.zeta.clone();
        self.query(dr, slot, &zeta)
    }
}
