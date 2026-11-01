//! The online polynomials a fuse step opens: the polynomial commitments its
//! three headers carry, which the step's own PCS batch opens at points the
//! application circuit chooses.
//!
//! Each header carries [`HEADER_POLYNOMIALS`] polynomials beside its field
//! data. A step's online slots are its headers' polynomials in the fixed
//! order `[L0, L1, R0, R1, O0, O1]` (see [`Slot`]): the left and right slots
//! are the children's output polynomials, which the children committed and
//! exported, and the output slots are the step's own, committed before $w$
//! is squeezed and exported for the parent. Every slot holds a polynomial:
//! a header that declares fewer than [`HEADER_POLYNOMIALS`] fills the rest
//! with [`padding`], the constant one, whose commitment is a fixed
//! generator and whose evaluation at any point is one.
//!
//! The commitments live on the nested side, in the `preamble` bridge stage,
//! and the nested walk folds them into $P$ with the rest of the native
//! batch; the polynomials themselves are native, evaluated at $u$ in the
//! `eval` stage and folded into $p$ in the same order. Each slot is opened
//! once, at the point the step queried it, or at $\zeta = w$ with the
//! polynomial's value there when the step did not; the `query` stage holds
//! the openings and `compute_v` folds them into the batch and exports them
//! in its bridge instance for the parent.

use alloc::vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    allocator::Allocator,
    consistent::Consistent,
    io::Write,
    vec::{ConstLen, FixedVec},
};
use udon::field::Field;

use crate::Proof;
pub use crate::header::HEADER_POLYNOMIALS;

/// The online polynomials a step opens: those of its three headers.
pub const NUM_ONLINE_QUERIES: usize = 3 * HEADER_POLYNOMIALS;

/// Length type for a step's online slots.
pub type QueriesLen = ConstLen<NUM_ONLINE_QUERIES>;

/// Length type for one header's polynomials.
pub type HeaderLen = ConstLen<HEADER_POLYNOMIALS>;

/// The headers of a step whose polynomials fill its online slots, in slot
/// order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position {
    /// The left input header.
    Left,
    /// The right input header.
    Right,
    /// The output header.
    Output,
}

impl Position {
    /// The positions in slot order.
    pub const ALL: [Self; 3] = [Self::Left, Self::Right, Self::Output];
}

/// An online slot: one of a header's polynomials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    position: Position,
    index: usize,
}

impl Slot {
    /// The `index`-th polynomial of the header at `position`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is not below [`HEADER_POLYNOMIALS`].
    pub const fn new(position: Position, index: usize) -> Self {
        assert!(
            index < HEADER_POLYNOMIALS,
            "a header carries at most HEADER_POLYNOMIALS polynomials"
        );
        Slot { position, index }
    }

    /// The `index`-th polynomial of the left header.
    pub const fn left(index: usize) -> Self {
        Self::new(Position::Left, index)
    }

    /// The `index`-th polynomial of the right header.
    pub const fn right(index: usize) -> Self {
        Self::new(Position::Right, index)
    }

    /// The `index`-th polynomial of the output header.
    pub const fn output(index: usize) -> Self {
        Self::new(Position::Output, index)
    }

    /// The header this slot belongs to.
    pub const fn position(self) -> Position {
        self.position
    }

    /// The slot's index among its header's polynomials.
    pub const fn index(self) -> usize {
        self.index
    }

    /// The slot's index among the step's [`NUM_ONLINE_QUERIES`] slots.
    pub const fn offset(self) -> usize {
        let header = match self.position {
            Position::Left => 0,
            Position::Right => 1,
            Position::Output => 2,
        };
        header * HEADER_POLYNOMIALS + self.index
    }

    /// Every slot, in slot order.
    pub fn all() -> impl Iterator<Item = Self> {
        Position::ALL.into_iter().flat_map(|position| {
            (0..HEADER_POLYNOMIALS).map(move |index| Self::new(position, index))
        })
    }
}

/// The coefficients of the first `declared` of `polys`, ascending in degree
/// with trailing zeros stripped: how a step's first phase reads a header's
/// polynomials.
pub fn coefficients<F: Field, R: Rank>(
    polys: &[sparse::Polynomial<F, R>; HEADER_POLYNOMIALS],
    declared: usize,
) -> alloc::vec::Vec<alloc::vec::Vec<F>> {
    polys[..declared]
        .iter()
        .map(|poly| {
            let mut coeffs: alloc::vec::Vec<F> = poly.iter_coeffs().collect();
            while coeffs.last() == Some(&F::ZERO) {
                coeffs.pop();
            }
            coeffs
        })
        .collect()
}

/// A step's online polynomials in slot order: the children's exported
/// polynomials as its left and right slots, then its own, `own`.
pub fn polys<'a, C: Cycle, R: Rank>(
    left: &'a Proof<C, R>,
    right: &'a Proof<C, R>,
    own: &'a [sparse::Polynomial<C::CircuitField, R>; HEADER_POLYNOMIALS],
) -> [&'a sparse::Polynomial<C::CircuitField, R>; NUM_ONLINE_QUERIES] {
    let headers = [left.online_polys(), right.online_polys(), own];
    core::array::from_fn(|slot| &headers[slot / HEADER_POLYNOMIALS][slot % HEADER_POLYNOMIALS])
}

/// The commitments of [`polys`], in the same order, given the step's own
/// commitments `own`.
pub fn commitments<C: Cycle, R: Rank>(
    left: &Proof<C, R>,
    right: &Proof<C, R>,
    own: [C::HostCurve; HEADER_POLYNOMIALS],
) -> [C::HostCurve; NUM_ONLINE_QUERIES] {
    let headers = [left.online_commitments(), right.online_commitments(), own];
    core::array::from_fn(|slot| headers[slot / HEADER_POLYNOMIALS][slot % HEADER_POLYNOMIALS])
}

/// The polynomial of an unused slot: the constant one, whose commitment is
/// a fixed generator (never the identity, which the walk cannot take) and
/// whose evaluation at any point is one.
pub fn padding<F: Field, R: Rank>() -> sparse::Polynomial<F, R> {
    sparse::Polynomial::from_coeffs(vec![F::ONE])
}

/// One opening claim $f(x) = y$ on an online slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query<F> {
    /// The point.
    pub x: F,
    /// The claimed evaluation.
    pub y: F,
}

/// A step's online openings, one per slot in slot order. The point every
/// unqueried slot is opened at is the step's $\zeta = w$, which the
/// instance does not repeat.
pub type Queries<F> = [Query<F>; NUM_ONLINE_QUERIES];

/// The openings of a step that queried nothing: every slot at `zeta`, with
/// `evaluate(slot, zeta)` the slot's value there.
pub fn queries_at<F: Field>(zeta: F, mut evaluate: impl FnMut(usize, F) -> F) -> Queries<F> {
    core::array::from_fn(|slot| Query {
        x: zeta,
        y: evaluate(slot, zeta),
    })
}

/// The opening of one slot, as wires.
#[derive(Gadget, Write, Consistent)]
pub struct QueryOutput<'dr, D: Driver<'dr>> {
    /// The point.
    #[ragu(gadget)]
    pub x: Element<'dr, D>,
    /// The claimed evaluation.
    #[ragu(gadget)]
    pub y: Element<'dr, D>,
}

/// A step's online openings, as wires, in slot order.
pub type QueriesOutput<'dr, D> = FixedVec<QueryOutput<'dr, D>, QueriesLen>;

/// Allocates the openings' wires from their values.
pub fn alloc_queries<'dr, D: Driver<'dr>, A: Allocator<'dr, D>>(
    dr: &mut D,
    allocator: &mut A,
    queries: DriverValue<D, &Queries<D::F>>,
) -> Result<QueriesOutput<'dr, D>> {
    FixedVec::try_from_fn(|i| {
        Ok(QueryOutput {
            x: Element::alloc(dr, allocator, queries.as_ref().map(|q| q[i].x))?,
            y: Element::alloc(dr, allocator, queries.as_ref().map(|q| q[i].y))?,
        })
    })
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::pasta::Fp;

    use super::*;

    #[test]
    fn slots_are_laid_out_in_header_order() {
        let offsets: alloc::vec::Vec<usize> = Slot::all().map(Slot::offset).collect();
        assert_eq!(
            offsets,
            (0..NUM_ONLINE_QUERIES).collect::<alloc::vec::Vec<_>>()
        );
        assert_eq!(Slot::left(1).offset(), 1);
        assert_eq!(Slot::right(0).offset(), HEADER_POLYNOMIALS);
        assert_eq!(Slot::output(0).offset(), 2 * HEADER_POLYNOMIALS);
        assert_eq!(Slot::output(0).position(), Position::Output);
        assert_eq!(Slot::output(1).index(), 1);
    }

    #[test]
    fn coefficients_strip_trailing_zeros() {
        let polys = [
            sparse::Polynomial::<Fp, TestRank>::from_coeffs(alloc::vec![
                Fp::from(3),
                Fp::ZERO,
                Fp::from(5),
            ]),
            padding(),
        ];
        assert_eq!(
            coefficients(&polys, 2),
            alloc::vec![
                alloc::vec![Fp::from(3), Fp::ZERO, Fp::from(5)],
                alloc::vec![Fp::ONE]
            ]
        );
        assert_eq!(
            coefficients(&polys, 0),
            alloc::vec::Vec::<alloc::vec::Vec<Fp>>::new()
        );
    }

    #[test]
    fn padding_is_the_constant_one() {
        let padding = padding::<Fp, TestRank>();
        assert_eq!(padding.eval(Fp::from(17)), Fp::ONE);
        assert_eq!(padding.eval(Fp::ZERO), Fp::ONE);
        let queries = queries_at(Fp::from(5), |_, x| padding.eval(x));
        assert!(queries.iter().all(|q| q.x == Fp::from(5) && q.y == Fp::ONE));
    }
}
