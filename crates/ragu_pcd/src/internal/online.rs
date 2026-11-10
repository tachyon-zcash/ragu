//! The online polynomials a fuse step opens: those stored in its two child
//! proofs and its own output proof, which the step's PCS batch opens at
//! points the application circuit chooses.
//!
//! Each proof stores [`NUM_ONLINE_POLYNOMIALS`] polynomials associated with its
//! output header, a parameter of the protocol rather than of the header type.
//! The header's field encoding is separate from these polynomials and their
//! commitments. A step's online slots are the proofs' polynomials in the
//! fixed order
//! `[L0, L1, R0, R1, O0, O1]` (see [`Slot`]): the left and right slots are
//! the children's output polynomials, which the children committed and
//! exported, and the output slots are the step's own, committed before $w$
//! is squeezed and exported for the parent. Every slot holds a polynomial
//! the producing step chose; a step that needs fewer puts [`padding`], the
//! constant one, in the rest, whose commitment is a fixed generator and
//! whose evaluation at any point is one, and holds the slot to it in its
//! circuit, since nothing else does. What a slot means is the
//! application's convention for the header, constrained by the circuits of
//! the steps that produce it, as the header's fields are; Ragu proves only
//! that every opening is of the committed polynomial.
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
pub use crate::header::NUM_ONLINE_POLYNOMIALS;

/// The number of online polynomials a step opens across its input and output proofs.
pub const NUM_ONLINE_QUERIES: usize = 3 * NUM_ONLINE_POLYNOMIALS;

/// Length type for a step's online slots.
pub type QueriesLen = ConstLen<NUM_ONLINE_QUERIES>;

/// Length type for one proof's online polynomials.
pub type PolynomialsLen = ConstLen<NUM_ONLINE_POLYNOMIALS>;

/// The input or output position whose proof supplies a step's online slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position {
    /// The left input proof.
    Left,
    /// The right input proof.
    Right,
    /// The output proof.
    Output,
}

impl Position {
    /// The positions in slot order.
    pub const ALL: [Self; 3] = [Self::Left, Self::Right, Self::Output];
}

/// An online slot: one of an input or output proof's polynomials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    position: Position,
    index: usize,
}

impl Slot {
    /// The `index`-th polynomial of the proof at `position`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is not below [`NUM_ONLINE_POLYNOMIALS`].
    pub const fn new(position: Position, index: usize) -> Self {
        assert!(
            index < NUM_ONLINE_POLYNOMIALS,
            "a proof carries at most NUM_ONLINE_POLYNOMIALS online polynomials"
        );
        Slot { position, index }
    }

    /// The `index`-th polynomial of the left input proof.
    pub const fn left(index: usize) -> Self {
        Self::new(Position::Left, index)
    }

    /// The `index`-th polynomial of the right input proof.
    pub const fn right(index: usize) -> Self {
        Self::new(Position::Right, index)
    }

    /// The `index`-th polynomial of the output proof.
    pub const fn output(index: usize) -> Self {
        Self::new(Position::Output, index)
    }

    /// The input or output proof this slot belongs to.
    pub const fn position(self) -> Position {
        self.position
    }

    /// The slot's index among its proof's online polynomials.
    pub const fn index(self) -> usize {
        self.index
    }

    /// The slot's index among the step's slots, three proofs'
    /// [`NUM_ONLINE_POLYNOMIALS`] each, in slot order.
    pub const fn offset(self) -> usize {
        let proof = match self.position {
            Position::Left => 0,
            Position::Right => 1,
            Position::Output => 2,
        };
        proof * NUM_ONLINE_POLYNOMIALS + self.index
    }

    /// Every slot, in slot order.
    pub fn all() -> impl Iterator<Item = Self> {
        Position::ALL.into_iter().flat_map(|position| {
            (0..NUM_ONLINE_POLYNOMIALS).map(move |index| Self::new(position, index))
        })
    }
}

/// The coefficients of `polys`, ascending in degree with trailing zeros
/// stripped: how a step's first phase reads a proof's online polynomials.
pub fn coefficients<F: Field, R: Rank>(
    polys: &[sparse::Polynomial<F, R>; NUM_ONLINE_POLYNOMIALS],
) -> [alloc::vec::Vec<F>; NUM_ONLINE_POLYNOMIALS] {
    core::array::from_fn(|i| {
        let mut coeffs: alloc::vec::Vec<F> = polys[i].iter_coeffs().collect();
        while coeffs.last() == Some(&F::ZERO) {
            coeffs.pop();
        }
        coeffs
    })
}

/// A step's online polynomials in slot order: the children's exported
/// polynomials as its left and right slots, then its own, `own`.
pub fn polys<'a, C: Cycle, R: Rank>(
    left: &'a Proof<C, crate::Uncompressed<R>>,
    right: &'a Proof<C, crate::Uncompressed<R>>,
    own: &'a [sparse::Polynomial<C::CircuitField, R>; NUM_ONLINE_POLYNOMIALS],
) -> [&'a sparse::Polynomial<C::CircuitField, R>; NUM_ONLINE_QUERIES] {
    let proofs = [left.online_polynomials(), right.online_polynomials(), own];
    core::array::from_fn(|slot| {
        &proofs[slot / NUM_ONLINE_POLYNOMIALS][slot % NUM_ONLINE_POLYNOMIALS]
    })
}

/// The commitments of [`polys`], in the same order, given the step's own
/// commitments `own`.
pub fn commitments<C: Cycle, R: Rank>(
    left: &Proof<C, crate::Uncompressed<R>>,
    right: &Proof<C, crate::Uncompressed<R>>,
    own: [C::HostCurve; NUM_ONLINE_POLYNOMIALS],
) -> [C::HostCurve; NUM_ONLINE_QUERIES] {
    let proofs = [left.online_commitments(), right.online_commitments(), own];
    core::array::from_fn(|slot| {
        proofs[slot / NUM_ONLINE_POLYNOMIALS][slot % NUM_ONLINE_POLYNOMIALS]
    })
}

/// The polynomial of a slot a step leaves unused: the constant one, whose
/// commitment is a fixed generator (never the identity, which the walk
/// cannot take) and whose evaluation at any point is one.
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
        assert_eq!(Slot::right(0).offset(), NUM_ONLINE_POLYNOMIALS);
        assert_eq!(Slot::output(0).offset(), 2 * NUM_ONLINE_POLYNOMIALS);
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
            coefficients(&polys),
            [
                alloc::vec![Fp::from(3), Fp::ZERO, Fp::from(5)],
                alloc::vec![Fp::ONE]
            ]
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
