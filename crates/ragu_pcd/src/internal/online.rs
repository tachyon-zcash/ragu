//! The online polynomials a fuse step opens: those stored in its two child
//! proofs and its own output proof, which the step's PCS batch opens at
//! points the application circuit chooses.
//!
//! Each proof stores [`NUM_ONLINE_FP_POLYS`] polynomials associated with its
//! output header, a parameter of the protocol rather than of the header type.
//! The header's field encoding is separate from these polynomials and their
//! commitments. A step's online slots are the proofs' polynomials in the
//! fixed order
//! `[L0, L1, R0, R1, O0, O1]`, which [`Oracles`](crate::step::Oracles)
//! keeps to: the left and right slots
//! are the children's output polynomials, which the children committed and
//! exported, and the output slots are the step's own, committed before $w$
//! is squeezed and exported for the parent. Every slot holds a polynomial
//! the producing step chose; a slot the step does not prepare holds
//! [`padding`], the constant one, whose commitment is a fixed generator and
//! whose evaluation at any point is one, and the adapter holds every
//! output slot the step's circuit does not open to it. What a slot means
//! is the application's convention for the header, named by the header's
//! [`OnlinePolyCommit`](crate::header::Header::OnlinePolyCommit) and
//! constrained by the circuits of the steps that produce it, as the
//! header's fields are; Ragu proves only that every opening is of the
//! committed polynomial.
//!
//! The commitments live on the nested side, in the `preamble` bridge stage,
//! and the nested walk folds them into $P$ with the rest of the native
//! batch; the polynomials themselves are native, evaluated at $u$ in the
//! `eval` stage and folded into $p$ in the same order. Each slot is opened
//! once, at the point the step queried it, or at $\zeta = w$ with the
//! polynomial's value there when the step did not; the `query` stage holds
//! the openings and `compute_v` folds them into the batch and exports them
//! in its bridge instance for the parent.

use alloc::{vec, vec::Vec};

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
pub(crate) use crate::header::NUM_ONLINE_FP_POLYS;

/// The number of online polynomials a step opens across its input and output proofs.
pub const NUM_ONLINE_FP_QUERIES: usize = 3 * NUM_ONLINE_FP_POLYS;

/// Length type for a step's online slots.
pub(crate) type QueriesLen = ConstLen<NUM_ONLINE_FP_QUERIES>;

/// Length type for one proof's online polynomials.
pub(crate) type PolynomialsLen = ConstLen<NUM_ONLINE_FP_POLYS>;

/// The coefficients of `polys`, ascending in degree with trailing zeros
/// stripped: how a step's first phase reads a proof's online polynomials.
pub(crate) fn coefficients<F: Field, R: Rank>(
    polys: &[sparse::Polynomial<F, R>; NUM_ONLINE_FP_POLYS],
) -> [Vec<F>; NUM_ONLINE_FP_POLYS] {
    core::array::from_fn(|i| {
        let mut coeffs: Vec<F> = polys[i].iter_coeffs().collect();
        while coeffs.last() == Some(&F::ZERO) {
            coeffs.pop();
        }
        coeffs
    })
}

/// A step's online polynomials in slot order: the children's exported
/// polynomials as its left and right slots, then its own, `own`.
pub(crate) fn polys<'a, C: Cycle, R: Rank>(
    left: &'a Proof<C, R>,
    right: &'a Proof<C, R>,
    own: &'a [sparse::Polynomial<C::CircuitField, R>; NUM_ONLINE_FP_POLYS],
) -> [&'a sparse::Polynomial<C::CircuitField, R>; NUM_ONLINE_FP_QUERIES] {
    let proofs = [left.online_polynomials(), right.online_polynomials(), own];
    core::array::from_fn(|slot| &proofs[slot / NUM_ONLINE_FP_POLYS][slot % NUM_ONLINE_FP_POLYS])
}

/// The commitments of [`polys`], in the same order, given the step's own
/// commitments `own`.
pub(crate) fn commitments<C: Cycle, R: Rank>(
    left: &Proof<C, R>,
    right: &Proof<C, R>,
    own: [C::HostCurve; NUM_ONLINE_FP_POLYS],
) -> [C::HostCurve; NUM_ONLINE_FP_QUERIES] {
    let proofs = [left.online_commitments(), right.online_commitments(), own];
    core::array::from_fn(|slot| proofs[slot / NUM_ONLINE_FP_POLYS][slot % NUM_ONLINE_FP_POLYS])
}

/// The polynomial of a slot a step leaves unused: the constant one, whose
/// commitment is a fixed generator (never the identity, which the walk
/// cannot take) and whose evaluation at any point is one.
pub(crate) fn padding<F: Field, R: Rank>() -> sparse::Polynomial<F, R> {
    sparse::Polynomial::from_coeffs(vec![F::ONE])
}

/// One opening claim $f(x) = y$ on an online slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Query<F> {
    /// The point.
    pub x: F,
    /// The claimed evaluation.
    pub y: F,
}

/// A step's online openings, one per slot in slot order. The point every
/// unqueried slot is opened at is the step's $\zeta = w$, which the
/// instance does not repeat.
pub(crate) type Queries<F> = [Query<F>; NUM_ONLINE_FP_QUERIES];

/// The openings of a step that queried nothing: every slot at `zeta`, with
/// `evaluate(slot, zeta)` the slot's value there.
pub(crate) fn queries_at<F: Field>(zeta: F, mut evaluate: impl FnMut(usize, F) -> F) -> Queries<F> {
    core::array::from_fn(|slot| Query {
        x: zeta,
        y: evaluate(slot, zeta),
    })
}

/// The opening of one slot, as wires.
#[derive(Gadget, Write, Consistent)]
pub(crate) struct QueryOutput<'dr, D: Driver<'dr>> {
    /// The point.
    #[ragu(gadget)]
    pub x: Element<'dr, D>,
    /// The claimed evaluation.
    #[ragu(gadget)]
    pub y: Element<'dr, D>,
}

/// A step's online openings, as wires, in slot order.
pub(crate) type QueriesOutput<'dr, D> = FixedVec<QueryOutput<'dr, D>, QueriesLen>;

/// Allocates the openings' wires from their values.
pub(crate) fn alloc_queries<'dr, D: Driver<'dr>, A: Allocator<'dr, D>>(
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
