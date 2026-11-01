//! The online polynomials a fuse step opens: the polynomial commitments its
//! three headers carry, which the step's own PCS batch opens at points the
//! application circuit chooses.
//!
//! Each header carries [`HEADER_POLYNOMIALS`] polynomials beside its field
//! data. A step's online slots are its headers' polynomials in the fixed
//! order `[L0, L1, R0, R1, O0, O1]`: the left and right slots
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
//! polynomial's value there when the step did not.

use alloc::vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Cycle;
use ragu_primitives::vec::ConstLen;
use udon::field::Field;

use crate::Proof;
pub use crate::header::HEADER_POLYNOMIALS;

/// The online polynomials a step opens: those of its three headers.
pub const NUM_ONLINE_QUERIES: usize = 3 * HEADER_POLYNOMIALS;

/// Length type for a step's online slots.
pub type QueriesLen = ConstLen<NUM_ONLINE_QUERIES>;

/// Length type for one header's polynomials.
pub type HeaderLen = ConstLen<HEADER_POLYNOMIALS>;

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

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::pasta::Fp;

    use super::*;

    #[test]
    fn padding_is_the_constant_one() {
        let padding = padding::<Fp, TestRank>();
        assert_eq!(padding.eval(Fp::from(17)), Fp::ONE);
        assert_eq!(padding.eval(Fp::ZERO), Fp::ONE);
    }
}
