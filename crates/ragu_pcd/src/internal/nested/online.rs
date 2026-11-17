//! The online polynomials over the scalar field: the step's own, which the
//! nested `compute_v` circuit opens.
//!
//! A profile sets how many each step commits, with
//! [`Profile::ONLINE_FQ_POLYS`]. The step commits each one natively, in the
//! native points stage that holds the children's nested commitments, before
//! $w$ is drawn. The native walk folds each commitment into $P_n$ after the
//! nested batch's other commitments. The nested `query` stage holds the
//! opened value $y_q$, the nested `eval` stage holds the value at $u_n$, and
//! the nested `compute_v` circuit reads them and folds the opening into the
//! step's own nested batch. The step does not export the polynomial, so a
//! parent never opens it.
//!
//! The opening point is $\zeta_q$, the challenge stage's lift of $w$, so no
//! stage holds a point. Every nested circuit that loads the `query` and
//! challenge stages reads the same $y_q$ and $\zeta_q$.

use core::marker::PhantomData;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_primitives::vec::Len;
use udon::field::Field;

use crate::profile::Profile;

/// The maximum number of online polynomials over the scalar field that a
/// step commits.
///
/// Such a polynomial belongs to the step that commits it. The step commits
/// it before its challenge is drawn, and the step's nested batch opens it.
/// The step does not export it, so a parent never opens it. Only a profile
/// that asks for the slot has it; see [`Profile::ONLINE_FQ_POLYS`]. A
/// profile that needs more pre-w polynomials over the scalar field declares
/// them in [`Profile::NESTED_ONLINE`] instead.
pub const NUM_ONLINE_FQ_POLYS: usize = 1;

/// Compatibility descriptors for pre-w slots opened at the lifted w.
/// Their stage placement is retained for existing profiles; their opening
/// algebra is shared with the general private batch.
pub(crate) fn openings(count: usize) -> impl Iterator<Item = crate::profile::online::Opening> {
    (0..count).map(|i| crate::profile::online::Opening {
        polynomial: i,
        point: crate::profile::online::Point::Challenge(crate::profile::online::Challenge::W),
        value: i,
    })
}

/// Length type for a step's own online polynomials over the scalar field
/// in profile `P`.
pub struct FqPolysLen<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for FqPolysLen<P> {
    fn len() -> usize {
        P::ONLINE_FQ_POLYS
    }
}

/// The walked commitments: legacy slots followed by distinct private polynomials.
pub struct FqPointsLen<P: Profile>(PhantomData<P>);
impl<P: Profile> Len for FqPointsLen<P> {
    fn len() -> usize {
        P::ONLINE_FQ_POLYS + P::NESTED_ONLINE.polynomials.len()
    }
}

/// Legacy and private points fixed before w; later auxiliaries live in later stages.
pub struct FqEarlyPointsLen<P: Profile>(PhantomData<P>);
impl<P: Profile> Len for FqEarlyPointsLen<P> {
    fn len() -> usize {
        P::ONLINE_FQ_POLYS + <crate::profile::online::stages::PhaseLen<P,crate::profile::online::stages::Nested,0> as Len>::len()
    }
}

/// The point at which a step opens its online Fq polynomials, given the
/// lift of $w$ into the scalar field: $\zeta_q$ itself.
///
/// No stage holds the point: the nested `compute_v` takes it from the
/// challenge stage. The prover's openings and quotients take it from here,
/// so this is the one place the prover chooses it.
///
/// New consumers with other opening points use [`Profile::NESTED_ONLINE`].
pub fn point<F: Field>(w: F) -> F {
    // Test hook: this runs on the thread that calls `fuse`, outside its
    // parallel jobs, as the hook's thread-local requires.
    #[cfg(test)]
    let w = crate::online_fq_oracles_tests::mutate_query_point(w);
    w
}

/// The polynomial that a step commits in each of its online Fq slots.
///
/// It is not zero, so its commitment is not the identity, which the native
/// walk cannot take. It is not constant, so its value at $\zeta_q$ depends
/// on $\zeta_q$.
///
/// This witness is retained for compatibility profiles. New consumers supply
/// their own polynomials through the private-batch preparation hooks.
pub fn placeholder<F: Field, R: Rank>() -> sparse::Polynomial<F, R> {
    sparse::Polynomial::from_coeffs(alloc::vec![F::from(1), F::from(2), F::from(3)])
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::pasta::Fq;

    use super::*;

    #[test]
    fn the_placeholder_is_not_constant() {
        let poly = placeholder::<Fq, TestRank>();
        // 1 + 2 * 5 + 3 * 25
        assert_eq!(poly.eval(Fq::from(5)), Fq::from(86));
        assert_ne!(poly.eval(Fq::from(5)), poly.eval(Fq::from(0)));
    }
}
