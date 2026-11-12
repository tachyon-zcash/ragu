//! What a step prepares before its challenge is drawn.

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use udon::field::Field;

use crate::header::{Has, Header, NUM_ONLINE_FP_POLYS};

/// A step's output before its challenge $\zeta$ is drawn.
///
/// Holds the output proof's online polynomials, by kind, and the staged
/// values. [`Step::prepare`](super::Step::prepare) builds one; Ragu commits
/// its polynomials and stages its values before $\zeta$.
///
/// `O` is the step's output header, whose
/// [`OnlinePolyCommit`](Header::OnlinePolyCommit) lists the kinds of
/// polynomial that can be prepared. A slot the step prepares nothing for
/// holds the constant one: the padding every unused slot carries.
///
/// # Examples
///
/// ```rust,ignore
/// Prepared::new()
///     .poly(TachygramSet, times(left.polynomial(TachygramSet), &linear(t)))
///     .stage([t])
/// ```
pub struct Prepared<F, O> {
    polynomials: [Vec<F>; NUM_ONLINE_FP_POLYS],
    staged: Vec<F>,
    _marker: PhantomData<fn() -> O>,
}

impl<F: Field, O: Header<F>> Default for Prepared<F, O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, O: Header<F>> Prepared<F, O> {
    /// Creates a `Prepared` with nothing prepared: every slot holds the
    /// constant one and no value is staged.
    #[must_use]
    pub fn new() -> Self {
        Prepared {
            polynomials: core::array::from_fn(|_| vec![F::ONE]),
            staged: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Creates a `Prepared` holding every slot's polynomial, as an internal
    /// step that copies a proof's polynomials prepares them, whatever the
    /// header lists.
    pub(crate) fn from_polynomials(polynomials: [Vec<F>; NUM_ONLINE_FP_POLYS]) -> Self {
        Prepared {
            polynomials,
            staged: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Sets the output's polynomial of `kind` to `coefficients`, in
    /// ascending degree, replacing whatever its slot held.
    ///
    /// The commitment is unblinded and deterministic for these
    /// coefficients, and opening points and values are public. A
    /// polynomial may have at most as many coefficients as the
    /// application's rank holds, and must not be zero; Ragu checks both
    /// before committing.
    #[must_use]
    pub fn poly<P, I>(mut self, kind: P, coefficients: impl Into<Vec<F>>) -> Self
    where
        O::OnlinePolyCommit: Has<P, I>,
    {
        self.polynomials[crate::header::slot::<O::OnlinePolyCommit, P, I>(kind)] =
            coefficients.into();
        self
    }

    /// Stages `values`, after those staged so far. A step stages exactly
    /// [`NUM_STAGED`](super::Step::NUM_STAGED) values in all.
    #[must_use]
    pub fn stage(mut self, values: impl Into<Vec<F>>) -> Self {
        self.staged.extend(values.into());
        self
    }

    /// Returns the coefficients prepared for `kind`, or the constant one if
    /// none were.
    pub fn polynomial<P, I>(&self, kind: P) -> &[F]
    where
        O::OnlinePolyCommit: Has<P, I>,
    {
        &self.polynomials[crate::header::slot::<O::OnlinePolyCommit, P, I>(kind)]
    }

    /// Returns every slot's coefficients, in slot order: what Ragu commits,
    /// the constant one in every slot the header leaves to padding.
    ///
    /// Not part of the public API: a step reads a polynomial by its kind,
    /// through [`polynomial`](Self::polynomial). This is public only for
    /// the mock in the `ragu` crate.
    #[doc(hidden)]
    pub fn polynomials(&self) -> &[Vec<F>; NUM_ONLINE_FP_POLYS] {
        &self.polynomials
    }

    /// Returns the staged values, in order.
    pub fn staged(&self) -> &[F] {
        &self.staged
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
        gadgets::Bound,
        pasta::Fp,
    };
    use ragu_primitives::allocator::Allocator;

    use super::*;
    use crate::header::{OnlinePoly, Padding, Suffix};

    /// A polynomial kept in the last slot.
    #[derive(Clone, Copy, Debug)]
    struct Last;
    impl OnlinePoly for Last {}

    struct LastHeader;
    impl Header<Fp> for LastHeader {
        const SUFFIX: Suffix = Suffix::new(0);
        type OnlinePolyCommit = (Padding, Last);
        type Data = ();
        type Output = ();
        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            _: &mut D,
            _: &mut A,
            _: DriverValue<D, ()>,
        ) -> Result<Bound<'dr, D, ()>> {
            Ok(())
        }
    }

    #[test]
    fn unprepared_slots_hold_the_constant_one() {
        let prepared = Prepared::<Fp, LastHeader>::new().poly(Last, vec![Fp::from(3), Fp::ONE]);
        assert_eq!(prepared.polynomial(Last), &[Fp::from(3), Fp::ONE]);
        assert_eq!(prepared.polynomials()[0], vec![Fp::ONE]);
        assert_eq!(
            prepared.polynomials()[NUM_ONLINE_FP_POLYS - 1],
            vec![Fp::from(3), Fp::ONE]
        );
        assert!(prepared.staged().is_empty());
    }

    #[test]
    fn a_polynomial_prepared_again_is_replaced() {
        let prepared = Prepared::<Fp, LastHeader>::new()
            .poly(Last, vec![Fp::ONE, Fp::ONE])
            .poly(Last, vec![Fp::from(2)]);
        assert_eq!(prepared.polynomial(Last), &[Fp::from(2)]);
    }

    #[test]
    fn staged_values_accumulate_in_order() {
        let prepared = Prepared::<Fp, ()>::new()
            .stage([Fp::from(1)])
            .stage(vec![Fp::from(2), Fp::from(3)]);
        assert_eq!(prepared.staged(), &[Fp::from(1), Fp::from(2), Fp::from(3)]);
    }
}
