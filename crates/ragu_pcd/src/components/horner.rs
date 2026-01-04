//! Streaming Horner's method evaluation via the Buffer trait.

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, io::Buffer};

/// A buffer that evaluates a polynomial at a point using Horner's method.
///
/// # Coefficient Ordering
///
/// Elements written first correspond to **higher degree** terms. This is the
/// natural ordering for Horner's method: for $p(x) = a_n x^n + \cdots + a_0$,
/// write $a_n$ first and $a_0$ last.
///
/// This is consistent with
/// [`Polynomial::fold`](ragu_circuits::polynomials::structured::Polynomial::fold)
/// and [`Element::fold`](Element::fold), which also expect descending order.
///
/// Unlike [`Ky`](super::ky::Ky), this does not add a trailing constant term.
pub struct Horner<'a, 'dr, D: Driver<'dr>> {
    point: &'a Element<'dr, D>,
    result: Option<Element<'dr, D>>,
}

impl<'a, 'dr, D: Driver<'dr>> Clone for Horner<'a, 'dr, D> {
    fn clone(&self) -> Self {
        Horner {
            point: self.point,
            result: self.result.clone(),
        }
    }
}

impl<'a, 'dr, D: Driver<'dr>> Horner<'a, 'dr, D> {
    /// Creates a new buffer that evaluates a polynomial at `point`.
    pub fn new(point: &'a Element<'dr, D>) -> Self {
        Horner {
            point,
            result: None,
        }
    }

    /// Finishes the evaluation, returning the accumulated result.
    ///
    /// Returns zero if no elements were written.
    pub fn finish(self, dr: &mut D) -> Element<'dr, D> {
        self.result.unwrap_or_else(|| Element::zero(dr))
    }
}

impl<'a, 'dr, D: Driver<'dr>> Buffer<'dr, D> for Horner<'a, 'dr, D> {
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        self.result = Some(match self.result.take() {
            Some(acc) => acc.mul(dr, self.point)?.add(dr, value),
            None => value.clone(),
        });
        Ok(())
    }
}
