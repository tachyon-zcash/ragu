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

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
    use ragu_pasta::Fp;

    /// Issue #347: Horner with no writes returns zero.
    #[test]
    fn empty_returns_zero() -> Result<()> {
        let dr = &mut Emulator::execute();
        let point = Element::constant(dr, Fp::from(5));
        let horner = Horner::new(&point);
        let result = *horner.finish(dr).value().take();
        assert_eq!(result, Fp::ZERO);
        Ok(())
    }

    /// Issue #347: Horner with a single write returns that value.
    #[test]
    fn single_element() -> Result<()> {
        let dr = &mut Emulator::execute();
        let point = Element::constant(dr, Fp::from(5));
        let mut horner = Horner::new(&point);
        let val = Element::constant(dr, Fp::from(42));
        horner.write(dr, &val)?;
        let result = *horner.finish(dr).value().take();
        assert_eq!(result, Fp::from(42));
        Ok(())
    }

    /// Issue #347: Horner evaluates p(x) = 3x^2 + 2x + 1 at x=5 → 86.
    #[test]
    fn evaluates_polynomial() -> Result<()> {
        let dr = &mut Emulator::execute();
        let point = Element::constant(dr, Fp::from(5));
        let mut horner = Horner::new(&point);

        // Write coefficients in descending order: 3, 2, 1
        for &c in &[3u64, 2, 1] {
            let elem = Element::constant(dr, Fp::from(c));
            horner.write(dr, &elem)?;
        }

        let result = *horner.finish(dr).value().take();
        // 3*25 + 2*5 + 1 = 75 + 10 + 1 = 86
        assert_eq!(result, Fp::from(86));
        Ok(())
    }

    /// Issue #347: Horner matches manual evaluation on random coefficients.
    #[test]
    fn random_polynomial() -> Result<()> {
        let mut rng = rand::rng();
        let dr = &mut Emulator::execute();

        let x = Fp::random(&mut rng);
        let point = Element::constant(dr, x);

        let coeffs: Vec<Fp> = (0..10).map(|_| Fp::random(&mut rng)).collect();

        let mut horner = Horner::new(&point);
        for &c in &coeffs {
            let elem = Element::constant(dr, c);
            horner.write(dr, &elem)?;
        }
        let result = *horner.finish(dr).value().take();

        // Manual Horner evaluation
        let mut expected = Fp::ZERO;
        for &c in &coeffs {
            expected = expected * x + c;
        }

        assert_eq!(result, expected);
        Ok(())
    }
}
