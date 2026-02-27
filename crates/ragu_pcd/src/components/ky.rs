//! Streaming Horner's method evaluation of k(Y) via the Buffer trait.

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, GadgetExt, io::Buffer};

use super::horner::Horner;

/// A buffer that evaluates k(Y) at a point `y` using Horner's method.
///
/// This wraps [`Horner`] and adds a trailing constant 1 term when finished.
pub struct Ky<'a, 'dr, D: Driver<'dr>> {
    inner: Horner<'a, 'dr, D>,
}

impl<'a, 'dr, D: Driver<'dr>> Clone for Ky<'a, 'dr, D> {
    fn clone(&self) -> Self {
        Ky {
            inner: self.inner.clone(),
        }
    }
}

impl<'a, 'dr, D: Driver<'dr>> Ky<'a, 'dr, D> {
    /// Creates a new buffer that evaluates k(Y) at point `y`.
    pub fn new(y: &'a Element<'dr, D>) -> Self {
        Ky {
            inner: Horner::new(y),
        }
    }

    /// Finishes the evaluation by adding the trailing constant (one) term.
    /// Returns the final k(y) value.
    pub fn finish(mut self, dr: &mut D) -> Result<Element<'dr, D>> {
        // Write trailing 1 and finish
        Element::one().write(dr, &mut self.inner)?;
        Ok(self.inner.finish(dr))
    }
}

impl<'a, 'dr, D: Driver<'dr>> Buffer<'dr, D> for Ky<'a, 'dr, D> {
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        self.inner.write(dr, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
    use ragu_pasta::Fp;

    /// Issue #347: Ky with no writes returns one (the trailing constant).
    #[test]
    fn empty_returns_one() -> Result<()> {
        let dr = &mut Emulator::execute();
        let y = Element::constant(dr, Fp::from(5));
        let ky = Ky::new(&y);
        let result = *ky.finish(dr)?.value().take();
        assert_eq!(result, Fp::ONE);
        Ok(())
    }

    /// Issue #347: Ky appends trailing 1, so [3, 2] at y=5 → 3*25 + 2*5 + 1 = 86.
    #[test]
    fn appends_trailing_one() -> Result<()> {
        let dr = &mut Emulator::execute();
        let y = Element::constant(dr, Fp::from(5));
        let mut ky = Ky::new(&y);

        for &c in &[3u64, 2] {
            let elem = Element::constant(dr, Fp::from(c));
            ky.write(dr, &elem)?;
        }

        let result = *ky.finish(dr)?.value().take();
        // 3*25 + 2*5 + 1 = 86
        assert_eq!(result, Fp::from(86));
        Ok(())
    }

    /// Issue #347: Ky(coeffs) == Horner(coeffs ++ [1]).
    #[test]
    fn matches_horner_plus_one() -> Result<()> {
        use super::super::horner::Horner;

        let mut rng = rand::rng();
        let dr = &mut Emulator::execute();

        let y = Fp::random(&mut rng);
        let y_elem = Element::constant(dr, y);

        let coeffs: Vec<Fp> = (0..8).map(|_| Fp::random(&mut rng)).collect();

        // Ky evaluation
        let mut ky = Ky::new(&y_elem);
        for &c in &coeffs {
            let elem = Element::constant(dr, c);
            ky.write(dr, &elem)?;
        }
        let ky_result = *ky.finish(dr)?.value().take();

        // Horner evaluation with trailing 1
        let mut horner = Horner::new(&y_elem);
        for &c in coeffs.iter().chain(&[Fp::ONE]) {
            let elem = Element::constant(dr, c);
            horner.write(dr, &elem)?;
        }
        let horner_result = *horner.finish(dr).value().take();

        assert_eq!(ky_result, horner_result);
        Ok(())
    }
}
