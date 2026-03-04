//! Streaming Horner's method evaluation of k(Y) via the Sink trait.

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, GadgetExt, io::Sink};

use super::horner::Horner;

/// A sink that evaluates k(Y) at a point `y` using Horner's method.
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
        Element::one().sink(dr, &mut self.inner)?;
        Ok(self.inner.finish(dr))
    }
}

impl<'a, 'dr, D: Driver<'dr>> Sink<'dr, D> for Ky<'a, 'dr, D> {
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        self.inner.write(dr, value)
    }
}
