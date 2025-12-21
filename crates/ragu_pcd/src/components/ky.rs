//! Streaming Horner's method evaluation of k(Y) via the Buffer trait.

use ff::Field;
use ragu_circuits::Circuit;
use ragu_core::{
    Result,
    drivers::{Driver, emulator::Emulator},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, io::Buffer};

/// Emulate k(Y) evaluation at point `y` for a circuit instance.
pub fn emulate<F: Field, C: Circuit<F>>(circuit: &C, instance: C::Instance<'_>, y: F) -> Result<F> {
    Emulator::emulate_wired((instance, y), |dr, witness| {
        let (instance, y) = witness.cast();
        let output = circuit.instance(dr, instance)?;
        let y_elem = Element::constant(dr, y.take());
        let mut ky = Ky::new(dr, &y_elem);
        output.write(dr, &mut ky)?;
        Ok(ky.finish(dr)?.wire().clone().value().take())
    })
}

/// A buffer that evaluates k(Y) at a point `y` using Horner's method.
pub struct Ky<'a, 'dr, D: Driver<'dr>> {
    y: &'a Element<'dr, D>,
    result: Element<'dr, D>,
}

impl<'a, 'dr, D: Driver<'dr>> Ky<'a, 'dr, D> {
    pub fn new(dr: &mut D, y: &'a Element<'dr, D>) -> Self {
        Ky {
            y,
            result: Element::zero(dr),
        }
    }

    /// Finishes the evaluation by adding the trailing constant (one) term.
    /// Returns the final k(y) value.
    pub fn finish(self, dr: &mut D) -> Result<Element<'dr, D>> {
        // Final Horner step: result = result * y + 1
        Ok(self.result.mul(dr, &self.y)?.add(dr, &Element::one()))
    }
}

impl<'a, 'dr, D: Driver<'dr>> Buffer<'dr, D> for Ky<'a, 'dr, D> {
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        // Horner's step: result = result * y + value.
        self.result = self.result.mul(dr, &self.y)?.add(dr, value);

        Ok(())
    }
}
