//! Assembly of the $k(Y)$ instance polynomial.
//!
//! The [`eval`] function in this module processes instance data for a
//! particular [`Circuit`], arranging it into the low-degree coefficient vector
//! for the circuit's $k(Y)$ instance polynomial.

use ff::Field;
use ragu_core::{
    Result,
    drivers::emulator::Emulator,
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_primitives::{Element, GadgetExt};

use super::Circuit;

/// Evaluates $k(y)$ for the given circuit and instance at a point $y$, without
/// collecting intermediate coefficients.
pub fn eval<F: Field, C: Circuit<F>>(circuit: &C, instance: C::Instance<'_>, y: F) -> Result<F> {
    let mut dr = Emulator::extractor();
    let y_elem = Element::alloc(&mut dr, Always::<F>::just(|| y))?;
    let mut ky = crate::horner::Horner::new(&y_elem);
    circuit
        .instance(&mut dr, Always::maybe_just(|| instance))?
        .write(&mut dr, &mut ky)?;

    Ok(ky.finish_ky(&mut dr)?.wire().clone().value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::SquareCircuit;
    use ragu_pasta::Fp;

    #[test]
    fn test_ky() {
        let circuit = SquareCircuit { times: 10 };
        let instance: Fp = Fp::from(3);
        let y = Fp::random(&mut rand::rng());

        // k(Y) = 1 + 3Y for this circuit, so k(y) = 1 + 3y.
        let expected = Fp::ONE + Fp::from(3) * y;
        assert_eq!(eval::<Fp, _>(&circuit, instance, y).unwrap(), expected);
    }
}
