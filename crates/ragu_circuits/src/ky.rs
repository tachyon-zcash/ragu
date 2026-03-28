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

    Ok(*ky.finish_ky(&mut dr)?.wire())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::SquareCircuit;
    use alloc::vec::Vec;
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
    use ragu_pasta::Fp;
    use ragu_primitives::io::Buffer;

    #[test]
    fn test_ky() {
        let circuit = SquareCircuit { times: 10 };
        let instance: Fp = Fp::from(3);
        let y = Fp::random(&mut rand::rng());

        // k(Y) = 1 + 3Y for this circuit, so k(y) = 1 + 3y.
        let expected = Fp::ONE + Fp::from(3) * y;
        assert_eq!(eval::<Fp, _>(&circuit, instance, y).unwrap(), expected);
    }

    /// Issue #347: finish_ky with no writes returns one (the trailing constant).
    #[test]
    fn empty_returns_one() -> Result<()> {
        let dr = &mut Emulator::execute();
        let y = Element::constant(dr, Fp::from(5));
        let ky = crate::horner::Horner::new(&y);
        let result = *ky.finish_ky(dr)?.value().take();
        assert_eq!(result, Fp::ONE);
        Ok(())
    }

    /// Issue #347: finish_ky appends trailing 1, so [3, 2] at y=5
    /// evaluates as 3*25 + 2*5 + 1 = 86.
    #[test]
    fn appends_trailing_one() -> Result<()> {
        let dr = &mut Emulator::execute();
        let y = Element::constant(dr, Fp::from(5));
        let mut ky = crate::horner::Horner::new(&y);

        for &c in &[3u64, 2] {
            let elem = Element::constant(dr, Fp::from(c));
            ky.write(dr, &elem)?;
        }

        let result = *ky.finish_ky(dr)?.value().take();
        // 3*25 + 2*5 + 1 = 86
        assert_eq!(result, Fp::from(86));
        Ok(())
    }

    /// Issue #347: finish_ky(coeffs) == Horner(coeffs ++ [1]).
    #[test]
    fn matches_horner_plus_one() -> Result<()> {
        let mut rng = rand::rng();
        let dr = &mut Emulator::execute();

        let y = Fp::random(&mut rng);
        let y_elem = Element::constant(dr, y);

        let coeffs: Vec<Fp> = (0..8).map(|_| Fp::random(&mut rng)).collect();

        // finish_ky evaluation
        let mut ky = crate::horner::Horner::new(&y_elem);
        for &c in &coeffs {
            let elem = Element::constant(dr, c);
            ky.write(dr, &elem)?;
        }
        let ky_result = *ky.finish_ky(dr)?.value().take();

        // Horner evaluation with trailing 1
        let mut horner = crate::horner::Horner::new(&y_elem);
        for &c in coeffs.iter().chain(&[Fp::ONE]) {
            let elem = Element::constant(dr, c);
            horner.write(dr, &elem)?;
        }
        let horner_result = *horner.finish(dr).value().take();

        assert_eq!(ky_result, horner_result);
        Ok(())
    }
}
