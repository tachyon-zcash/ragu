//! Routine for evaluating the k(Y) polynomial at a challenge point y using Horner's method.

use alloc::vec::Vec;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
    routines::{Prediction, Routine},
};
use ragu_primitives::{
    Element,
    vec::{ConstLen, FixedVec},
};

use crate::polynomials::TotalKyCoeffsLen;

#[derive(Clone)]
pub struct EvaluateKyPolynomials<const HEADER_SIZE: usize, const NUM_CIRCUITS: usize> {
    ky_degree: usize,
}

impl<const HEADER_SIZE: usize, const NUM_CIRCUITS: usize>
    EvaluateKyPolynomials<HEADER_SIZE, NUM_CIRCUITS>
{
    pub fn new(ky_degree: usize) -> Self {
        Self { ky_degree }
    }
}

impl<F: Field, const HEADER_SIZE: usize, const NUM_CIRCUITS: usize> Routine<F>
    for EvaluateKyPolynomials<HEADER_SIZE, NUM_CIRCUITS>
{
    type Input = Kind![F; (FixedVec<Element<'_, _>, TotalKyCoeffsLen<HEADER_SIZE, NUM_CIRCUITS>>, Element<'_, _>)];
    type Output = Kind![F; FixedVec<Element<'_, _>, ConstLen<NUM_CIRCUITS>>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let (ky_coefficients, y_challenge) = input;

        let mut ky_elements = Vec::with_capacity(NUM_CIRCUITS);

        // Evaluate each k(Y) polynomial at y.
        for circuit_idx in 0..NUM_CIRCUITS {
            let ky_start = circuit_idx * self.ky_degree;

            // Evaluate k(y) using Horner's method.
            let mut ky_at_y = Element::zero(dr);
            for coeff_idx in (0..self.ky_degree).rev() {
                let global_idx = ky_start + coeff_idx;
                let ky_coeff = ky_coefficients[global_idx].clone();

                ky_at_y = ky_at_y.mul(dr, &y_challenge)?;
                ky_at_y = ky_at_y.add(dr, &ky_coeff);
            }

            ky_elements.push(ky_at_y);
        }

        Ok(FixedVec::new(ky_elements).expect("ky_elements length"))
    }

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: &<Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<
        Prediction<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>, DriverValue<D, Self::Aux<'dr>>>,
    > {
        let mut ky_elements = Vec::with_capacity(NUM_CIRCUITS);

        // Evaluate each k(Y) polynomial at y.
        for circuit_idx in 0..NUM_CIRCUITS {
            let ky_start = circuit_idx * self.ky_degree;
            let ky_degree = self.ky_degree;

            let ky_elem = Element::alloc(
                dr,
                D::with(|| {
                    let ky_coefficients: Vec<F> =
                        input.0.iter().map(|elem| *elem.value().take()).collect();
                    let y_challenge = *input.1.value().take();

                    // Evaluate using Horner's method.
                    let mut ky_at_y = F::ZERO;
                    for coeff_idx in (0..ky_degree).rev() {
                        let global_idx = ky_start + coeff_idx;
                        let ky_coeff = ky_coefficients[global_idx];

                        ky_at_y *= y_challenge;
                        ky_at_y += ky_coeff;
                    }

                    Ok(ky_at_y)
                })?,
            )?;

            ky_elements.push(ky_elem);
        }

        Ok(Prediction::Known(
            FixedVec::new(ky_elements).expect("ky_elements length"),
            D::just(|| ()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::polynomials::KyPolyLen;

    use super::*;
    use ff::Field;
    use ragu_core::drivers::emulator::Emulator;
    use ragu_pasta::Fp;
    use ragu_primitives::vec::Len;
    use rand::rngs::OsRng;

    #[test]
    fn test_evaluate_ky_polynomials() {
        const NUM_CIRCUITS: usize = 3;
        const HEADER_SIZE: usize = 4;
        let ky_degree = KyPolyLen::<HEADER_SIZE>::len();
        let total_ky_coeffs = TotalKyCoeffsLen::<HEADER_SIZE, NUM_CIRCUITS>::len();
        let y_challenge = Fp::random(OsRng);

        let mut ky_coeffs = Vec::new();
        for _ in 0..total_ky_coeffs {
            ky_coeffs.push(Fp::random(OsRng));
        }

        let mut expected = Vec::new();
        for circuit_idx in 0..NUM_CIRCUITS {
            let ky_start = circuit_idx * ky_degree;
            let mut ky_at_y = Fp::ZERO;

            for coeff_idx in (0..ky_degree).rev() {
                let global_idx = ky_start + coeff_idx;
                ky_at_y *= y_challenge;
                ky_at_y += ky_coeffs[global_idx];
            }

            expected.push(ky_at_y);
        }

        // Run the routine using emulator driver.
        let mut em = Emulator::execute();

        let mut ky_elems = Vec::new();
        for &coeff in &ky_coeffs {
            ky_elems.push(Element::constant(&mut em, coeff));
        }

        let ky_elems_fixed = FixedVec::new(ky_elems).unwrap();
        let y_elem = Element::constant(&mut em, y_challenge);

        let routine = EvaluateKyPolynomials::<HEADER_SIZE, NUM_CIRCUITS>::new(ky_degree);
        let result = em.routine(routine, (ky_elems_fixed, y_elem)).unwrap();

        for (i, ky_elem) in result.iter().enumerate().take(NUM_CIRCUITS) {
            let computed = *ky_elem.value().take();
            assert_eq!(computed, expected[i], "Mismatch for circuit {}", i);
        }
    }
}
