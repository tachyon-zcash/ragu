//! Routine for evaluating ky polynomials at challenge point y using Horner's method.

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

#[derive(Clone)]
pub struct EvaluateKyPolynomials<const TOTAL_KY_COEFFS: usize, const MAX_CIRCUITS: usize> {
    num_circuits: usize,
    ky_degree: usize,
}

impl<const TOTAL_KY_COEFFS: usize, const MAX_CIRCUITS: usize>
    EvaluateKyPolynomials<TOTAL_KY_COEFFS, MAX_CIRCUITS>
{
    pub fn new(num_circuits: usize, ky_degree: usize) -> Self {
        Self {
            num_circuits,
            ky_degree,
        }
    }
}

impl<F: Field, const TOTAL_KY_COEFFS: usize, const MAX_CIRCUITS: usize> Routine<F>
    for EvaluateKyPolynomials<TOTAL_KY_COEFFS, MAX_CIRCUITS>
{
    type Input = Kind![F; (FixedVec<Element<'_, _>, ConstLen<TOTAL_KY_COEFFS>>, Element<'_, _>)];
    type Output = Kind![F; FixedVec<Element<'_, _>, ConstLen<MAX_CIRCUITS>>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let (ky_coefficients, y_challenge) = input;

        let mut ky_elements = Vec::with_capacity(self.num_circuits);

        for circuit_idx in 0..self.num_circuits {
            let ky_start = circuit_idx * self.ky_degree;

            // Evaluate k(y) using Horner's method.
            let mut ky_at_y = Element::zero(dr);
            for coeff_idx in (0..self.ky_degree).rev() {
                let global_idx = ky_start + coeff_idx;
                let ky_coeff = ky_coefficients[global_idx].clone();

                // result = result * y + coeff
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
        let mut ky_elements = Vec::with_capacity(self.num_circuits);

        // Evaluate each ky polynomial at y
        for circuit_idx in 0..self.num_circuits {
            let ky_start = circuit_idx * self.ky_degree;
            let ky_degree = self.ky_degree;

            // Allocate the predicted ky value for this circuit
            let ky_elem = Element::alloc(
                dr,
                D::with(|| {
                    // Extract coefficients and challenge within D::with context
                    let ky_coefficients: Vec<F> =
                        input.0.iter().map(|elem| *elem.value().take()).collect();
                    let y_challenge = *input.1.value().take();

                    // Evaluate using Horner's method
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
    use super::*;
    use ff::Field;
    use ragu_core::{drivers::Emulator, maybe::Always};
    use ragu_pasta::Fp;
    use rand::rngs::OsRng;

    #[test]
    fn test_evaluate_ky_polynomials() {
        const NUM_CIRCUITS: usize = 3;
        const KY_DEGREE: usize = 4;
        const TOTAL_KY_COEFFS: usize = 12; // NUM_CIRCUITS * KY_DEGREE
        let y_challenge = Fp::random(OsRng);

        let mut ky_coeffs = Vec::new();
        for _ in 0..TOTAL_KY_COEFFS {
            ky_coeffs.push(Fp::random(OsRng));
        }

        let mut expected = Vec::new();
        for circuit_idx in 0..NUM_CIRCUITS {
            let ky_start = circuit_idx * KY_DEGREE;
            let mut ky_at_y = Fp::ZERO;

            for coeff_idx in (0..KY_DEGREE).rev() {
                let global_idx = ky_start + coeff_idx;
                ky_at_y *= y_challenge;
                ky_at_y += ky_coeffs[global_idx];
            }

            expected.push(ky_at_y);
        }

        // Run the routine
        let mut em = Emulator::<Always<()>, Fp>::default();

        let mut ky_elems = Vec::new();
        for &coeff in &ky_coeffs {
            ky_elems.push(Element::constant(&mut em, coeff));
        }

        let ky_elems_fixed = FixedVec::new(ky_elems).unwrap();
        let y_elem = Element::constant(&mut em, y_challenge);

        let routine =
            EvaluateKyPolynomials::<TOTAL_KY_COEFFS, NUM_CIRCUITS>::new(NUM_CIRCUITS, KY_DEGREE);
        let result = em.routine(routine, (ky_elems_fixed, y_elem)).unwrap();

        for (i, ky_elem) in result.iter().enumerate().take(NUM_CIRCUITS) {
            let computed = *ky_elem.value().take();
            assert_eq!(computed, expected[i], "Mismatch for circuit {}", i);
        }
    }
}
