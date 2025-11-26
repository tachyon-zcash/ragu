//! Routine for computing the folding c value in-circuit.
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

use crate::polynomials::CrossProductsLen;

/// Routine for computing the folding c value in-circuit.
#[derive(Clone, Default)]
pub struct ComputeC<const NUM_CIRCUITS: usize>;

impl<F: Field, const NUM_CIRCUITS: usize> Routine<F> for ComputeC<NUM_CIRCUITS> {
    type Input = Kind![F; (((Element<'_, _>, Element<'_, _>), Element<'_, _>), (FixedVec<Element<'_, _>, CrossProductsLen<NUM_CIRCUITS>>, FixedVec<Element<'_, _>, ConstLen<NUM_CIRCUITS>>))];
    type Output = Kind![F; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let ((mu_challenge, nu_challenge), mu_inv) = input.0;
        let (cross_elements, ky_elements) = input.1;

        let munu = mu_challenge.mul(dr, &nu_challenge)?;

        let mut c_acc = Element::zero(dr);
        let mut row_power = Element::one();
        let mut cross_iter = 0;

        for i in 0..NUM_CIRCUITS {
            let mut col_power = row_power.clone();
            for j in 0..NUM_CIRCUITS {
                let term = if i == j {
                    ky_elements[i].clone()
                } else {
                    let cross_elem = cross_elements[cross_iter].clone();
                    cross_iter += 1;
                    cross_elem
                };

                let contribution = col_power.mul(dr, &term)?;
                c_acc = c_acc.add(dr, &contribution);
                col_power = col_power.mul(dr, &munu)?;
            }
            row_power = row_power.mul(dr, &mu_inv)?;
        }

        Ok(c_acc)
    }

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: &<Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<
        Prediction<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>, DriverValue<D, Self::Aux<'dr>>>,
    > {
        let output = Element::alloc(
            dr,
            D::with(|| {
                let mu = *input.0.0.0.value().take();
                let nu = *input.0.0.1.value().take();
                let mu_inv = *input.0.1.value().take();
                let cross_elements: Vec<F> =
                    input.1.0.iter().map(|elem| *elem.value().take()).collect();
                let ky_elements: Vec<F> =
                    input.1.1.iter().map(|elem| *elem.value().take()).collect();

                let munu = mu * nu;

                let mut c = F::ZERO;
                let mut row_power = F::ONE;
                let mut cross_iter = 0;

                for (i, &ky_i) in ky_elements.iter().enumerate().take(NUM_CIRCUITS) {
                    let mut col_power = row_power;
                    for j in 0..NUM_CIRCUITS {
                        let term = if i == j {
                            ky_i
                        } else {
                            let cross_elem = cross_elements[cross_iter];
                            cross_iter += 1;
                            cross_elem
                        };

                        c += col_power * term;
                        col_power *= munu;
                    }
                    row_power *= mu_inv;
                }

                Ok(c)
            })?,
        )?;

        Ok(Prediction::Known(output, D::just(|| ())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use ragu_core::drivers::emulator::Emulator;
    use ragu_pasta::Fp;
    use ragu_primitives::vec::Len;
    use rand::rngs::OsRng;

    #[test]
    fn test_c_routine_equivalency() -> Result<()> {
        const NUM_CIRCUITS: usize = 3;

        let mu = Fp::random(OsRng);
        let nu = Fp::random(OsRng);
        let mu_inv = mu.invert().unwrap();

        let num_cross = CrossProductsLen::<NUM_CIRCUITS>::len();
        let cross_products: Vec<Fp> = (0..num_cross).map(|_| Fp::random(OsRng)).collect();
        let ky_values: Vec<Fp> = (0..NUM_CIRCUITS).map(|_| Fp::random(OsRng)).collect();

        // Compute expected c value
        let munu = mu * nu;
        let mut expected_c = Fp::ZERO;
        let mut row_power = Fp::ONE;
        let mut cross_iter = 0;

        for i in 0..NUM_CIRCUITS {
            let mut col_power = row_power;
            for j in 0..NUM_CIRCUITS {
                let term = if i == j {
                    ky_values[i]
                } else {
                    let cross_elem = cross_products[cross_iter];
                    cross_iter += 1;
                    cross_elem
                };

                expected_c += col_power * term;
                col_power *= munu;
            }
            row_power *= mu_inv;
        }

        // Run routine with Emulator
        let mut em = Emulator::execute();

        let mu_elem = Element::constant(&mut em, mu);
        let nu_elem = Element::constant(&mut em, nu);
        let mu_inv_elem = Element::constant(&mut em, mu_inv);

        let cross_vec: Vec<_> = cross_products
            .iter()
            .map(|&val| Element::constant(&mut em, val))
            .collect();
        let cross_elems = FixedVec::new(cross_vec).unwrap();

        let ky_vec: Vec<_> = ky_values
            .iter()
            .map(|&val| Element::constant(&mut em, val))
            .collect();
        let ky_elems = FixedVec::new(ky_vec).unwrap();

        let input = (((mu_elem, nu_elem), mu_inv_elem), (cross_elems, ky_elems));

        let routine = ComputeC::<NUM_CIRCUITS>::default();
        let result = em.routine(routine, input).unwrap();
        let computed_c = result.value().take();

        assert_eq!(
            *computed_c, expected_c,
            "C routine computed value doesn't match expected"
        );

        Ok(())
    }
}
