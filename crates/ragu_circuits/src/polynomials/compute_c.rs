//! Routine for computing c, the revdot claim for the folded accumulator.

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    routines::{Prediction, Routine},
};
use ragu_primitives::{
    Element,
    vec::{ConstLen, FixedVec},
};

use crate::polynomials::CrossProductsLen;

/// Input gadget for the ComputeRevdotClaim routine.
#[derive(Gadget)]
pub struct RevdotClaimInput<'dr, D: Driver<'dr>, const NUM_CIRCUITS: usize> {
    #[ragu(gadget)]
    pub mu: Element<'dr, D>,
    #[ragu(gadget)]
    pub nu: Element<'dr, D>,
    #[ragu(gadget)]
    pub mu_inv: Element<'dr, D>,
    #[ragu(gadget)]
    pub cross_products: FixedVec<Element<'dr, D>, CrossProductsLen<NUM_CIRCUITS>>,
    #[ragu(gadget)]
    pub ky_values: FixedVec<Element<'dr, D>, ConstLen<NUM_CIRCUITS>>,
}

/// Routine for computing the revdot claim, c.
#[derive(Clone, Default)]
pub struct ComputeRevdotClaim<const NUM_CIRCUITS: usize>;

impl<F: Field, const NUM_CIRCUITS: usize> Routine<F> for ComputeRevdotClaim<NUM_CIRCUITS> {
    type Input = Kind![F; RevdotClaimInput<'_, _, NUM_CIRCUITS>];
    type Output = Kind![F; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let munu = input.mu.mul(dr, &input.nu)?;

        let mut c_acc = Element::zero(dr);
        let mut row_power = Element::one();
        let mut cross_iter = 0;

        for i in 0..NUM_CIRCUITS {
            let mut col_power = row_power.clone();
            for j in 0..NUM_CIRCUITS {
                let term = if i == j {
                    input.ky_values[i].clone()
                } else {
                    let cross_elem = input.cross_products[cross_iter].clone();
                    cross_iter += 1;
                    cross_elem
                };

                let contribution = col_power.mul(dr, &term)?;
                c_acc = c_acc.add(dr, &contribution);
                col_power = col_power.mul(dr, &munu)?;
            }
            row_power = row_power.mul(dr, &input.mu_inv)?;
        }

        Ok(c_acc)
    }

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        _dr: &mut D,
        _input: &<Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<
        Prediction<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>, DriverValue<D, Self::Aux<'dr>>>,
    > {
        // Prediction requires the same computation as execution. Return Unknown to defer to execute().
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
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

        // Compute expected c value.
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

        // Run routine with Emulator.
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

        let input = RevdotClaimInput {
            mu: mu_elem,
            nu: nu_elem,
            mu_inv: mu_inv_elem,
            cross_products: cross_elems,
            ky_values: ky_elems,
        };

        let routine = ComputeRevdotClaim::<NUM_CIRCUITS>::default();
        let result = em.routine(routine, input).unwrap();
        let computed_c = result.value().take();

        assert_eq!(
            *computed_c, expected_c,
            "C routine computed value doesn't match expected"
        );

        Ok(())
    }
}
