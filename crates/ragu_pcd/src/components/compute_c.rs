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

use alloc::vec::Vec;

use super::ErrorTermsLen;

/// Off-diagonal error terms.
#[derive(Gadget)]
pub struct ErrorMatrix<'dr, D: Driver<'dr>, const N: usize> {
    #[ragu(gadget)]
    elements: FixedVec<Element<'dr, D>, ErrorTermsLen<N>>,
}

impl<'dr, D: Driver<'dr>, const N: usize> ErrorMatrix<'dr, D, N> {
    /// Creates a new error matrix from the given elements.
    pub fn new(elements: FixedVec<Element<'dr, D>, ErrorTermsLen<N>>) -> Self {
        Self { elements }
    }

    /// Consumes the matrix and returns the underlying elements.
    pub fn into_inner(self) -> Vec<Element<'dr, D>> {
        self.elements.into_inner()
    }
}

/// Input gadget for the [`ComputeRevdotClaim`] routine.
#[derive(Gadget)]
pub struct RevdotClaimInput<'dr, D: Driver<'dr>, const NUM_REVDOT_CLAIMS: usize> {
    /// Folding challenge for rows.
    #[ragu(gadget)]
    pub mu: Element<'dr, D>,
    /// Folding challenge for columns.
    #[ragu(gadget)]
    pub nu: Element<'dr, D>,
    /// Inverse of mu.
    #[ragu(gadget)]
    pub mu_inv: Element<'dr, D>,
    /// Off-diagonal error terms from folding.
    #[ragu(gadget)]
    pub error_matrix: ErrorMatrix<'dr, D, NUM_REVDOT_CLAIMS>,
    /// Diagonal k(Y) polynomial evaluations.
    #[ragu(gadget)]
    pub ky_values: FixedVec<Element<'dr, D>, ConstLen<NUM_REVDOT_CLAIMS>>,
}

/// Routine for folding the revdot claims into a target value c.
#[derive(Clone, Default)]
pub struct ComputeRevdotClaim<const NUM_REVDOT_CLAIMS: usize>;

impl<F: Field, const NUM_REVDOT_CLAIMS: usize> Routine<F>
    for ComputeRevdotClaim<NUM_REVDOT_CLAIMS>
{
    type Input = Kind![F; RevdotClaimInput<'_, _, NUM_REVDOT_CLAIMS>];
    type Output = Kind![F; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let munu = input.mu.mul(dr, &input.nu)?;

        let mut error_terms = input.error_matrix.into_inner().into_iter();
        let mut ky_values = input.ky_values.into_inner().into_iter();

        let mut result = Element::zero(dr);
        let mut row_power = Element::one();

        for i in 0..NUM_REVDOT_CLAIMS {
            let mut col_power = row_power.clone();
            for j in 0..NUM_REVDOT_CLAIMS {
                let term = if i == j {
                    ky_values.next().expect("should exist")
                } else {
                    error_terms.next().expect("should exist")
                };

                let contribution = col_power.mul(dr, &term)?;
                result = result.add(dr, &contribution);
                col_power = col_power.mul(dr, &munu)?;
            }
            row_power = row_power.mul(dr, &input.mu_inv)?;
        }

        Ok(result)
    }

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        _dr: &mut D,
        _input: &<Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<
        Prediction<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>, DriverValue<D, Self::Aux<'dr>>>,
    > {
        // Prediction requires the same computation as execution. Return `Prediction::Unknown` to defer to execute().
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
    use ragu_pasta::Fp;
    use rand::rngs::OsRng;

    #[test]
    fn test_c_routine_equivalency() -> Result<()> {
        const NUM_REVDOT_CLAIMS: usize = 3;

        let a: Vec<Fp> = (0..NUM_REVDOT_CLAIMS).map(|_| Fp::random(OsRng)).collect();
        let b: Vec<Fp> = (0..NUM_REVDOT_CLAIMS).map(|_| Fp::random(OsRng)).collect();

        let mut ky = vec![];
        let mut error = vec![];

        for (i, a) in a.iter().enumerate() {
            for (j, b) in b.iter().enumerate() {
                if i == j {
                    ky.push(a * b);
                } else {
                    error.push(a * b);
                }
            }
        }

        let mu = Fp::random(OsRng);
        let nu = Fp::random(OsRng);
        let mu_inv = mu.invert().unwrap();

        let expected_c = arithmetic::eval(a.iter(), mu_inv) * arithmetic::eval(b.iter(), mu * nu);

        // Run routine with Emulator.
        let mut emulator = Emulator::execute();

        let mu_elem = Element::constant(&mut emulator, mu);
        let nu_elem = Element::constant(&mut emulator, nu);
        let mu_inv_elem = Element::constant(&mut emulator, mu_inv);

        let error_vec: Vec<_> = error
            .iter()
            .map(|&v| Element::constant(&mut emulator, v))
            .collect();
        let error_matrix = ErrorMatrix::new(FixedVec::new(error_vec).unwrap());

        let ky_vec: Vec<_> = ky
            .iter()
            .map(|&v| Element::constant(&mut emulator, v))
            .collect();
        let ky_values = FixedVec::new(ky_vec).unwrap();

        let input = RevdotClaimInput {
            mu: mu_elem,
            nu: nu_elem,
            mu_inv: mu_inv_elem,
            error_matrix,
            ky_values,
        };

        let result = emulator.routine(ComputeRevdotClaim::<NUM_REVDOT_CLAIMS>, input)?;
        let computed_c = result.value().take();

        assert_eq!(
            *computed_c, expected_c,
            "C routine computed value doesn't match expected"
        );

        Ok(())
    }
}
