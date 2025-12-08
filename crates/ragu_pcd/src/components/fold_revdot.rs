//! Operations and utilities for reasoning about folded revdot claims.

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{
    Element,
    vec::{ConstLen, FixedVec, Len},
};

/// Represents the number of "error" terms produced during a folding operation
/// of many `revdot` claims.
///
/// Given $m$ claims being folded, the error terms are defined as the
/// off-diagonal entries of an $m \times m$ matrix, which by definition has $m *
/// (m - 1)$ terms.
///
/// See the book entry on [folding revdot
/// claims](https://tachyon.z.cash/_ragu_INTERNAL_ONLY_H83J19XK1/design/structured.html#folding)
/// for more information.
pub struct ErrorTermsLen<const NUM_REVDOT_CLAIMS: usize>;

impl<const NUM_REVDOT_CLAIMS: usize> Len for ErrorTermsLen<NUM_REVDOT_CLAIMS> {
    fn len() -> usize {
        // NUM_REVDOT_CLAIMS * (NUM_REVDOT_CLAIMS - 1) =
        NUM_REVDOT_CLAIMS * NUM_REVDOT_CLAIMS - NUM_REVDOT_CLAIMS
    }
}

pub fn compute_c<'dr, D: Driver<'dr>, const NUM_REVDOT_CLAIMS: usize>(
    dr: &mut D,
    mu: &Element<'dr, D>,
    nu: &Element<'dr, D>,
    error_terms: &FixedVec<Element<'dr, D>, ErrorTermsLen<NUM_REVDOT_CLAIMS>>,
    ky_values: &FixedVec<Element<'dr, D>, ConstLen<NUM_REVDOT_CLAIMS>>,
) -> Result<Element<'dr, D>> {
    let munu = mu.mul(dr, nu)?;
    let mu_inv = mu.invert(dr)?;

    let mut error_terms = error_terms.iter();
    let mut ky_values = ky_values.iter();

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

            let contribution = col_power.mul(dr, term)?;
            result = result.add(dr, &contribution);
            col_power = col_power.mul(dr, &munu)?;
        }
        row_power = row_power.mul(dr, &mu_inv)?;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
    use ragu_pasta::Fp;
    use ragu_primitives::vec::CollectFixed;
    use rand::rngs::OsRng;

    #[test]
    fn test_revdot_folding() -> Result<()> {
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
        let dr = &mut Emulator::execute();

        let mu = Element::constant(dr, mu);
        let nu = Element::constant(dr, nu);

        let error_terms = error
            .iter()
            .map(|&v| Element::constant(dr, v))
            .collect_fixed()
            .unwrap();

        let ky_values = ky
            .iter()
            .map(|&v| Element::constant(dr, v))
            .collect_fixed()
            .unwrap();

        let result = compute_c::<_, NUM_REVDOT_CLAIMS>(dr, &mu, &nu, &error_terms, &ky_values)?;
        let computed_c = result.value().take();

        assert_eq!(
            *computed_c, expected_c,
            "C routine computed value doesn't match expected"
        );

        Ok(())
    }
}
