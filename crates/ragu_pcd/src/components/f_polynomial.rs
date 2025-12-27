// Computes the F polynomial by batching quotient polynomials  `(p(X) - p(a)) / (X - a)`
//! using the alpha challenge. This enables efficient batched polynomial evaluation
//! verification.

use alloc::{boxed::Box, vec::Vec};
use ff::Field;
use ragu_circuits::polynomials::{Rank, unstructured};

pub fn compute_f_polynomial<F: Field, R: Rank>(
    queries: Vec<Box<dyn Iterator<Item = F>>>,
    alpha: F,
) -> unstructured::Polynomial<F, R> {
    if queries.is_empty() {
        return unstructured::Polynomial::new();
    }

    let mut queries = queries;

    let mut f_coeffs = Vec::with_capacity(R::num_coeffs());

    'poly: loop {
        let mut this_coeff = F::ZERO;
        for query in queries.iter_mut() {
            this_coeff *= alpha;
            if let Some(coeff) = query.next() {
                this_coeff += coeff;
            } else {
                // All queries exhausted
                break 'poly;
            }
        }
        f_coeffs.push(this_coeff);
    }

    // Reverse coefficients and construct unstructured polynomial for F.
    f_coeffs.reverse();

    unstructured::Polynomial::from_coeffs(f_coeffs)
}
