//! Shared coefficient-stream quotient batching.
use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse};
use udon::field::Field;
/// Horner-batches quotient coefficient streams with $\alpha$: the first
/// stream receives the highest power.
pub(in crate::fuse::prover) fn alpha_batched_quotients<F: Field, R: Rank>(
    mut iters: Vec<impl Iterator<Item = F>>,
    alpha: F,
) -> sparse::Polynomial<F, R> {
    let mut coeffs = Vec::with_capacity(R::num_coeffs());
    let (first, rest) = iters.split_first_mut().unwrap();
    for val in first.by_ref() {
        let c = rest
            .iter_mut()
            .fold(val, |acc, iter| acc.mul_add(&alpha, &iter.next().unwrap()));
        coeffs.push(c);
    }
    coeffs.reverse();

    sparse::Polynomial::from_coeffs(coeffs)
}
