use alloc::{vec, vec::Vec};
use core::borrow::Borrow;

use ragu_backend::Backend;
use ragu_circuits::polynomials::{Rank, sparse::Polynomial};
use udon::{fft::Domain, field::Field};

/// Keep working storage bounded while giving the backend many independent FFTs.
const COEFFICIENT_PAIRS_PER_BATCH: usize = 256;

/// Evaluates the degree-m-2 quotient at m-1 consecutive new nodes, then
/// interpolates its coefficients. The input nodes are 0 through m-1.
/// For each new node t, Lagrange interpolation gives
/// `A(t)/Z(t) = sum_i A(i) / (Z'(i) * (t-i))`. The same formula applies to
/// B and the actual diagonal targets. The differences t-i are consecutive
/// integers, so the normalized evaluations are a convolution.
pub(super) struct Quotient<F> {
    domain: Domain<F>,
    kernel: Vec<F>,
    spectrum: Vec<F>,
    barycentric: Vec<F>,
    vanishing: Vec<F>,
    output_basis: Vec<Vec<F>>,
}

impl<F: Field> Quotient<F> {
    pub(super) fn new<B: Backend>(m: usize) -> Option<Self> {
        if m < 2 {
            return None;
        }
        let end = m.checked_mul(2)?.checked_sub(1)?;
        let size = (end - 1).checked_next_power_of_two()?;
        let domain = F::domain(size.ilog2()).ok()?;

        let kernel: Vec<_> = (1..end)
            .map(|i| F::from(i as u64).invert())
            .collect::<Option<_>>()?;
        let barycentric = (0..m)
            .map(|i| {
                (0..m)
                    .filter(|&j| j != i)
                    .map(|j| F::from(i as u64) - F::from(j as u64))
                    .product::<F>()
                    .invert()
            })
            .collect::<Option<_>>()?;
        let vanishing = (m..end)
            .map(|t| (0..m).map(|i| F::from((t - i) as u64)).product())
            .collect();

        let mut spectrum = kernel.clone();
        spectrum.resize(size, F::ZERO);
        B::fft(domain, &mut spectrum);

        Some(Self {
            domain,
            kernel,
            spectrum,
            barycentric,
            vanishing,
            output_basis: super::bases(m..end).0,
        })
    }

    fn fill_row(&self, row: &mut [F], coefficients: &mut [impl Iterator<Item = F>]) -> bool {
        let mut nonzero = false;
        for ((output, coefficient), &weight) in
            row.iter_mut().zip(coefficients).zip(&self.barycentric)
        {
            let value = coefficient.next().expect("coefficient count matches rank");
            *output = value;
            if !value.is_zero() {
                *output *= weight;
                nonzero = true;
            }
        }
        nonzero
    }

    fn accumulate<B: Backend>(&self, batch: &mut Vec<F>, products: &mut [F::Accumulator]) {
        let size = self.domain.size();
        B::fft_batch(self.domain, batch);
        for row in batch.chunks_exact_mut(size) {
            for (coefficient, &kernel) in row.iter_mut().zip(&self.spectrum) {
                *coefficient *= kernel;
            }
        }
        B::ifft_batch(self.domain, batch);

        // The retained coefficients start at m-1, beyond the reach of
        // wraparound in the cyclic convolution of length at least 2m-2.
        let start = self.barycentric.len() - 1;
        let end = start + products.len();
        for pair in batch.chunks_exact(2 * size) {
            let (a, b) = pair.split_at(size);
            for ((product, a), b) in products.iter_mut().zip(&a[start..end]).zip(&b[start..end]) {
                F::mul_accumulate(product, a, b);
            }
        }
        batch.clear();
    }

    fn shifted_products<B: Backend, R: Rank>(
        &self,
        a: &[impl Borrow<Polynomial<F, R>>],
        b: &[impl Borrow<Polynomial<F, R>>],
    ) -> impl Iterator<Item = F> {
        let mut a: Vec<_> = a.iter().map(|poly| poly.borrow().iter_coeffs()).collect();
        let mut b: Vec<_> = b
            .iter()
            .map(|poly| poly.borrow().iter_coeffs().rev())
            .collect();
        let mut products: Vec<_> = (0..self.vanishing.len())
            .map(|_| F::Accumulator::default())
            .collect();
        let size = self.domain.size();
        let batch_size = 2 * size * COEFFICIENT_PAIRS_PER_BATCH;
        let mut batch = Vec::with_capacity(batch_size);
        let mut pair = vec![F::ZERO; 2 * size];
        let (left, right) = pair.split_at_mut(size);
        for _ in 0..R::num_coeffs() {
            let left_nonzero = self.fill_row(left, &mut a);
            let right_nonzero = self.fill_row(right, &mut b);
            if left_nonzero && right_nonzero {
                batch.extend_from_slice(left);
                batch.extend_from_slice(right);
                if batch.len() == batch_size {
                    self.accumulate::<B>(&mut batch, &mut products);
                }
            }
        }
        if !batch.is_empty() {
            self.accumulate::<B>(&mut batch, &mut products);
        }
        products.into_iter().map(F::reduce)
    }

    pub(super) fn compute<B: Backend, R: Rank>(
        &self,
        a: &[impl Borrow<Polynomial<F, R>>],
        b: &[impl Borrow<Polynomial<F, R>>],
    ) -> Vec<F> {
        let m = self.barycentric.len();
        let empty = |poly: &Polynomial<F, R>| poly.iter_stored_coeffs().next().is_none();
        if a.iter().all(|poly| empty(poly.borrow())) || b.iter().all(|poly| empty(poly.borrow())) {
            return vec![F::ZERO; m - 1];
        }
        let pairs = a.iter().zip(b).map(|(a, b)| (a.borrow(), b.borrow()));
        let diagonal: Vec<_> = B::map(pairs, |(a, b)| B::sparse_revdot(a, b))
            .zip(&self.barycentric)
            .map(|(value, &weight)| value * weight)
            .collect();
        let mut quotient = vec![F::ZERO; m - 1];
        for (offset, product) in self.shifted_products::<B, R>(a, b).enumerate() {
            let target: F = diagonal
                .iter()
                .enumerate()
                .map(|(i, &value)| value * self.kernel[m - 1 + offset - i])
                .sum();
            // The convolutions yield A(t)/Z(t) and B(t)/Z(t).
            let value = self.vanishing[offset] * product - target;
            for (coefficient, &weight) in quotient.iter_mut().zip(&self.output_basis[offset]) {
                *coefficient += value * weight;
            }
        }
        quotient
    }
}
