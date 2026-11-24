use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, iter::Peekable, ops::Range};

use ragu_backend::Backend;
use ragu_circuits::polynomials::{Rank, sparse::Polynomial};
use udon::{fft::Domain, field::Field};

/// Keep working storage bounded while giving the backend many independent FFTs.
const COEFFICIENT_PAIRS_PER_BATCH: usize = 256;

fn merged_support<'a, F: 'a>(
    polynomials: &[impl Iterator<Item = (usize, &'a [F])> + Clone],
) -> Vec<Range<usize>> {
    let mut ranges = polynomials
        .iter()
        .flat_map(|blocks| blocks.clone())
        .map(|(start, coefficients)| start..start + coefficients.len())
        .collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
}

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

    fn fill_rows<'a, const REVERSED: bool>(
        &self,
        window: Range<usize>,
        polynomials: &mut [Peekable<impl Iterator<Item = (usize, &'a [F])>>],
        batch: &mut [F],
        present: &mut [u8],
    ) {
        let size = self.domain.size();
        let stride = 2 * size;
        let lane = usize::from(REVERSED) * size;
        let side = if REVERSED { 0b10 } else { 0b01 };

        for (column, (blocks, &weight)) in polynomials.iter_mut().zip(&self.barycentric).enumerate()
        {
            while let Some(&(start, coefficients)) = blocks.peek() {
                if start >= window.end {
                    break;
                }
                let end = start + coefficients.len();
                for index in start.max(window.start)..end.min(window.end) {
                    let offset = index - start;
                    let value = if REVERSED {
                        coefficients[coefficients.len() - 1 - offset]
                    } else {
                        coefficients[offset]
                    };
                    if !value.is_zero() {
                        let row = index - window.start;
                        batch[row * stride + lane + column] = value * weight;
                        present[row] |= side;
                    }
                }
                if end > window.end {
                    break;
                }
                blocks.next();
            }
        }
    }

    fn accumulate<B: Backend>(
        &self,
        batch: &mut Vec<F>,
        present: &mut Vec<u8>,
        products: &mut [F::Accumulator],
    ) {
        let size = self.domain.size();
        let stride = 2 * size;
        // Short zero runs can live inside stored blocks. Remove rows with
        // no nonzero coefficient on either side before transforming them.
        let mut active = 0;
        for (row, side) in present.drain(..).enumerate() {
            if side == 0b11 {
                if active != row {
                    batch.copy_within(row * stride..(row + 1) * stride, active * stride);
                }
                active += 1;
            }
        }
        batch.truncate(active * stride);
        if batch.is_empty() {
            return;
        }
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
        let mut a: Vec<_> = a
            .iter()
            .map(|poly| poly.borrow().iter_stored_blocks().peekable())
            .collect();
        let mut b: Vec<_> = b
            .iter()
            .map(|poly| {
                poly.borrow()
                    .iter_stored_blocks()
                    .rev()
                    .map(|(start, coefficients)| {
                        (R::num_coeffs() - start - coefficients.len(), coefficients)
                    })
                    .peekable()
            })
            .collect();
        let mut a_support = merged_support(&a).into_iter().peekable();
        let mut b_support = merged_support(&b).into_iter().peekable();
        let mut products: Vec<_> = (0..self.vanishing.len())
            .map(|_| F::Accumulator::default())
            .collect();
        let stride = 2 * self.domain.size();
        let mut batch = Vec::with_capacity(stride * COEFFICIENT_PAIRS_PER_BATCH);
        let mut present = Vec::with_capacity(COEFFICIENT_PAIRS_PER_BATCH);
        while let (Some(left), Some(right)) = (a_support.peek(), b_support.peek()) {
            let mut start = left.start.max(right.start);
            let end = left.end.min(right.end);
            let advance_left = left.end <= right.end;
            let advance_right = right.end <= left.end;
            while start < end {
                let offset = present.len();
                let count = (end - start).min(COEFFICIENT_PAIRS_PER_BATCH - offset);
                let window = start..start + count;
                batch.resize((offset + count) * stride, F::ZERO);
                present.resize(offset + count, 0);
                self.fill_rows::<false>(
                    window.clone(),
                    &mut a,
                    &mut batch[offset * stride..],
                    &mut present[offset..],
                );
                self.fill_rows::<true>(
                    window,
                    &mut b,
                    &mut batch[offset * stride..],
                    &mut present[offset..],
                );
                if present.len() == COEFFICIENT_PAIRS_PER_BATCH {
                    self.accumulate::<B>(&mut batch, &mut present, &mut products);
                }
                start += count;
            }
            if advance_left {
                a_support.next();
            }
            if advance_right {
                b_support.next();
            }
        }
        if !batch.is_empty() {
            self.accumulate::<B>(&mut batch, &mut present, &mut products);
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
