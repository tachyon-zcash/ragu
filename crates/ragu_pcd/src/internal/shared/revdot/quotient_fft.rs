use alloc::{vec, vec::Vec};
use core::borrow::Borrow;

use ragu_backend::Backend;
use ragu_circuits::polynomials::{Rank, sparse::Polynomial};
use udon::{
    fft::{Domain, reference},
    field::Field,
};

#[derive(Clone, Copy)]
struct Twiddle<F>(F);

impl<F: Field> reference::Twiddle for Twiddle<F> {
    const ONE: Self = Self(F::ONE);

    fn multiply(&self, rhs: &Self) -> Self {
        Self(self.0 * rhs.0)
    }

    fn square(&self) -> Self {
        Self(self.0.square())
    }
}

#[derive(Clone)]
struct Coefficients<F: Field, R: Rank>(Polynomial<F, R>);

impl<F: Field, R: Rank> reference::Butterfly<Twiddle<F>> for Coefficients<F, R> {
    fn scaled(&self, by: &Twiddle<F>) -> Self {
        let mut poly = self.clone();
        poly.0.scale(by.0);
        poly
    }

    fn add(&self, rhs: &Self) -> Self {
        let mut poly = self.clone();
        poly.0.add_assign(&rhs.0);
        poly
    }

    fn negated(&self) -> Self {
        self.scaled(&Twiddle(-F::ONE))
    }
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

    fn shift<R: Rank>(&self, input: &[impl Borrow<Polynomial<F, R>>]) -> Vec<Coefficients<F, R>> {
        let mut values: Vec<_> = input
            .iter()
            .zip(&self.barycentric)
            .map(|(value, &weight)| {
                let mut value = value.borrow().clone();
                value.scale(weight);
                Coefficients(value)
            })
            .collect();
        values.resize_with(self.domain.size(), || Coefficients(Polynomial::default()));
        reference::transform(&mut values, &Twiddle(self.domain.root()));
        for (value, &weight) in values.iter_mut().zip(&self.spectrum) {
            value.0.scale(weight);
        }
        reference::inverse_transform(
            &mut values,
            &Twiddle(self.domain.inverse_root()),
            &Twiddle(self.domain.size_inverse()),
        );
        values
    }

    pub(super) fn compute<B: Backend, R: Rank>(
        &self,
        a: &[impl Borrow<Polynomial<F, R>>],
        b: &[impl Borrow<Polynomial<F, R>>],
    ) -> Vec<F> {
        let m = self.barycentric.len();
        let pairs = a.iter().zip(b).map(|(a, b)| (a.borrow(), b.borrow()));
        let diagonal: Vec<_> = B::map(pairs, |(a, b)| B::sparse_revdot(a, b))
            .zip(&self.barycentric)
            .map(|(value, &weight)| value * weight)
            .collect();
        let a = self.shift(a);
        let b = self.shift(b);
        let products = B::map(m - 1..2 * m - 2, |index| {
            B::sparse_revdot(&a[index].0, &b[index].0)
        });

        let mut quotient = vec![F::ZERO; m - 1];
        for (offset, product) in products.enumerate() {
            let target: F = diagonal
                .iter()
                .enumerate()
                .map(|(i, &value)| value * self.kernel[m - 1 + offset - i])
                .sum();
            // The convolutions yield A(t)/Z(t) and B(t)/Z(t). Their retained
            // coefficients start at m-1, beyond the reach of wraparound.
            let value = self.vanishing[offset] * product - target;
            for (coefficient, &weight) in quotient.iter_mut().zip(&self.output_basis[offset]) {
                *coefficient += value * weight;
            }
        }
        quotient
    }
}
