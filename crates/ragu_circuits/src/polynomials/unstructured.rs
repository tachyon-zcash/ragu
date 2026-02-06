//! Polynomials with coefficients in an unstructured (monomial basis)
//! arrangement.

use arithmetic::CurveAffine;
use ff::Field;
use rand::CryptoRng;

use alloc::{vec, vec::Vec};
use core::ops::{AddAssign, Deref, DerefMut};

use super::Rank;

/// Represents a polynomial in an unstructured (monomial basis) arrangement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial<F: Field, R: Rank> {
    /// Coefficients of the polynomial.
    pub(super) coeffs: Vec<F>,
    pub(super) _marker: core::marker::PhantomData<R>,
}

impl<F: Field, R: Rank> Deref for Polynomial<F, R> {
    type Target = [F];

    fn deref(&self) -> &Self::Target {
        &self.coeffs
    }
}

impl<F: Field, R: Rank> DerefMut for Polynomial<F, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.coeffs
    }
}

impl<F: Field, R: Rank> Default for Polynomial<F, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, R: Rank> Polynomial<F, R> {
    /// Create a new (zero) polynomial.
    pub fn new() -> Self {
        Self {
            coeffs: vec![F::ZERO; R::num_coeffs()],
            _marker: core::marker::PhantomData,
        }
    }

    /// Creates a new polynomial with random coefficients.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        let mut coeffs = Vec::with_capacity(R::num_coeffs());
        for _ in 0..R::num_coeffs() {
            coeffs.push(F::random(&mut *rng));
        }
        Self {
            coeffs,
            _marker: core::marker::PhantomData,
        }
    }

    /// Create a polynomial from the given coefficients. Panics if the number of
    /// coefficients exceeds the rank's limit.
    pub fn from_coeffs(mut coeffs: Vec<F>) -> Self {
        assert!(coeffs.len() <= R::num_coeffs());
        coeffs.resize(R::num_coeffs(), F::ZERO);
        Self {
            coeffs,
            _marker: core::marker::PhantomData,
        }
    }

    /// Iterate over the coefficients of this polynomial in ascending order of
    /// degree.
    pub fn iter_coeffs(&self) -> impl DoubleEndedIterator<Item = F> {
        self.coeffs.iter().cloned()
    }

    /// Evaluate this polynomial at the given point.
    pub fn eval(&self, x: F) -> F {
        arithmetic::eval(&self.coeffs[..], x)
    }

    /// Scale the coefficients of the polynomial by the given factor.
    pub fn scale(&mut self, by: F) {
        self.coeffs.iter_mut().for_each(|coeff| {
            *coeff *= by;
        });
    }

    /// Add another unstructured polynomial to this one.
    pub fn add_unstructured(&mut self, other: &Self) {
        assert_eq!(self.coeffs.len(), R::num_coeffs());
        assert_eq!(other.coeffs.len(), R::num_coeffs());

        self.coeffs
            .iter_mut()
            .zip(other.coeffs.iter())
            .for_each(|(a, b)| *a += b);
    }

    /// Adds a structured polynomial to this unstructured polynomial.
    pub fn add_structured(&mut self, other: &super::structured::Polynomial<F, R>) {
        let v_len = other.v.len();
        let d_len = other.d.len();

        assert_eq!(self.coeffs.len(), R::num_coeffs());
        assert!(other.u.len() <= R::n());
        assert!(v_len <= R::n());
        assert!(other.w.len() <= R::n());
        assert!(d_len <= R::n());

        let mut cursor = &mut self.coeffs[..];
        cursor
            .iter_mut()
            .zip(other.w.iter())
            .for_each(|(coeff, val)| *coeff += val);
        cursor = &mut cursor[R::n() * 2 - v_len..];
        cursor
            .iter_mut()
            .zip(other.v.iter().rev().chain(other.u.iter()))
            .for_each(|(coeff, val)| *coeff += val);
        cursor = &mut cursor[R::n() * 2 + v_len - d_len..];
        cursor
            .iter_mut()
            .zip(other.d.iter().rev())
            .for_each(|(coeff, val)| *coeff += val);
    }

    /// Compute a commitment to this polynomial using the provided generators.
    pub fn commit<C: CurveAffine<ScalarExt = F>>(
        &self,
        generators: &impl arithmetic::FixedGenerators<C>,
        blind: F,
    ) -> C {
        assert!(generators.g().len() >= R::num_coeffs()); // TODO(ebfull)

        arithmetic::mul(
            self.coeffs.iter().chain(Some(&blind)),
            generators
                .g()
                .iter()
                .take(self.coeffs.len())
                .chain(Some(generators.h())),
        )
        .into() // TODO(ebfull)
    }
}

impl<F: Field, R: Rank> AddAssign<&Self> for Polynomial<F, R> {
    fn add_assign(&mut self, rhs: &Self) {
        self.add_unstructured(rhs);
    }
}

impl<F: Field, R: Rank> AddAssign<&super::structured::Polynomial<F, R>> for Polynomial<F, R> {
    fn add_assign(&mut self, rhs: &super::structured::Polynomial<F, R>) {
        self.add_structured(rhs);
    }
}

#[test]
fn test_add_structured() {
    use ragu_pasta::Fp;

    type R = super::R<13>;

    let p = super::structured::Polynomial::<Fp, R>::random(&mut rand::rng());

    let mut q = super::structured::Polynomial::<Fp, R>::new();
    for i in 0..R::n() {
        if i % 7 == 0 {
            q.u.push(Fp::random(&mut rand::rng()));
        }
        if i % 5 == 0 {
            q.v.push(Fp::random(&mut rand::rng()));
        }
        if i % 3 == 0 {
            q.w.push(Fp::random(&mut rand::rng()));
        }
        if i % 2 == 0 {
            q.d.push(Fp::random(&mut rand::rng()));
        }
    }

    let mut expected = p.unstructured();
    expected.add_structured(&q);

    let mut computed = p;
    computed.add_assign(&q);
    let computed = computed.unstructured();

    assert_eq!(expected.coeffs, computed.coeffs);
}
