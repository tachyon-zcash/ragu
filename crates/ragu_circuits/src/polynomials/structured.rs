//! Polynomials with coefficients in a split structure arrangement.

use arithmetic::CurveAffine;
use ff::Field;
use rand::Rng;

use alloc::vec::Vec;

use super::Rank;

/// Represents the $2^k = 4n$ coefficients of a polynomial for a particular
/// [`Rank`] as four (sparse) vectors $\mathbf{a}, \mathbf{b}, \mathbf{c},
/// \mathbf{d} \in \mathbb{F}^n$.
///
/// The represented polynomial is given by
///
/// $$ p(X) = \sum_{i=0}^{n-1} \big( \mathbf{c}_i X^{i} + \mathbf{b}_i
/// X^{2n-1-i} + \mathbf{a}_i X^{2n+i} + \mathbf{d}_i X^{4n - 1 - i} \big) $$
///
/// such that when the coefficients are reversed, the resulting polynomial is
/// represented by the same vectors with $\mathbf{a}$ swapped with $\mathbf{b}$,
/// and $\mathbf{c}$ swapped with $\mathbf{d}$.
///
/// ## Usage
///
/// Given a [`Polynomial`] you can obtain a [`View`] of the polynomial from the
/// standard perspective using [`Polynomial::forward`], which exposes only the
/// $\mathbf{a}, \mathbf{b}, \mathbf{c}$ coefficient vectors. Alternatively, you
/// can obtain a view of the polynomial with its coefficients reversed. Only
/// using a [`View`] can the coefficient vectors be accessed and mutated.
#[derive(Clone, Debug)]
pub struct Polynomial<F: Field, R: Rank> {
    // Note: We use `u`, `v`, `w`, and `d` to represent the coefficient vectors
    // in the general polynomial so they cannot be confused with the vectors in
    // the structured `View`.
    //
    // In the forward perspective, a -> u, b -> v, c -> w, and in the backward
    // perspective, a -> v, b -> u, c -> d.
    pub(super) u: Vec<F>,
    pub(super) v: Vec<F>,
    pub(super) w: Vec<F>,
    pub(super) d: Vec<F>,
    _marker: core::marker::PhantomData<R>,
}

impl<F: Field, R: Rank> arithmetic::Ring for Polynomial<F, R> {
    type R = Self;
    type F = F;

    fn scale_assign(r: &mut Self, by: Self::F) {
        r.scale(by);
    }
    fn add_assign(r: &mut Self, other: &Self) {
        Self::add_assign(r, other);
    }
    fn sub_assign(r: &mut Self, other: &Self) {
        Self::sub_assign(r, other);
    }
}

impl<F: Field, R: Rank> Default for Polynomial<F, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, R: Rank> Polynomial<F, R> {
    /// Creates a new polynomial with empty coefficient vectors.
    pub fn new() -> Self {
        Self {
            u: Vec::new(),
            v: Vec::new(),
            w: Vec::new(),
            d: Vec::new(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Creates a new polynomial with random coefficients.
    pub fn random<RNG: Rng>(rng: &mut RNG) -> Self {
        let mut u = Vec::with_capacity(R::n());
        let mut v = Vec::with_capacity(R::n());
        let mut w = Vec::with_capacity(R::n());
        let mut d = Vec::with_capacity(R::n());

        for _ in 0..R::n() {
            u.push(F::random(&mut *rng));
            v.push(F::random(&mut *rng));
            w.push(F::random(&mut *rng));
            d.push(F::random(&mut *rng));
        }

        Self {
            u,
            v,
            w,
            d,
            _marker: core::marker::PhantomData,
        }
    }

    /// Folds an iterator of polynomials into a single polynomial with
    /// successive powers of the provided scale factor.
    pub fn fold<I, P>(polys: I, scale_factor: F) -> Self
    where
        I: DoubleEndedIterator<Item = P>,
        P: core::ops::Deref<Target = Self>,
    {
        polys.rev().fold(Self::default(), |mut acc, poly| {
            acc.scale(scale_factor);
            acc.add_assign(&*poly);
            acc
        })
    }

    /// Iterate over the coefficients of this polynomial in ascending order of
    /// degree.
    pub fn iter_coeffs(&self) -> impl DoubleEndedIterator<Item = F> {
        use core::iter::repeat_n;

        assert!(self.u.len() <= R::n());
        assert!(self.v.len() <= R::n());
        assert!(self.w.len() <= R::n());
        assert!(self.d.len() <= R::n());

        self.w
            .iter()
            .cloned()
            .chain(repeat_n(F::ZERO, self.first_padding()))
            .chain(self.v.iter().rev().cloned())
            .chain(self.u.iter().cloned())
            .chain(repeat_n(F::ZERO, self.second_padding()))
            .chain(self.d.iter().rev().cloned())
    }

    /// Inner product of `self` with the reversed `other`.
    pub fn revdot(&self, other: &Self) -> F {
        self.u
            .iter()
            .zip(other.v.iter())
            .chain(self.v.iter().zip(other.u.iter()))
            .chain(self.w.iter().zip(other.d.iter()))
            .chain(self.d.iter().zip(other.w.iter()))
            .fold(F::ZERO, |acc, (a, b)| acc + (*a * *b))
    }

    /// Add the coefficients of `other` to `self`.
    pub fn add_assign(&mut self, other: &Self) {
        self.combine_assign_all(other, |a, b| *a += *b);
    }

    /// Subtract the coefficients of `other` from `self`.
    pub fn sub_assign(&mut self, other: &Self) {
        self.combine_assign_all(other, |a, b| *a -= *b);
    }

    /// Negate the coefficients of this polynomial.
    pub fn negate(&mut self) {
        self.apply_all(|coeff| *coeff = -*coeff);
    }

    /// Scale the coefficients of the polynomial by the given factor.
    pub fn scale(&mut self, by: F) {
        self.apply_all(|coeff| *coeff *= by);
    }

    /// Returns a mutable reference to the constant term of the polynomial.
    pub fn constant_term(&mut self) -> &mut F {
        if self.w.is_empty() {
            self.w.push(F::ZERO);
        }
        &mut self.w[0]
    }

    /// Transforms this polynomial from $p(X)$ to $p(zX)$ for $z \in \mathbb{F}$.
    pub fn dilate(&mut self, z: F) {
        assert!(self.u.len() <= R::n());
        assert!(self.v.len() <= R::n());
        assert!(self.w.len() <= R::n());
        assert!(self.d.len() <= R::n());

        let mut cur = F::ONE;
        for c in self.w.iter_mut() {
            *c *= cur;
            cur *= z;
        }
        cur *= z.pow_vartime([self.first_padding() as u64]);
        for b in self.v.iter_mut().rev() {
            *b *= cur;
            cur *= z;
        }
        for a in self.u.iter_mut() {
            *a *= cur;
            cur *= z;
        }
        cur *= z.pow_vartime([self.second_padding() as u64]);
        for d in self.d.iter_mut().rev() {
            *d *= cur;
            cur *= z;
        }
    }

    /// Evaluate this polynomial at a point `z`.
    pub fn eval(&self, z: F) -> F {
        assert!(self.u.len() <= R::n());
        assert!(self.v.len() <= R::n());
        assert!(self.w.len() <= R::n());
        assert!(self.d.len() <= R::n());

        let mut result = F::ZERO;

        let mut cur = F::ONE;
        for c in self.w.iter() {
            result += *c * cur;
            cur *= z;
        }
        cur *= z.pow_vartime([self.first_padding() as u64]);
        for b in self.v.iter().rev() {
            result += *b * cur;
            cur *= z;
        }
        for a in self.u.iter() {
            result += *a * cur;
            cur *= z;
        }
        cur *= z.pow_vartime([self.second_padding() as u64]);
        for d in self.d.iter().rev() {
            result += *d * cur;
            cur *= z;
        }

        result
    }

    /// Compute a commitment to this polynomial using the provided generators.
    pub fn commit<C: CurveAffine<ScalarExt = F>>(
        &self,
        generators: &impl arithmetic::FixedGenerators<C>,
        blind: F,
    ) -> C {
        assert!(self.u.len() <= R::n());
        assert!(self.v.len() <= R::n());
        assert!(self.w.len() <= R::n());
        assert!(self.d.len() <= R::n());

        assert!(generators.g().len() >= R::num_coeffs()); // TODO(ebfull)

        let w_start = generators.g();
        let v_start = &w_start[self.w.len() + self.first_padding()..];
        let u_start = &v_start[self.v.len()..];
        let d_start = &u_start[self.u.len() + self.second_padding()..];

        arithmetic::mul(
            self.w
                .iter()
                .chain(self.v.iter().rev())
                .chain(self.u.iter())
                .chain(self.d.iter().rev())
                .chain(Some(&blind)),
            w_start
                .iter()
                .take(self.w.len())
                .chain(v_start.iter().take(self.v.len()))
                .chain(u_start.iter().take(self.u.len()))
                .chain(d_start.iter().take(self.d.len()))
                .chain(Some(generators.h())),
        )
        .into() // TODO(ebfull)
    }

    /// Reduce this polynomial into its unstructured representation,
    pub fn unstructured(&self) -> super::unstructured::Polynomial<F, R> {
        super::unstructured::Polynomial {
            coeffs: self.iter_coeffs().collect(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Helper function to apply an operation to all coefficients.
    fn apply_all<Op>(&mut self, op: Op)
    where
        Op: Fn(&mut F),
    {
        self.u.iter_mut().for_each(&op);
        self.v.iter_mut().for_each(&op);
        self.w.iter_mut().for_each(&op);
        self.d.iter_mut().for_each(&op);
    }

    /// Helper function to combine two polynomials with a binary operation.
    fn combine_assign_all<Op>(&mut self, other: &Self, mut op: Op)
    where
        Op: FnMut(&mut F, &F),
    {
        Self::combine_assign(&mut self.u, &other.u, &mut op);
        Self::combine_assign(&mut self.v, &other.v, &mut op);
        Self::combine_assign(&mut self.w, &other.w, &mut op);
        Self::combine_assign(&mut self.d, &other.d, &mut op);
    }

    /// Helper function to combine coefficient vectors with a binary operation.
    fn combine_assign<Op>(a: &mut Vec<F>, b: &[F], mut op: Op)
    where
        Op: FnMut(&mut F, &F),
    {
        if a.len() < b.len() {
            a.resize(b.len(), F::ZERO);
        }

        for (a_coeff, b_coeff) in a.iter_mut().zip(b.iter()) {
            op(a_coeff, b_coeff);
        }
    }

    /// The first padding space between the `w` and `v` vectors.
    fn first_padding(&self) -> usize {
        R::n() * 2 - self.w.len() - self.v.len()
    }

    /// The second padding space between the `u` and `d` vectors.
    fn second_padding(&self) -> usize {
        R::n() * 2 - self.u.len() - self.d.len()
    }
}

/// Marker trait for distinguishing between different polynomial views.
pub trait Perspective {}

/// Unaltered perspective of the polynomial.
pub struct Forward;

/// Perspective of the polynomial with coefficients reversed.
pub struct Backward;

impl Perspective for Forward {}
impl Perspective for Backward {}

/// Represents a view of a [`Polynomial`] from a specific perspective.
///
/// The caller is responsible for ensuring that none of the exposed vectors
/// exceed [`A::n()`](super::Rank::n) in length.
pub struct View<'a, F, R: Rank, M: Perspective> {
    /// The A wires of multiplication gates.
    pub a: &'a mut Vec<F>,

    /// The B wires of multiplication gates.
    pub b: &'a mut Vec<F>,

    /// The C wires of multiplication gates.
    pub c: &'a mut Vec<F>,

    _marker: core::marker::PhantomData<(R, M)>,
}

impl<F: Field, R: Rank> Polynomial<F, R> {
    /// Obtain a view of the polynomial from the forward perspective.
    pub fn forward(&mut self) -> View<F, R, Forward> {
        View {
            a: &mut self.u,
            b: &mut self.v,
            c: &mut self.w,
            _marker: core::marker::PhantomData,
        }
    }

    /// Obtain a view of the polynomial from the backward perspective.
    pub fn backward(&mut self) -> View<F, R, Backward> {
        // a and b are swapped, c and d are swapped
        View {
            a: &mut self.v,
            b: &mut self.u,
            c: &mut self.d,
            _marker: core::marker::PhantomData,
        }
    }
}

#[test]
fn test_eval() {
    use ragu_pasta::Fp;
    use rand::thread_rng;

    type R = super::R<6>;

    for insertions in 0..R::n() {
        let mut poly = Polynomial::<Fp, R>::new();
        for _ in 0..insertions {
            poly.u.push(Fp::random(thread_rng()));
            poly.v.push(Fp::random(thread_rng()));
            poly.w.push(Fp::random(thread_rng()));
            poly.d.push(Fp::random(thread_rng()));
        }

        let x = Fp::random(thread_rng());

        assert_eq!(
            arithmetic::eval(&poly.unstructured().coeffs, x),
            poly.eval(x)
        );
    }
}

#[test]
fn test_backward_forward() {
    use ragu_pasta::Fp;

    type R = super::R<7>;

    for insertions in 0..R::n() {
        let mut poly = Polynomial::<Fp, R>::new();
        let forward_view = poly.forward();
        for i in 0..insertions {
            let a = Fp::from((i + 1) as u64);
            let b = Fp::from((i + 10001) as u64);
            let c = Fp::from((i + 20001) as u64);
            forward_view.a.push(a);
            forward_view.b.push(b);
            forward_view.c.push(c);
        }
        drop(forward_view);

        let unstructured1 = poly.unstructured();
        assert_eq!(unstructured1.coeffs.len(), R::num_coeffs());

        let mut poly = Polynomial::<Fp, R>::new();
        let backward_view = poly.backward();
        for i in 0..insertions {
            let a = Fp::from((i + 1) as u64);
            let b = Fp::from((i + 10001) as u64);
            let c = Fp::from((i + 20001) as u64);
            backward_view.a.push(a);
            backward_view.b.push(b);
            backward_view.c.push(c);
        }
        drop(backward_view);

        let mut unstructured2 = poly.unstructured();
        assert_eq!(unstructured2.coeffs.len(), R::num_coeffs());
        unstructured2.coeffs.reverse();

        assert_eq!(unstructured1.coeffs, unstructured2.coeffs);
    }
}

#[test]
fn test_dilate() {
    use ragu_pasta::Fp;
    use rand::thread_rng;

    type R = super::R<5>;

    for insertions_a in 0..R::n() {
        for insertions_b in 0..R::n() {
            for insertions_c in 0..R::n() {
                for insertions_d in 0..R::n() {
                    let mut poly = Polynomial::<Fp, R>::new();
                    for _ in 0..insertions_a {
                        poly.u.push(Fp::random(thread_rng()));
                    }
                    for _ in 0..insertions_b {
                        poly.v.push(Fp::random(thread_rng()));
                    }
                    for _ in 0..insertions_c {
                        poly.w.push(Fp::random(thread_rng()));
                    }
                    for _ in 0..insertions_d {
                        poly.d.push(Fp::random(thread_rng()));
                    }
                    let x = Fp::random(thread_rng());
                    let z = Fp::random(thread_rng());
                    let upoly = poly.unstructured();
                    poly.dilate(z);
                    let vpoly = poly.unstructured();
                    assert_eq!(
                        arithmetic::eval(&upoly.coeffs, x * z),
                        arithmetic::eval(&vpoly.coeffs, x)
                    );
                }
            }
        }
    }
}

#[test]
fn test_negate() {
    use ragu_pasta::Fp;
    use rand::thread_rng;

    type R = super::R<6>;

    for insertions in 0..R::n() {
        let mut poly = Polynomial::<Fp, R>::new();
        for _ in 0..insertions {
            poly.u.push(Fp::random(thread_rng()));
            poly.v.push(Fp::random(thread_rng()));
            poly.w.push(Fp::random(thread_rng()));
            poly.d.push(Fp::random(thread_rng()));
        }

        let original = poly.clone();
        poly.negate();

        assert_eq!(poly.u.len(), original.u.len());
        assert_eq!(poly.v.len(), original.v.len());
        assert_eq!(poly.w.len(), original.w.len());
        assert_eq!(poly.d.len(), original.d.len());

        for (negated, orig) in poly.u.iter().zip(original.u.iter()) {
            assert_eq!(*negated, -*orig);
        }
        for (negated, orig) in poly.v.iter().zip(original.v.iter()) {
            assert_eq!(*negated, -*orig);
        }
        for (negated, orig) in poly.w.iter().zip(original.w.iter()) {
            assert_eq!(*negated, -*orig);
        }
        for (negated, orig) in poly.d.iter().zip(original.d.iter()) {
            assert_eq!(*negated, -*orig);
        }

        let x = Fp::random(thread_rng());
        assert_eq!(poly.eval(x), -original.eval(x));
    }
}

#[test]
fn test_constant_term() {
    use ragu_pasta::Fp;
    use rand::thread_rng;

    type R = super::R<6>;

    let mut poly = Polynomial::<Fp, R>::new();
    let random_value = Fp::random(thread_rng());

    *poly.constant_term() = random_value;

    let unstructured = poly.unstructured();

    assert_eq!(unstructured.coeffs.len(), R::num_coeffs());
    assert_eq!(unstructured.coeffs[0], random_value);
}

#[test]
fn test_prod() {
    use ragu_pasta::Fp;
    use rand::thread_rng;

    type R = super::R<7>;

    let mut rx = Polynomial::<Fp, R>::new();
    {
        let rx = rx.forward();
        for _ in 0..R::n() {
            let a = Fp::random(thread_rng());
            let b = Fp::random(thread_rng());

            rx.a.push(a);
            rx.b.push(b);
            rx.c.push(a * b);
        }
    }

    let mut rzx = rx.clone();
    let z = Fp::random(thread_rng());
    rzx.dilate(z);
    rzx.add_assign(&R::tz::<Fp>(z));

    let a = rx.unstructured().coeffs;
    let mut b = rzx.unstructured().coeffs;
    b.reverse();

    assert_eq!(arithmetic::dot(&a, &b), Fp::ZERO);
}

#[test]
fn test_commit_consistency() {
    use arithmetic::Cycle;
    use ragu_pasta::{Fp, Pasta};
    use rand::thread_rng;

    type R = super::R<10>;

    let pasta = Pasta::baked();
    let generators = pasta.host_generators();

    let blind = Fp::random(thread_rng());

    let mut poly = Polynomial::<Fp, R>::new();

    for _ in 0..R::n() / 4 {
        poly.u.push(Fp::random(thread_rng()));
    }
    for _ in 0..R::n() / 3 {
        poly.v.push(Fp::random(thread_rng()));
    }
    for _ in 0..R::n() / 2 {
        poly.w.push(Fp::random(thread_rng()));
    }
    for _ in 0..R::n() {
        poly.d.push(Fp::random(thread_rng()));
    }

    let structured_commitment = poly.commit(generators, blind);
    let unstructured_commitment = poly.unstructured().commit(generators, blind);

    assert_eq!(structured_commitment, unstructured_commitment);
}

#[test]
fn test_product_with_dot() {
    use ragu_pasta::Fp;
    use rand::thread_rng;

    type R = super::R<5>;

    let mut poly1 = Polynomial::<Fp, R>::new();
    let mut poly2 = Polynomial::<Fp, R>::new();

    for _ in 0..3 {
        poly1.u.push(Fp::random(thread_rng()));
    }
    for _ in 0..5 {
        poly1.v.push(Fp::random(thread_rng()));
    }
    for _ in 0..7 {
        poly1.w.push(Fp::random(thread_rng()));
    }
    for _ in 0..2 {
        poly1.d.push(Fp::random(thread_rng()));
    }

    for _ in 0..4 {
        poly2.u.push(Fp::random(thread_rng()));
    }
    for _ in 0..6 {
        poly2.v.push(Fp::random(thread_rng()));
    }
    for _ in 0..1 {
        poly2.w.push(Fp::random(thread_rng()));
    }
    for _ in 0..8 {
        poly2.d.push(Fp::random(thread_rng()));
    }

    assert_eq!(
        poly1.revdot(&poly2),
        arithmetic::dot(
            poly1.unstructured().iter(),
            poly2.unstructured().iter().rev(),
        )
    );
}

#[test]
fn ring_poly_test() {
    use ragu_pasta::Fp;
    use rand::thread_rng;

    type R = super::R<5>;

    let rand = || Fp::random(thread_rng());

    let little = arithmetic::Domain::<Fp>::new(2);
    let big = arithmetic::Domain::<Fp>::new(3);

    let mut a_polys = vec![];
    let mut b_polys = vec![];

    for _ in 0..4 {
        let mut tmp = Polynomial::<Fp, R>::new();
        for _ in 0..8 {
            tmp.u.push(rand());
            tmp.v.push(rand());
            tmp.w.push(rand());
            tmp.d.push(rand());
        }
        a_polys.push(tmp);
    }

    for _ in 0..4 {
        let mut tmp = Polynomial::<Fp, R>::new();
        for _ in 0..8 {
            tmp.u.push(rand());
            tmp.v.push(rand());
            tmp.w.push(rand());
            tmp.d.push(rand());
        }
        b_polys.push(tmp);
    }

    let mut c = vec![];
    for i in 0..4 {
        c.push(a_polys[i].revdot(&b_polys[i]));
    }

    little.ring_ifft::<Polynomial<Fp, R>>(&mut a_polys);
    let a_polys_collapse = a_polys.clone();
    a_polys.resize(8, Default::default());
    big.ring_fft::<Polynomial<Fp, R>>(&mut a_polys);

    little.ring_ifft::<Polynomial<Fp, R>>(&mut b_polys);
    let b_polys_collapse = b_polys.clone();
    b_polys.resize(8, Default::default());
    big.ring_fft::<Polynomial<Fp, R>>(&mut b_polys);

    let mut big_c = vec![];
    for i in 0..8 {
        big_c.push(a_polys[i].revdot(&b_polys[i]));
    }

    big.ifft(&mut big_c);

    let x = rand();

    let mut cur = Fp::ONE;
    let mut a = Polynomial::<Fp, R>::new();
    let mut b = Polynomial::<Fp, R>::new();
    for i in 0..4 {
        let mut tmp = a_polys_collapse[i].clone();
        tmp.scale(cur);
        a.add_assign(&tmp);

        let mut tmp = b_polys_collapse[i].clone();
        tmp.scale(cur);
        b.add_assign(&tmp);

        cur *= x;
    }
    let mut cur = Fp::ONE;
    let mut cx = Fp::ZERO;
    for i in 0..8 {
        cx += big_c[i] * cur;
        cur *= x;
    }

    assert_eq!(a.revdot(&b), cx);
}
