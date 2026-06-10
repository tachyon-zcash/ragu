use alloc::{boxed::Box, vec, vec::Vec};

use crate::{
    domain::Domain,
    ff::{Field, PrimeField},
    multicore::*,
    pasta_curves::{
        arithmetic::CurveAffine,
        group::{Curve, Group},
    },
};

/// Returns the low 64 bits of a [`PrimeField`] element's canonical
/// little-endian representation.
///
/// # Panics
///
/// Panics if the field's canonical representation is shorter than 8 bytes.
pub fn low_u64<F: PrimeField>(f: &F) -> u64 {
    let repr = f.to_repr();
    let bytes = repr.as_ref();
    u64::from_le_bytes(
        bytes[..8]
            .try_into()
            .expect("field repr is at least 8 bytes"),
    )
}

/// Evaluates a polynomial $p \in \mathbb{F}\[X]$ at a point $x \in \mathbb{F}$,
/// where $p$ is defined by `coeffs` in ascending order of degree.
pub fn eval<'a, F: Field, I: IntoIterator<Item = &'a F>>(coeffs: I, x: F) -> F
where
    I::IntoIter: DoubleEndedIterator,
{
    let mut result = F::ZERO;
    for coeff in coeffs.into_iter().rev() {
        result *= x;
        result += *coeff;
    }
    result
}

/// Computes $\langle \mathbf{a} , \mathbf{b} \rangle$ where $\mathbf{a}, \mathbf{b} \in \mathbb{F}^n$
/// are defined by the provided equal-length iterators.
///
/// # Panics
///
/// Panics if the lengths of $\mathbf{a}$ and $\mathbf{b}$ are not equal.
pub fn dot<'a, F: Field, I1: IntoIterator<Item = &'a F>, I2: IntoIterator<Item = &'a F>>(
    a: I1,
    b: I2,
) -> F
where
    I1::IntoIter: ExactSizeIterator,
    I2::IntoIter: ExactSizeIterator,
{
    let a = a.into_iter();
    let b = b.into_iter();
    assert_eq!(a.len(), b.len());
    a.into_iter()
        .zip(b)
        .map(|(a, b)| *a * *b)
        .fold(F::ZERO, |acc, x| acc + x)
}

fn factor_iter_inner<F: Field, I: IntoIterator<Item = F>>(a: I, mut b: F) -> impl Iterator<Item = F>
where
    I::IntoIter: DoubleEndedIterator,
{
    b = -b;
    let mut a = a.into_iter().rev().peekable();

    assert!(a.peek().is_some(), "cannot factor a polynomial of degree 0");

    let mut tmp = F::ZERO;

    core::iter::from_fn(move || {
        let current = a.next()?;

        // Discard `current` if constant term and short-circuit the iterator.
        a.peek()?;

        let mut lead_coeff = current;
        lead_coeff -= tmp;
        tmp = lead_coeff;
        tmp *= b;
        Some(lead_coeff)
    })
}

/// Returns an iterator that yields the coefficients of $a / (X - b)$,
/// assuming $b$ is a root of $a$ (i.e., the division is exact). If $b$ is not
/// a root, the returned quotient silently drops the remainder.
/// The coefficients are yielded in reverse order (highest degree first).
///
/// # Panics
///
/// Panics if the polynomial $a$ is of degree $0$, as it cannot be factored by a linear term.
pub fn factor_iter<'a, F: Field, I: IntoIterator<Item = F> + 'a>(
    a: I,
    b: F,
) -> Box<dyn Iterator<Item = F> + 'a>
where
    I::IntoIter: DoubleEndedIterator,
{
    Box::new(factor_iter_inner(a, b))
}

/// Computes $a / (X - b)$, assuming $b$ is a root of $a$ (i.e., the division
/// is exact). If $b$ is not a root, the returned quotient silently drops the
/// remainder.
///
/// # Panics
///
/// Panics if the polynomial $a$ is of degree $0$, as it cannot be factored by a linear term.
pub fn factor<F: Field, I: IntoIterator<Item = F>>(a: I, b: F) -> Vec<F>
where
    I::IntoIter: DoubleEndedIterator,
{
    let mut result: Vec<F> = factor_iter_inner(a, b).collect();
    result.reverse();
    result
}

/// Given a number of scalars, returns the ideal bucket size (in bits) for
/// multiexp, obtained through experimentation. This could probably be optimized
/// further and for particular compilation targets.
fn bucket_lookup(n: usize) -> usize {
    // Approximates ceil(ln(n)) without floating-point. See test_bucket_lookup_thresholds.
    const LN_THRESHOLDS: [usize; 15] = [
        4, 4, 32, 55, 149, 404, 1097, 2981, 8104, 22027, 59875, 162755, 442414, 1202605, 3269018,
    ];

    let mut cur = 1;
    for &threshold in LN_THRESHOLDS.iter() {
        if n < threshold {
            return cur;
        }

        cur += 1;
    }
    cur
}

#[test]
fn test_bucket_lookup_thresholds() {
    for n in 0..8886111 {
        // This is heuristic behavior that uses floating point intrinsics to
        // succinctly estimate the correct bucket size for multiscalar
        // multiplication. These intrinsics are only available in the standard
        // library, so we replicate them (to sufficient extent) through a lookup
        // table.
        let expected = {
            if n < 4 {
                1
            } else if n < 32 {
                3
            } else {
                (f64::from(n as u32)).ln().ceil() as usize
            }
        };
        let actual = bucket_lookup(n);
        if expected != actual {
            panic!("n = {}: expected {}, got {}", n, expected, actual);
        }
    }
}

/// Batch-convert projective points to affine using a single field inversion
/// (Montgomery's trick).
pub fn batch_to_affine<C: CurveAffine, const N: usize>(projectives: [C::Curve; N]) -> [C; N] {
    let mut affines = [C::identity(); N];
    C::Curve::batch_normalize(&projectives, &mut affines);
    affines
}

/// Compute the multiscalar multiplication $\langle \mathbf{a}, \mathbf{G} \rangle$ where
/// $\mathbf{a} \in \mathbb{F}^n$ is a vector of scalars and $\mathbf{G} \in \mathbb{G}^n$
/// is a vector of bases.
///
/// When the `multicore` feature is enabled, window computation is parallelized
/// using rayon.
///
/// # Correctness
///
/// The caller must ensure that `coeffs` and `bases` yield the same number of
/// elements.
pub fn mul<
    'a,
    C: CurveAffine,
    A: IntoIterator<Item = &'a C::Scalar>,
    B: IntoIterator<Item = &'a C>,
>(
    coeffs: A,
    bases: B,
) -> C::Curve
where
    B::IntoIter: Clone + Sync,
{
    let coeffs: Vec<_> = coeffs.into_iter().map(|a| a.to_repr()).collect();

    let c = bucket_lookup(coeffs.len());

    fn get_at<F: PrimeField>(segment: usize, c: usize, bytes: &F::Repr) -> usize {
        let skip_bits = segment * c;
        let skip_bytes = skip_bits / 8;

        if skip_bytes >= bytes.as_ref().len() {
            return 0;
        }

        // 4 bytes suffices since bucket_lookup returns at most 16.
        let mut v = [0; 4];
        for (v, o) in v.iter_mut().zip(bytes.as_ref()[skip_bytes..].iter()) {
            *v = *o;
        }

        let mut tmp = u32::from_le_bytes(v);
        tmp >>= skip_bits - (skip_bytes * 8);
        tmp %= 1 << c;

        tmp as usize
    }

    let segments = (C::Scalar::NUM_BITS as usize).div_ceil(c);

    #[derive(Clone, Copy)]
    enum Bucket<C: CurveAffine> {
        None,
        Affine(C),
        Projective(C::Curve),
    }

    impl<C: CurveAffine> Bucket<C> {
        fn add_assign(&mut self, other: &C) {
            *self = match *self {
                Bucket::None => Bucket::Affine(*other),
                Bucket::Affine(a) => Bucket::Projective(a + *other),
                Bucket::Projective(mut a) => {
                    a += *other;
                    Bucket::Projective(a)
                }
            }
        }

        fn add(self, mut other: C::Curve) -> C::Curve {
            match self {
                Bucket::None => other,
                Bucket::Affine(a) => {
                    other += a;
                    other
                }
                Bucket::Projective(a) => other + a,
            }
        }
    }

    /// Compute the bucket sum for a single window segment.
    fn window_sum<'a, C: CurveAffine, I: Iterator<Item = &'a C>>(
        current_segment: usize,
        c: usize,
        coeffs: &[<C::Scalar as PrimeField>::Repr],
        bases: I,
    ) -> C::Curve {
        let mut buckets: Vec<Bucket<C>> = vec![Bucket::None; (1 << c) - 1];

        for (coeff, base) in coeffs.iter().zip(bases) {
            let coeff = get_at::<C::Scalar>(current_segment, c, coeff);
            if coeff != 0 {
                buckets[coeff - 1].add_assign(base);
            }
        }

        // Summation by parts
        // e.g. 3a + 2b + 1c = a +
        //                    (a) + b +
        //                    ((a) + b) + c
        let mut running_sum = C::Curve::identity();
        let mut sum = C::Curve::identity();
        for exp in buckets.into_iter().rev() {
            running_sum = exp.add(running_sum);
            sum += &running_sum;
        }
        sum
    }

    // Compute each window's bucket sum in parallel (or sequentially via maybe-rayon facade).
    let bases_iter = bases.into_iter();
    let window_sums: Vec<C::Curve> = (0..segments)
        .into_par_iter()
        .map(|seg| window_sum(seg, c, &coeffs, bases_iter.clone()))
        .collect();

    // Combine window sums sequentially, from most significant to least.
    let mut acc = C::Curve::identity();
    for sum in window_sums.into_iter().rev() {
        for _ in 0..c {
            acc = acc.double();
        }
        acc += &sum;
    }

    acc
}

/// Computes the geometric sum $0 + 1 + r + ... + r^{m-1}$.
pub fn geosum<F: Field>(mut r: F, mut m: usize) -> F {
    let mut block = F::ONE;
    let mut sum = F::ZERO;
    let mut step = F::ONE;
    while m > 0 {
        if (m & 1) == 1 {
            sum += step * block;
            step *= r;
        }
        block += r * block;
        r = r.square();
        m >>= 1;
    }
    sum
}

/// Writes $c(X) = a(X) \cdot b(X)$ into `out` via FFT.
///
/// If either input is empty, `out` is cleared and the function returns.
/// Otherwise `out.len()` becomes `a.len() + b.len() - 1` on return, with
/// capacity left at `≥ 2 · next_power_of_two(a.len() + b.len() - 1)` (the
/// function uses the upper half of the buffer as FFT scratch); one-shot
/// callers that care about the slack should `shrink_to_fit` before handing
/// the buffer to consumers.
///
/// # Panics
///
/// Panics if the required FFT domain size exceeds the field's 2-adicity,
/// i.e., if `(a.len() + b.len() - 1).next_power_of_two().ilog2() > F::S`.
pub fn poly_mul<F: PrimeField>(a: &[F], b: &[F], out: &mut Vec<F>) {
    out.clear();

    if a.is_empty() || b.is_empty() {
        return;
    }

    let result_len = a.len() + b.len() - 1;
    let n = result_len.next_power_of_two();
    // TODO(cnode): instantiate Domain{...} in-line instead of using new(...),
    // which loops `F::S - k` times to derive the generator via halvings.
    let domain = Domain::new(n.ilog2());

    // Lay out both evaluation forms back-to-back in `out`: lower half will
    // carry FFT(a), upper half will carry FFT(b). The `resize` zero-fills,
    // so the zero-padding tail of each half is in place before we write
    // the inputs.
    out.resize(2 * n, F::ZERO);
    out[..a.len()].copy_from_slice(a);
    domain.fft(&mut out[..n]);

    out[n..n + b.len()].copy_from_slice(b);
    domain.fft(&mut out[n..]);

    let (lo, hi) = out.split_at_mut(n);
    for (l, h) in lo.iter_mut().zip(hi.iter()) {
        *l *= h;
    }

    domain.ifft(&mut out[..n]);
    out.truncate(result_len);
}

/// Decomposes the product $a(X) \cdot b(X)$ into coefficient vectors
/// $(p, q)$ whose constant term $p(0)$ equals the *reverse dot product*
/// $\mathrm{revdot}(\mathbf{a}, \mathbf{b}) = \sum\_{i=0}^{n-1} a\_i b\_{n-1-i}$.
///
/// This is the polynomial-decomposition step in the protocol's reduction
/// from a revdot claim to a polynomial query; see the
/// [book](https://tachyon.z.cash/ragu/protocol/prelim/structured_vectors.html#reduction-to-polynomial-queries)
/// for how the protocol consumes it.
///
/// Equal length is required: the identity is parameterized by a single $n$
/// where $|\mathbf{a}| = |\mathbf{b}| = n$. With $c = a \cdot b$ of length
/// $2n - 1$, $p$ is the reverse of the lower $n$ coefficients of $c$ and
/// $q$ is the upper $n - 1$ coefficients, so
///
/// $$ a(X) \cdot b(X) = X^{n-1} p(X^{-1}) + X^n q(X). $$
///
/// $p(0) = c\_{n-1}$ holds by construction of $p$, and the further
/// identification $c\_{n-1} = \mathrm{revdot}(\mathbf{a}, \mathbf{b})$
/// holds because $|\mathbf{a}| = |\mathbf{b}| = n$.
///
/// # Output lengths
///
/// When $n \geq 1$:
/// - `p.len() == n`
/// - `q.len() == n - 1` (empty when $n = 1$)
///
/// `q` is the raw upper half of $c$ with no leading-zero trimming. In
/// particular, for $n \geq 2$, `q.last()` (the highest-degree coefficient
/// of `q` viewed as a polynomial) may be `F::ZERO`.
///
/// When both inputs are empty, both vectors are returned empty.
///
/// # Panics
///
/// Panics if `a` and `b` have different lengths. Also inherits the FFT
/// domain-size panic from [`poly_mul`].
pub fn decomp_product_poly<F: PrimeField>(a: &[F], b: &[F]) -> (Vec<F>, Vec<F>) {
    assert_eq!(
        a.len(),
        b.len(),
        "decomp_product_poly requires equal-length vectors"
    );

    if a.is_empty() {
        return (vec![], vec![]);
    }

    // `c` has length `2n - 1`; split off the upper `n - 1` coefficients into
    // `q`, then reverse the remaining lower `n` coefficients in place to
    // form `p`.
    let n = a.len();
    let mut c = Vec::new();
    poly_mul(a, b, &mut c);
    assert_eq!(
        c.len(),
        2 * n - 1,
        "internal invariant: poly_mul should produce a vector of length 2n - 1"
    );

    let q = c.split_off(n);
    c.reverse();
    // `poly_mul` resized `out` to `2 · next_power_of_two(2n - 1)` (the upper
    // half was used as scratch for `FFT(b)`) and then truncated to `2n - 1`,
    // leaving slack in `c`'s capacity. `split_off` preserves that capacity,
    // so shrink before returning so `p` doesn't carry it.
    c.shrink_to_fit();
    (c, q)
}

/// Computes the lowest degree monic polynomial
///
/// $$
/// \prod_{i=0}^{n-1} (X - r_i)
/// $$
///
/// where $r_i$ are the provided values. Multiplicity is maintained, i.e. if a
/// root appears $k$ times in the input, it will appear $k$ times in the output
/// polynomial.
pub fn poly_with_roots<F: PrimeField>(roots: &[F]) -> Vec<F> {
    if roots.is_empty() {
        return vec![F::ONE];
    }

    let mut polys: Vec<Vec<F>> = roots.iter().map(|&root| vec![-root, F::ONE]).collect();
    // `poly_mul` uses `out` itself as scratch and grows it to twice the FFT
    // domain size; pre-allocate for the largest multiply we'll do.
    let max_n = (roots.len() + 1).next_power_of_two();
    let mut out = Vec::with_capacity(2 * max_n);

    while polys.len() > 1 {
        let pairs = polys.len() / 2;
        let has_odd = polys.len() % 2 == 1;

        for i in 0..pairs {
            poly_mul(&polys[2 * i], &polys[2 * i + 1], &mut out);
            polys[i].clear();
            polys[i].extend_from_slice(&out);
        }

        if has_odd {
            let last_idx = polys.len() - 1;
            if pairs < last_idx {
                polys.swap(pairs, last_idx);
            }
        }

        polys.truncate(pairs + if has_odd { 1 } else { 0 });
    }

    polys.into_iter().next().unwrap()
}

#[cfg(test)]
mod poly_with_roots_tests {
    use proptest::prelude::*;
    use ragu_testing::strategies;

    use super::*;
    use crate::{ff::Field, pasta_curves::Fp as F};

    fn check(roots: &[F]) -> Result<(), TestCaseError> {
        let poly = poly_with_roots(roots);

        // Correct degree
        prop_assert_eq!(poly.len(), roots.len() + 1);

        // Monic
        prop_assert_eq!(poly.last(), Some(&F::ONE));

        // Each root vanishes with correct multiplicity
        let mut checked = vec![];
        for &r in roots {
            if checked.contains(&r) {
                continue;
            }
            checked.push(r);
            let k = roots.iter().filter(|&&x| x == r).count();
            let mut q = poly.clone();
            for _ in 0..k {
                prop_assert_eq!(eval(&q, r), F::ZERO);
                q = factor(q.iter().copied(), r);
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn proptest_poly_with_roots(roots in strategies::poly_with_roots::<F>()) {
            check(&roots)?;
        }
    }
}

#[test]
fn test_poly_with_roots() {
    use crate::pasta_curves::Fp as F;

    let roots = vec![F::from(1), F::from(2), F::from(3)];
    let poly = poly_with_roots(&roots);

    for &root in &roots {
        assert_eq!(eval(&poly, root), F::ZERO);
    }

    let non_root = F::from(5);
    assert_ne!(eval(&poly, non_root), F::ZERO);

    let expected_coeffs = vec![F::from(6).neg(), F::from(11), F::from(6).neg(), F::ONE];
    assert_eq!(poly, expected_coeffs);

    let empty_roots: Vec<F> = vec![];
    let constant_poly = poly_with_roots(&empty_roots);
    assert_eq!(constant_poly, vec![F::ONE]);
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;
    use crate::{
        ff::{Field, PrimeField},
        pasta_curves::Fp as F,
    };

    fn arb_fe() -> impl Strategy<Value = F> {
        (any::<u64>(), any::<u64>())
            .prop_map(|(a, b)| F::from(a) + F::from(b) * F::MULTIPLICATIVE_GENERATOR)
    }

    /// Random nonzero field element. With probability `1/10` each, returns
    /// `F::ONE` or `-F::ONE`, exercising boundary points that uniformly
    /// random elements would essentially never reach.
    fn arb_fe_nonzero() -> impl Strategy<Value = F> {
        prop_oneof![
            8 => arb_fe().prop_filter("nonzero", |x| !bool::from(x.is_zero())),
            1 => Just(F::ONE),
            1 => Just(-F::ONE),
        ]
    }

    /// Like `arb_fe`, but returns `F::ZERO` with probability `1/10`, so
    /// vectors built from this strategy exercise sparse polynomials and
    /// the case where the highest-degree coefficient is zero.
    fn arb_fe_with_zeros() -> impl Strategy<Value = F> {
        prop_oneof![
            9 => arb_fe(),
            1 => Just(F::ZERO),
        ]
    }

    /// Draws two vectors of independently random field elements with a
    /// common random length in `1..=32`. Coefficients occasionally land
    /// on zero, exercising sparse polynomials and the case where the
    /// highest-degree coefficient is zero — relevant to the no-trim
    /// contract on `decomp_product_poly`'s `q`.
    fn arb_equal_length_pair() -> impl Strategy<Value = (Vec<F>, Vec<F>)> {
        (1usize..=32).prop_flat_map(|n| {
            (
                proptest::collection::vec(arb_fe_with_zeros(), n..=n),
                proptest::collection::vec(arb_fe_with_zeros(), n..=n),
            )
        })
    }

    /// Checks the [`decomp_product_poly`] identity
    /// $a(x) \cdot b(x) = x^{n-1} p(x^{-1}) + x^n q(x)$ from precomputed
    /// evaluations at $x$. Centralizing the exponents in one helper makes
    /// the identity explicit and easy to mirror in any future verifier
    /// implementation.
    ///
    /// Requires `n >= 1` — the helper computes `n - 1` as a `usize`, which
    /// would underflow for `n == 0`. The body asserts this precondition.
    fn check_decomp_identity<F: PrimeField>(
        a_at_x: F,
        b_at_x: F,
        p_at_x_inv: F,
        q_at_x: F,
        x: F,
        n: usize,
    ) -> bool {
        assert!(n >= 1, "check_decomp_identity requires n >= 1");
        let x_pow_n_minus_1 = x.pow_vartime([(n - 1) as u64]);
        let x_pow_n = x_pow_n_minus_1 * x;
        a_at_x * b_at_x == x_pow_n_minus_1 * p_at_x_inv + x_pow_n * q_at_x
    }

    proptest! {
        #[test]
        fn eval_dot_equivalence(x in arb_fe(), coeffs in proptest::collection::vec(arb_fe(), 1..32)) {
            let mut powers = Vec::with_capacity(coeffs.len());
            let mut p = F::ONE;
            for _ in 0..coeffs.len() {
                powers.push(p);
                p *= x;
            }
            prop_assert_eq!(dot(powers.iter(), coeffs.iter()), eval(&coeffs, x));
        }

        #[test]
        fn factor_quotient_identity(
            p in proptest::collection::vec(arb_fe(), 2..16),
            b in arb_fe(),
            y in arb_fe(),
        ) {
            let q = factor(p.iter().copied(), b);
            let lhs = eval(&p, y);
            let rhs = eval(&q, y) * (y - b) + eval(&p, b);
            prop_assert_eq!(lhs, rhs);
        }

        #[test]
        fn geosum_matches_naive(r in arb_fe(), m in 1usize..64) {
            let mut naive = F::ZERO;
            let mut power = F::ONE;
            for _ in 0..m {
                naive += power;
                power *= r;
            }
            prop_assert_eq!(geosum(r, m), naive);
        }

        #[test]
        fn poly_mul_convolution(
            a in proptest::collection::vec(arb_fe(), 1..32),
            b in proptest::collection::vec(arb_fe(), 1..32),
        ) {
            let mut c = Vec::new();
            poly_mul(&a, &b, &mut c);
            prop_assert_eq!(c.len(), a.len() + b.len() - 1);

            let mut expected = vec![F::ZERO; a.len() + b.len() - 1];
            for (i, &ai) in a.iter().enumerate() {
                for (j, &bj) in b.iter().enumerate() {
                    expected[i + j] += ai * bj;
                }
            }
            prop_assert_eq!(c, expected);
        }

        #[test]
        fn decomp_product_poly_identity(
            (a, b) in arb_equal_length_pair(),
            x in arb_fe_nonzero(),
        ) {
            let n = a.len();
            let (p, q) = decomp_product_poly(&a, &b);
            prop_assert_eq!(p.len(), n);
            prop_assert_eq!(q.len(), n - 1);

            let x_inv = x.invert().unwrap();
            prop_assert!(check_decomp_identity(
                eval(&a, x),
                eval(&b, x),
                eval(&p, x_inv),
                eval(&q, x),
                x,
                n,
            ));

            let revdot: F = a.iter().zip(b.iter().rev()).map(|(&x, &y)| x * y).sum();
            prop_assert_eq!(p[0], revdot);
        }
    }

    #[test]
    fn decomp_product_poly_n_eq_1() {
        let a = vec![F::from(7)];
        let b = vec![F::from(11)];
        let (p, q) = decomp_product_poly(&a, &b);
        assert_eq!(p, vec![F::from(77)]);
        assert!(q.is_empty());
    }

    #[test]
    fn decomp_product_poly_empty() {
        let (p, q) = decomp_product_poly::<F>(&[], &[]);
        assert!(p.is_empty());
        assert!(q.is_empty());
    }

    #[test]
    #[should_panic(expected = "decomp_product_poly requires equal-length vectors")]
    fn decomp_product_poly_length_mismatch() {
        let a = vec![F::ONE, F::ONE];
        let b = vec![F::ONE];
        let _ = decomp_product_poly(&a, &b);
    }

    #[test]
    fn poly_mul_empty() {
        let mut out = Vec::<F>::new();
        poly_mul::<F>(&[], &[F::ONE], &mut out);
        assert!(out.is_empty());
        poly_mul::<F>(&[F::ONE], &[], &mut out);
        assert!(out.is_empty());
        poly_mul::<F>(&[], &[], &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn poly_mul_by_one() {
        let a = vec![F::from(2), F::from(3), F::from(5)];
        let one = vec![F::ONE];
        let mut out = Vec::new();
        poly_mul(&a, &one, &mut out);
        assert_eq!(out, a);
        poly_mul(&one, &a, &mut out);
        assert_eq!(out, a);
    }
}

#[test]
fn test_mul() {
    use crate::pasta_curves::group::{Curve, CurveAffine};

    let mut coeffs = vec![];
    for i in 0..1000 {
        coeffs.push(
            crate::pasta_curves::Fp::from(i) * crate::pasta_curves::Fp::MULTIPLICATIVE_GENERATOR,
        );
    }

    let mut bases = vec![];
    for i in 0..1000 {
        bases.push(
            (crate::pasta_curves::EqAffine::generator() * crate::pasta_curves::Fp::from(i))
                .to_affine(),
        );
    }

    let expected = coeffs.iter().zip(bases.iter()).fold(
        crate::pasta_curves::Eq::identity(),
        |acc, (scalar, point)| acc + point * scalar,
    );

    assert_eq!(mul(coeffs.iter(), bases.iter()), expected);
}

#[test]
fn test_dot() {
    use crate::pasta_curves::Fp as F;

    let powers = [
        F::ONE,
        F::DELTA,
        F::DELTA.square(),
        F::DELTA.square() * F::DELTA,
        F::DELTA.square().square(),
    ];
    let coeffs = [F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];

    assert_eq!(
        dot(powers.iter(), coeffs.iter()),
        eval(coeffs.iter(), F::DELTA)
    );
}

#[test]
fn test_factor() {
    use crate::pasta_curves::Fp as F;

    let poly = vec![
        F::DELTA,
        F::DELTA.square(),
        F::from(348) * F::DELTA,
        F::from(438) * F::MULTIPLICATIVE_GENERATOR,
    ];
    let x = F::TWO_INV;
    let v = eval(poly.iter(), x);
    let quot = factor(poly.clone(), x);
    let mut quot_iter = factor_iter(poly.clone(), x).collect::<Vec<_>>();
    quot_iter.reverse();
    assert_eq!(quot, quot_iter);
    let y = F::DELTA + F::from(100);
    assert_eq!(eval(quot.iter(), y) * (y - x), eval(poly.iter(), y) - v);
}

#[test]
fn test_geosum() {
    use crate::pasta_curves::Fp as F;

    fn geosum_slow<F: Field>(r: F, m: usize) -> F {
        let mut sum = F::ZERO;
        let mut power = F::ONE;
        for _ in 0..m {
            sum += power;
            power *= r;
        }
        sum
    }

    let r = F::from(42u64) * F::MULTIPLICATIVE_GENERATOR;
    for m in 0..33 {
        assert_eq!(geosum(F::ZERO, m), geosum_slow(F::ZERO, m));
        assert_eq!(geosum(F::ONE, m), geosum_slow(F::ONE, m));
        assert_eq!(geosum(r, m), geosum_slow(r, m));
    }
}

#[test]
fn test_batched_quotient_streaming() {
    use crate::{ff::Field, pasta_curves::Fp as F};

    let polys: Vec<Vec<F>> = vec![
        vec![F::from(1), F::from(2), F::from(3), F::from(4)],
        vec![F::from(5), F::from(6), F::from(7), F::from(8)],
        vec![F::from(9), F::from(10), F::from(11), F::from(12)],
    ];
    let x = F::from(42);
    let alpha = F::from(7);

    let f_coeffs: Vec<F> = {
        let mut iters: Vec<_> = polys
            .iter()
            .map(|p| factor_iter(p.iter().copied(), x))
            .collect();

        let mut coeffs_rev = Vec::new();
        while let Some(first) = iters[0].next() {
            let c = iters[1..]
                .iter_mut()
                .fold(first, |acc, iter| alpha * acc + iter.next().unwrap());
            coeffs_rev.push(c);
        }
        coeffs_rev.reverse();
        coeffs_rev
    };

    let f_expected: Vec<F> = {
        let quotients: Vec<Vec<F>> = polys.iter().map(|p| factor(p.iter().copied(), x)).collect();

        let n = quotients.len();
        let max_len = quotients.iter().map(|q| q.len()).max().unwrap();
        let mut f = vec![F::ZERO; max_len];
        for (i, q) in quotients.iter().enumerate() {
            let alpha_i = alpha.pow([(n - 1 - i) as u64]);
            for (j, &c) in q.iter().enumerate() {
                f[j] += alpha_i * c;
            }
        }
        f
    };

    assert_eq!(f_coeffs, f_expected);

    let y = F::from(100);
    let f_at_y = eval(f_coeffs.iter(), y);
    let n = polys.len();
    let expected_at_y: F = polys
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let q_at_y = eval(factor(p.iter().copied(), x).iter(), y);
            alpha.pow([(n - 1 - i) as u64]) * q_at_y
        })
        .sum();
    assert_eq!(f_at_y, expected_at_y);
}
