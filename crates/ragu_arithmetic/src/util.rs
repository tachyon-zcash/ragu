use ff::{Field, PrimeField};
use pasta_curves::{arithmetic::CurveAffine, group::Group};

use alloc::{boxed::Box, vec, vec::Vec};

use crate::domain::Domain;

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

    if a.peek().is_none() {
        panic!("cannot factor a polynomial of degree 0");
    }

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

/// Returns an iterator that yields the coefficients of $a / (X - b)$ with no remainder
/// for the given univariate polynomial $a \in \mathbb{F}\[X]$ and value $b \in \mathbb{F}$.
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

/// Computes $a / (X - b)$ with no remainder for the given univariate polynomial $a \in \mathbb{F}\[X]$ and value $b \in \mathbb{F}$.
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

/// Compute the multiscalar multiplication $\langle \mathbf{a}, \mathbf{G} \rangle$ where
/// $\mathbf{a} \in \mathbb{F}^n$ is a vector of scalars and $\mathbf{G} \in \mathbb{G}^n$
/// is a vector of bases.
///
/// # Usage
///
/// Ensure that the provided iterators have the same length, or this function may not
/// behave properly or could even panic.
pub fn mul<
    'a,
    C: CurveAffine,
    A: IntoIterator<Item = &'a C::Scalar>,
    B: IntoIterator<Item = &'a C> + Clone,
>(
    coeffs: A,
    bases: B,
) -> C::Curve {
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

    let mut acc = C::Curve::identity();

    for current_segment in (0..segments).rev() {
        for _ in 0..c {
            acc = acc.double();
        }

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

        let mut buckets: Vec<Bucket<C>> = vec![Bucket::None; (1 << c) - 1];

        for (coeff, base) in coeffs.iter().zip(bases.clone().into_iter()) {
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
        for exp in buckets.into_iter().rev() {
            running_sum = exp.add(running_sum);
            acc += &running_sum;
        }
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

    let max_domain_size = (roots.len() + 1).next_power_of_two();
    let mut scratch1 = vec![F::ZERO; max_domain_size];
    let mut scratch2 = vec![F::ZERO; max_domain_size];

    while polys.len() > 1 {
        let pairs = polys.len() / 2;
        let has_odd = polys.len() % 2 == 1;

        for i in 0..pairs {
            let poly1_len = polys[2 * i].len();
            let poly2_len = polys[2 * i + 1].len();
            let new_degree = (poly1_len - 1) + (poly2_len - 1);
            let domain_size = (new_degree + 1).next_power_of_two();
            // TODO(cnode): instantiate Domain{...} in-line instead of using new(...) which performs a loop
            let domain = Domain::new(domain_size.ilog2());
            let n = domain.n();

            scratch1[..poly1_len].copy_from_slice(&polys[2 * i]);
            scratch1[poly1_len..n].fill(F::ZERO);
            domain.fft(&mut scratch1[..n]);

            scratch2[..poly2_len].copy_from_slice(&polys[2 * i + 1]);
            scratch2[poly2_len..n].fill(F::ZERO);
            domain.fft(&mut scratch2[..n]);

            for j in 0..n {
                scratch1[j] *= scratch2[j];
            }

            domain.ifft(&mut scratch1[..n]);

            polys[i].clear();
            polys[i].extend_from_slice(&scratch1[..new_degree + 1]);
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
    use super::*;
    use ff::Field;
    use pasta_curves::Fp as F;
    use proptest::prelude::*;

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

    fn size_strategy() -> impl Strategy<Value = usize> {
        prop::sample::select(vec![
            0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 633,
        ])
    }

    fn arb_field_element() -> impl Strategy<Value = F> {
        (0u64..10000).prop_map(|i| F::from(i) * F::MULTIPLICATIVE_GENERATOR + F::DELTA)
    }

    fn roots_strategy() -> impl Strategy<Value = Vec<F>> {
        let w = Domain::<F>::new(6).omega();

        prop_oneof![
            // Distinct roots at boundary sizes
            size_strategy().prop_map(|n| (0..n).map(|i| F::from(i as u64) + F::DELTA).collect()),
            // Repeated roots at different tree levels
            Just(vec![F::from(7); 2]), // level 0: (X-7)²
            Just(vec![F::from(3); 4]), // level 1: (X-3)⁴
            Just(vec![F::from(5); 8]), // FFT level: (X-5)⁸
            // Zero roots (tests interaction with internal zero-padding)
            Just(vec![F::ZERO, F::from(1), F::from(2)]),
            Just(vec![F::ZERO; 5]),
            // Roots of unity (vanishing polynomials)
            Just((0..4).map(|i| w.pow([i * 16])).collect()), // 4th roots
            Just((0..16).map(|i| w.pow([i * 4])).collect()), // 16th roots
            Just((0..64).map(|i| w.pow([i as u64])).collect()), // 64th roots
            // Mixed: repeated roots of unity + arbitrary elements
            Just(vec![
                w,
                w,
                w.square(),
                w.square(),
                F::from(42),
                F::from(123)
            ]),
            // Random roots with random size
            (1usize..100).prop_flat_map(|n| { proptest::collection::vec(arb_field_element(), n) }),
            // All-same random root
            (arb_field_element(), 1usize..20).prop_map(|(r, n)| vec![r; n]),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn test_poly_with_roots(roots in roots_strategy()) {
            check(&roots)?;
        }
    }
}

#[test]
fn test_poly_with_roots() {
    use pasta_curves::Fp as F;

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

#[test]
fn test_mul() {
    use pasta_curves::group::{Curve, prime::PrimeCurveAffine};

    let mut coeffs = vec![];
    for i in 0..1000 {
        coeffs.push(pasta_curves::Fp::from(i) * pasta_curves::Fp::MULTIPLICATIVE_GENERATOR);
    }

    let mut bases = vec![];
    for i in 0..1000 {
        bases.push((pasta_curves::EqAffine::generator() * pasta_curves::Fp::from(i)).to_affine());
    }

    let expected = coeffs
        .iter()
        .zip(bases.iter())
        .fold(pasta_curves::Eq::identity(), |acc, (scalar, point)| {
            acc + point * scalar
        });

    assert_eq!(mul(coeffs.iter(), bases.iter()), expected);
}

#[test]
fn test_dot() {
    use pasta_curves::Fp as F;

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
    use pasta_curves::Fp as F;

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
    use pasta_curves::Fp as F;

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
    use ff::Field;
    use pasta_curves::Fp as F;

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
