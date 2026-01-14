use ff::{Field, PrimeField};
use pasta_curves::{arithmetic::CurveAffine, group::Group};

use alloc::{boxed::Box, vec, vec::Vec};

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

/// Computes the first `n` powers of `base`, i.e., z^0, z^1, z^2, ..., z^{n-1}.
pub fn powers<F: Field>(base: F, n: usize) -> Vec<F> {
    let mut result = Vec::with_capacity(n);
    let mut cur = F::ONE;
    for _ in 0..n {
        result.push(cur);
        cur *= base;
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

        if skip_bytes >= 32 {
            return 0;
        }

        let mut v = [0; 8];
        for (v, o) in v.iter_mut().zip(bytes.as_ref()[skip_bytes..].iter()) {
            *v = *o;
        }

        let mut tmp = u64::from_le_bytes(v);
        tmp >>= skip_bits - (skip_bytes * 8);
        tmp %= 1 << c;

        tmp as usize
    }

    let segments = (256 / c) + 1;

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
        dot(powers.iter(), coeffs.iter().rev().rev()),
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
