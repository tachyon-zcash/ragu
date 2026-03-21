use crate::multicore;
use ff::{Field, PrimeField};

/// A ring that can be used for FFTs.
pub trait Ring {
    /// Elements of the ring.
    type R: Default + Clone + Send;

    /// Scalar field for the ring.
    type F: Field;

    /// Scale a ring element by a scalar.
    fn scale_assign(r: &mut Self::R, by: Self::F);

    /// Add two ring elements.
    fn add_assign(r: &mut Self::R, other: &Self::R);

    /// Subtract two ring elements.
    fn sub_assign(r: &mut Self::R, other: &Self::R);
}

pub(crate) struct FFTField<F: PrimeField>(core::marker::PhantomData<F>);

impl<F: PrimeField> Ring for FFTField<F> {
    type R = F;
    type F = F;

    fn scale_assign(r: &mut Self::R, by: Self::F) {
        *r *= by;
    }

    fn add_assign(r: &mut Self::R, other: &Self::R) {
        *r += *other;
    }

    fn sub_assign(r: &mut Self::R, other: &Self::R) {
        *r -= *other;
    }
}

/// Reverses the lowest `l` bits of `n`.
pub fn bitreverse(n: u32, l: u32) -> u32 {
    if l == 0 {
        return 0;
    }
    n.reverse_bits() >> (32 - l)
}

/// Adapted from halo2_proofs::arithmetic::best_fft. The only changes are the
/// use of the `Ring` trait (which abstracts over Clone-based ring elements)
/// instead of halo2's `FftGroup` trait (which requires Copy).
pub(crate) fn fft<R: Ring>(a: &mut [R::R], omega: R::F, log_n: u32) {
    let threads = multicore::current_num_threads();
    let log_threads = log2_floor(threads);
    let n = a.len();
    assert_eq!(n, 1 << log_n);

    for k in 0..n {
        let rk = bitreverse(k as u32, log_n) as usize;
        if k < rk {
            a.swap(rk, k);
        }
    }

    // precompute twiddle factors
    let twiddles: alloc::vec::Vec<_> = (0..(n / 2))
        .scan(R::F::ONE, |w, _| {
            let tw = *w;
            *w *= &omega;
            Some(tw)
        })
        .collect();

    if log_n <= log_threads {
        let mut chunk = 2_usize;
        let mut twiddle_chunk = n / 2;
        for _ in 0..log_n {
            a.chunks_mut(chunk).for_each(|coeffs| {
                let (left, right) = coeffs.split_at_mut(chunk / 2);

                // case when twiddle factor is one
                let (a, left) = left.split_at_mut(1);
                let (b, right) = right.split_at_mut(1);
                let t = b[0].clone();
                b[0] = a[0].clone();
                R::add_assign(&mut a[0], &t);
                R::sub_assign(&mut b[0], &t);

                left.iter_mut()
                    .zip(right.iter_mut())
                    .enumerate()
                    .for_each(|(i, (a, b))| {
                        let mut t = b.clone();
                        R::scale_assign(&mut t, twiddles[(i + 1) * twiddle_chunk]);
                        *b = a.clone();
                        R::add_assign(a, &t);
                        R::sub_assign(b, &t);
                    });
            });
            chunk *= 2;
            twiddle_chunk /= 2;
        }
    } else {
        recursive_butterfly_arithmetic::<R>(a, n, 1, &twiddles)
    }
}

/// Adapted from halo2_proofs::arithmetic::recursive_butterfly_arithmetic.
pub(crate) fn recursive_butterfly_arithmetic<R: Ring>(
    a: &mut [R::R],
    n: usize,
    twiddle_chunk: usize,
    twiddles: &[R::F],
) {
    if n == 2 {
        let t = a[1].clone();
        a[1] = a[0].clone();
        R::add_assign(&mut a[0], &t);
        R::sub_assign(&mut a[1], &t);
    } else {
        let (left, right) = a.split_at_mut(n / 2);
        multicore::join(
            || recursive_butterfly_arithmetic::<R>(left, n / 2, twiddle_chunk * 2, twiddles),
            || recursive_butterfly_arithmetic::<R>(right, n / 2, twiddle_chunk * 2, twiddles),
        );

        // case when twiddle factor is one
        let (a, left) = left.split_at_mut(1);
        let (b, right) = right.split_at_mut(1);
        let t = b[0].clone();
        b[0] = a[0].clone();
        R::add_assign(&mut a[0], &t);
        R::sub_assign(&mut b[0], &t);

        left.iter_mut()
            .zip(right.iter_mut())
            .enumerate()
            .for_each(|(i, (a, b))| {
                let mut t = b.clone();
                R::scale_assign(&mut t, twiddles[(i + 1) * twiddle_chunk]);
                *b = a.clone();
                R::add_assign(a, &t);
                R::sub_assign(b, &t);
            });
    }
}

fn log2_floor(num: usize) -> u32 {
    assert!(num > 0);
    let mut pow = 0;
    while (1 << (pow + 1)) <= num {
        pow += 1;
    }
    pow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Domain;
    use alloc::vec;
    use alloc::vec::Vec;
    use pasta_curves::Fp;

    fn naive_dft<F: PrimeField>(input: &[F], omega: F) -> Vec<F> {
        let n = input.len();
        (0..n)
            .map(|k| {
                input.iter().enumerate().fold(F::ZERO, |acc, (j, x)| {
                    acc + *x * omega.pow([(k * j) as u64])
                })
            })
            .collect()
    }

    #[test]
    fn test_fft_matches_naive_dft() {
        for log2_n in 1..=8 {
            let domain = Domain::<Fp>::new(log2_n);
            let n = 1 << log2_n;

            let input: Vec<Fp> = (0..n)
                .map(|i| Fp::from((i * i + 7 * i + 13) as u64))
                .collect();

            let mut fft_result = input.clone();
            fft::<FFTField<Fp>>(&mut fft_result, domain.omega(), log2_n);

            let dft_result = naive_dft(&input, domain.omega());

            for i in 0..n {
                assert_eq!(
                    fft_result[i], dft_result[i],
                    "FFT differs from DFT at index {} for size 2^{}",
                    i, log2_n
                );
            }
        }
    }

    #[test]
    fn test_fft_single_element() {
        let domain = Domain::<Fp>::new(0);
        let mut data = vec![Fp::from(42u64)];

        fft::<FFTField<Fp>>(&mut data, domain.omega(), 0);

        assert_eq!(data[0], Fp::from(42u64));
    }
}
