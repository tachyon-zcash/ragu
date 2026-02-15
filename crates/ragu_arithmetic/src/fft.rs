use ff::{Field, PrimeField};

/// A ring that can be used for FFTs.
pub trait Ring {
    /// Elements of the ring.
    type R: Default + Clone;

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

pub(crate) fn fft<R: Ring>(log2_n: u32, input: &mut [R::R], omega: R::F) {
    // Enforce that the input and domain sizes match.
    let n = input.len() as u32;
    assert_eq!(n, 1 << log2_n);

    for i in 0..n {
        let ri = bitreverse(i, log2_n);
        if i < ri {
            input.swap(ri as usize, i as usize);
        }
    }

    let mut m = 1;
    for _ in 0..log2_n {
        let w_m = omega.pow([(n / (m << 1)) as u64]);

        let mut i = 0;
        while i < n {
            let mut w = R::F::ONE;
            for j in 0..m {
                let mut a = R::R::default();
                core::mem::swap(&mut a, &mut input[(i + j + m) as usize]);
                R::scale_assign(&mut a, w);
                let mut b = input[(i + j) as usize].clone();
                R::sub_assign(&mut b, &a);
                input[(i + j + m) as usize] = b;
                R::add_assign(&mut input[(i + j) as usize], &a);
                w *= w_m;
            }

            i += m << 1;
        }

        m <<= 1;
    }
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
            fft::<FFTField<Fp>>(log2_n, &mut fft_result, domain.omega());

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

        fft::<FFTField<Fp>>(0, &mut data, domain.omega());

        assert_eq!(data[0], Fp::from(42u64));
    }
}
