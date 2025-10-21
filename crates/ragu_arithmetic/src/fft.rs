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

/// Reverses the bits of `n` using `l` bits.
pub fn bitreverse(mut n: u32, l: u32) -> u32 {
    let mut r = 0;
    for _ in 0..l {
        r = (r << 1) | (n & 1);
        n >>= 1;
    }
    r
}

pub(crate) fn fft<R: Ring>(log2_n: u32, input: &mut [R::R], omega: R::F) {
    assert_eq!(input.len(), 1 << log2_n);
    let n = input.len() as u32;

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
