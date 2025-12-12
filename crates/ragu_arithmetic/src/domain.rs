use ff::PrimeField;

use alloc::vec::Vec;

/// Radix-2 evaluation domain for polynomials in fields supported by Ragu.
pub struct Domain<F> {
    /// $n$, the size of the domain
    n: usize,
    /// $\log_2(n)$
    log2_n: u32,
    /// The primitive $n$-th root of unity in the field
    omega: F,
    /// Inverse of the primitive $n$-th root of unity in the field
    omega_inv: F,
    /// Inverse of $n$ in the field (as an integer) for inverse FFTs
    n_inv: F,
}

impl<F: PrimeField> Default for Domain<F> {
    fn default() -> Self {
        Domain {
            log2_n: F::S,
            n: 1 << F::S,
            omega: F::ROOT_OF_UNITY,
            omega_inv: F::ROOT_OF_UNITY_INV,
            n_inv: (F::TWO_INV).pow_vartime([F::S as u64]),
        }
    }
}

impl<F: PrimeField> Domain<F> {
    /// Initializes a new domain of size $2^k$.
    ///
    /// # Panics
    ///
    /// Panics if attempting to create a domain larger than supported by the
    /// field.
    pub fn new(k: u32) -> Self {
        if k > F::S {
            panic!(
                "tried to create a domain of size 2^{} in a field with 2-adicity {}",
                k,
                F::S
            );
        }

        let mut tmp = Self::default();
        for _ in k..F::S {
            tmp = tmp.halve();
        }
        assert_eq!(k, tmp.log2_n);
        tmp
    }

    /// Halves the size of the evaluation domain.
    ///
    /// # Panics
    ///
    /// Panics if attempting to halve a domain of size 1.
    fn halve(&self) -> Self {
        if self.log2_n == 0 {
            panic!("cannot halve a domain of size 1");
        }

        let log2_n = self.log2_n - 1;
        Domain {
            log2_n,
            n: 1 << log2_n,
            omega: self.omega.square(),
            omega_inv: self.omega_inv.square(),
            n_inv: self.n_inv.double(),
        }
    }

    /// The size of the domain.
    pub fn n(&self) -> usize {
        self.n
    }

    /// The $\log_2(n)$ of this domain of size $n$.
    pub fn log2_n(&self) -> u32 {
        self.log2_n
    }

    /// Returns the generator of the domain.
    pub fn omega(&self) -> F {
        self.omega
    }

    /// Computes the radix2 discrete Fourier transform (DFT) of a slice of
    /// generic ring elements using the Cooley-Tukey FFT algorithm.
    pub fn ring_fft<R: crate::fft::Ring<F = F>>(&self, input: &mut [R::R]) {
        crate::fft::fft::<R>(self.log2_n, input, self.omega);
    }

    /// Performs the inverse operation of [`Self::ring_fft`].
    pub fn ring_ifft<R: crate::fft::Ring<F = F>>(&self, input: &mut [R::R]) {
        crate::fft::fft::<R>(self.log2_n, input, self.omega_inv);

        for input in input.iter_mut() {
            R::scale_assign(input, self.n_inv);
        }
    }

    /// Computes the radix2 discrete Fourier transform (DFT) of a slice of field
    /// elements using the Cooley-Tukey FFT algorithm.
    pub fn fft(&self, input: &mut [F]) {
        self.ring_fft::<crate::fft::FFTField<F>>(input);
    }

    /// Performs the inverse operation of [`Self::fft`].
    pub fn ifft(&self, input: &mut [F]) {
        self.ring_ifft::<crate::fft::FFTField<F>>(input);
    }

    /// Computes the Lagrange coefficients for the provided `x`.
    ///
    /// Returns `None` if `x` is in the domain, otherwise returns a vector where
    /// `result[i]` contains `ell_i(x)`.
    ///
    /// # Panics
    ///
    /// Panics if the provided `amount` exceeds `n`.
    pub fn ell(&self, x: F, amount: usize) -> Option<Vec<F>> {
        assert!(amount <= self.n);

        let xn = x.pow([self.n as u64]);
        if xn == F::ONE {
            return None;
        }

        // Compute omega^j for each j, using ROOT_OF_UNITY for consistency across domain sizes
        // omega^j = ROOT_OF_UNITY^(j * 2^(F::S - log2_n))
        let shift = F::S - self.log2_n;
        let omega_powers: Vec<F> = (0..amount)
            .map(|j| {
                // Compute j * 2^(F::S - log2_n) by left-shifting j
                let exponent = (j as u64) << shift;
                F::ROOT_OF_UNITY.pow([exponent])
            })
            .collect();

        // Compute (x - omega_i)^{-1} for each omega power
        let mut denominators: Vec<F> = omega_powers.iter().map(|&omega_i| x - omega_i).collect();

        // Batch invert all denominators using Montgomery's trick
        {
            let mut scratch = denominators.clone();
            ff::BatchInverter::invert_with_external_scratch(&mut denominators, &mut scratch);
        }

        // Compute ell_i(x) = (x - omega_i)^{-1} * (x^n - 1) * omega_i / n
        let xn_minus_1_over_n = (xn - F::ONE) * self.n_inv;
        Some(
            denominators
                .into_iter()
                .zip(omega_powers.iter())
                .map(|(inv_denom, &omega_i)| inv_denom * xn_minus_1_over_n * omega_i)
                .collect(),
        )
    }
}

#[test]
fn test_fft() {
    use crate::eval;
    use ff::Field;
    use pasta_curves::Fp as F;

    let params = Domain::<F>::new(4);

    let coeffs = (0..params.n)
        .map(|i| F::DELTA.pow([(i + 1) as u64]))
        .collect::<Vec<_>>();
    let mut evals = coeffs.clone();

    params.fft(&mut evals);

    {
        let mut p = F::ONE;
        for e in evals.iter().take(params.n) {
            assert_eq!(*e, eval(&coeffs, p));
            p *= params.omega;
        }
    }

    let mut coeffs_recovered = evals.clone();
    params.ifft(&mut coeffs_recovered);
    assert_eq!(coeffs, coeffs_recovered);
}

#[test]
fn test_ell() {
    use crate::eval;
    use ff::Field;
    use pasta_curves::Fp as F;

    use alloc::vec;

    let params = Domain::<F>::new(5);

    let mut lagrange_polys = vec![];
    for i in 0..params.n {
        assert!(params.ell(params.omega.pow([i as u64]), params.n).is_none());
        let mut tmp = vec![F::ZERO; params.n];
        tmp[i] = F::ONE;
        params.ifft(&mut tmp);
        for j in 0..params.n {
            assert_eq!(
                eval(&tmp, params.omega.pow([j as u64])),
                if i == j { F::ONE } else { F::ZERO }
            );
        }
        lagrange_polys.push(tmp);
    }

    let x = F::DELTA;

    let expected = params.ell(x, params.n).unwrap();
    for (i, expected) in expected.iter().enumerate() {
        assert_eq!(eval(&lagrange_polys[i], x), *expected);
    }
}
