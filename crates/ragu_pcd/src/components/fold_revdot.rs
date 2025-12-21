//! Operations and utilities for reasoning about folded revdot claims.

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{
    Element,
    vec::{ConstLen, FixedVec, Len},
};

use core::marker::PhantomData;

/// The parameters $(m, n)$ that dictate the multi-layer revdot reduction.
///
/// The first layer involves $n$ instances of size-$m$ revdot reductions, and
/// the second layer reduces these into a single revdot using a single size-$n$
/// revdot reduction.
///
/// The parameters here collapse as much as $m \cdot n$ claims into a single
/// claim using roughly $f(m, n) = 2nm^2 + 2n^2 - n + 3$ multiplication
/// constraints.
pub trait Parameters: 'static + Send + Sync + Clone + Copy + Default {
    type N: Len;
    type M: Len;
}

/// Default parameters for native revdot folding
#[derive(Clone, Copy, Default)]
pub struct NativeParameters;

impl Parameters for NativeParameters {
    type N = ConstLen<17>;
    type M = ConstLen<6>;
}

/// Represents the number of "error" terms produced during a folding operation
/// of many `revdot` claims.
///
/// Given $m$ claims being folded, the error terms are defined as the
/// off-diagonal entries of an $m \times m$ matrix, which by definition has $m *
/// (m - 1)$ terms.
///
/// See the book entry on [folding revdot
/// claims](https://tachyon.z.cash/_ragu_INTERNAL_ONLY_H83J19XK1/design/structured.html#folding)
/// for more information.
pub struct ErrorTermsLen<L: Len>(PhantomData<L>);

impl<L: Len> Len for ErrorTermsLen<L> {
    fn len() -> usize {
        let n = L::len();
        // n * (n - 1) = n² - n
        n * n - n
    }
}

/// Precomputed folding context for computing revdot claim `c`.
///
/// Computing `munu` and `mu_inv` once and reusing across multiple calls
/// saves 2*(N-1) multiplications in the two-layer reduction.
pub struct FoldC<'dr, D: Driver<'dr>> {
    munu: Element<'dr, D>,
    mu_inv: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> FoldC<'dr, D> {
    /// Create a folding context from mu and nu.
    pub fn new(dr: &mut D, mu: &Element<'dr, D>, nu: &Element<'dr, D>) -> Result<Self> {
        let munu = mu.mul(dr, nu)?;
        let mu_inv = mu.invert(dr)?;
        Ok(Self { munu, mu_inv })
    }

    /// Compute folded revdot claim `c` for layer 1 (M-sized reduction).
    pub fn compute_m<P: Parameters>(
        &self,
        dr: &mut D,
        error_terms: &FixedVec<Element<'dr, D>, ErrorTermsLen<P::M>>,
        ky_values: &FixedVec<Element<'dr, D>, P::M>,
    ) -> Result<Element<'dr, D>> {
        compute_c_impl::<_, P::M>(dr, &self.munu, &self.mu_inv, error_terms, ky_values)
    }

    /// Compute folded revdot claim `c` for layer 2 (N-sized reduction).
    pub fn compute_n<P: Parameters>(
        &self,
        dr: &mut D,
        error_terms: &FixedVec<Element<'dr, D>, ErrorTermsLen<P::N>>,
        ky_values: &FixedVec<Element<'dr, D>, P::N>,
    ) -> Result<Element<'dr, D>> {
        compute_c_impl::<_, P::N>(dr, &self.munu, &self.mu_inv, error_terms, ky_values)
    }
}

/// Core folding computation using precomputed munu and mu_inv.
fn compute_c_impl<'dr, D: Driver<'dr>, S: Len>(
    dr: &mut D,
    munu: &Element<'dr, D>,
    mu_inv: &Element<'dr, D>,
    error_terms: &FixedVec<Element<'dr, D>, ErrorTermsLen<S>>,
    ky_values: &FixedVec<Element<'dr, D>, S>,
) -> Result<Element<'dr, D>> {
    let mut error_terms = error_terms.iter();
    let mut ky_values = ky_values.iter();

    let mut result = Element::zero(dr);
    let mut row_power = Element::one();

    let n = S::len();
    for i in 0..n {
        let mut col_power = row_power.clone();
        for j in 0..n {
            let term = if i == j {
                ky_values.next().expect("should exist")
            } else {
                error_terms.next().expect("should exist")
            };

            let contribution = col_power.mul(dr, term)?;
            result = result.add(dr, &contribution);

            // Skip last column (col_power won't be used again)
            if j < n - 1 {
                col_power = col_power.mul(dr, munu)?;
            }
        }

        // Skip last row (row_power won't be used again)
        if i < n - 1 {
            row_power = row_power.mul(dr, mu_inv)?;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
    use ragu_pasta::Fp;
    use ragu_primitives::{Simulator, vec::CollectFixed};
    use rand::rngs::OsRng;

    /// Test parameters with N=3, M=3.
    #[derive(Clone, Copy, Default)]
    struct TestParams3;
    impl Parameters for TestParams3 {
        type N = ConstLen<3>;
        type M = ConstLen<3>;
    }

    /// Test parameters with configurable N and M.
    #[derive(Clone, Copy, Default)]
    struct TestParams<const N: usize, const M: usize>;
    impl<const N: usize, const M: usize> Parameters for TestParams<N, M> {
        type N = ConstLen<N>;
        type M = ConstLen<M>;
    }

    #[test]
    fn test_revdot_folding() -> Result<()> {
        type P = TestParams3;
        let n = <P as Parameters>::N::len();

        let a: Vec<_> = (0..n).map(|_| Fp::random(OsRng)).collect();
        let b: Vec<_> = (0..n).map(|_| Fp::random(OsRng)).collect();

        let mut ky = vec![];
        let mut error = vec![];

        for (i, a) in a.iter().enumerate() {
            for (j, b) in b.iter().enumerate() {
                if i == j {
                    ky.push(a * b);
                } else {
                    error.push(a * b);
                }
            }
        }

        let mu = Fp::random(OsRng);
        let nu = Fp::random(OsRng);
        let mu_inv = mu.invert().unwrap();

        let expected_c = arithmetic::eval(a.iter(), mu_inv) * arithmetic::eval(b.iter(), mu * nu);

        // Run routine with Emulator.
        let dr = &mut Emulator::execute();

        let mu = Element::constant(dr, mu);
        let nu = Element::constant(dr, nu);

        let error_terms = error
            .iter()
            .map(|&v| Element::constant(dr, v))
            .collect_fixed()
            .unwrap();

        let ky_values = ky
            .iter()
            .map(|&v| Element::constant(dr, v))
            .collect_fixed()
            .unwrap();

        let fold_c = FoldC::new(dr, &mu, &nu)?;
        let result = fold_c.compute_n::<P>(dr, &error_terms, &ky_values)?;
        let computed_c = result.value().take();

        assert_eq!(
            *computed_c, expected_c,
            "C routine computed value doesn't match expected"
        );

        Ok(())
    }

    #[test]
    fn test_compute_c_constraints() -> Result<()> {
        fn measure<P: Parameters>() -> Result<usize> {
            let sim = Simulator::simulate((), |dr, _| {
                let mu = Element::constant(dr, Fp::random(OsRng));
                let nu = Element::constant(dr, Fp::random(OsRng));
                let error_terms = FixedVec::from_fn(|_| Element::constant(dr, Fp::random(OsRng)));
                let ky_values = FixedVec::from_fn(|_| Element::constant(dr, Fp::random(OsRng)));

                let fold_c = FoldC::new(dr, &mu, &nu)?;
                fold_c.compute_n::<P>(dr, &error_terms, &ky_values)?;
                Ok(())
            })?;

            Ok(sim.num_multiplications())
        }

        // Formula: 2N^2 + 1
        assert_eq!(measure::<TestParams<5, 1>>()?, 51);
        assert_eq!(measure::<TestParams<15, 1>>()?, 451);
        assert_eq!(measure::<TestParams<30, 1>>()?, 1801);
        assert_eq!(measure::<TestParams<60, 1>>()?, 7201);

        Ok(())
    }

    #[test]
    fn test_multireduce() -> Result<()> {
        fn measure<P: Parameters>() -> Result<usize> {
            let rng = OsRng;
            let sim = Simulator::simulate(rng, |dr, mut rng| {
                let mu = Element::alloc(dr, rng.view_mut().map(Fp::random))?;
                let nu = Element::alloc(dr, rng.view_mut().map(Fp::random))?;
                let mu_prime = Element::alloc(dr, rng.view_mut().map(Fp::random))?;
                let nu_prime = Element::alloc(dr, rng.view_mut().map(Fp::random))?;

                // Layer 1: N instances of M-sized reductions (uses mu, nu)
                let fold_c_layer1 = FoldC::new(dr, &mu, &nu)?;
                let error_terms_m =
                    FixedVec::try_from_fn(|_| Element::alloc(dr, rng.view_mut().map(Fp::random)))?;
                let ky_values_m =
                    FixedVec::try_from_fn(|_| Element::alloc(dr, rng.view_mut().map(Fp::random)))?;

                let mut collapsed = vec![];
                for _ in 0..P::N::len() {
                    let v = fold_c_layer1.compute_m::<P>(dr, &error_terms_m, &ky_values_m)?;
                    collapsed.push(v);
                }
                let collapsed = FixedVec::new(collapsed)?;

                // Layer 2: Single N-sized reduction (uses mu', nu' - separate FoldC)
                let fold_c_layer2 = FoldC::new(dr, &mu_prime, &nu_prime)?;
                let error_terms_n =
                    FixedVec::try_from_fn(|_| Element::alloc(dr, rng.view_mut().map(Fp::random)))?;

                fold_c_layer2.compute_n::<P>(dr, &error_terms_n, &collapsed)?;

                Ok(())
            })?;

            let num = sim.num_multiplications();

            let expected = |m: usize, n: usize| 2 * n * m * m + 2 * n * n - n + 3;

            assert_eq!(num, expected(P::M::len(), P::N::len()));

            Ok(sim.num_multiplications())
        }

        // TestParams<N, M> where N is layer 2 size and M is layer 1 size
        // Formula: 2NM^2 + 2N^2 - N + 3
        assert_eq!(measure::<TestParams<2, 2>>()?, 25);
        assert_eq!(measure::<TestParams<7, 3>>()?, 220);
        assert_eq!(measure::<TestParams<11, 6>>()?, 1026);
        assert_eq!(measure::<TestParams<10, 5>>()?, 693);
        assert_eq!(measure::<TestParams<10, 10>>()?, 2193);

        Ok(())
    }

    /// Computes the number of multiplication constraints for given M, N.
    ///
    /// Formula: 2NM^2 + 2N^2 - N + 3
    /// - Layer 1: 2 + N(2M^2 - 1) = 2NM^2 - N + 2
    /// - Layer 2: 2 + (2N^2 - 1) = 2N^2 + 1
    fn muls(m: usize, n: usize) -> usize {
        2 * n * m * m + 2 * n * n - n + 3
    }

    /// Computes the number of allocations for given M, N.
    ///
    /// Formula: M^2 + N^2 - N + 2
    fn allocs(m: usize, n: usize) -> usize {
        m * m + n * n - n + 2
    }

    /// This measures the effective constraint cost that accounts
    /// for both multiplication gates and allocations for various M
    /// and N combinations. The optimal accounting here is to maximize
    /// M * N, while staying under the circuit budget.
    #[test]
    fn test_cost_formulas() -> Result<()> {
        fn verify<const M: usize, const N: usize>() -> Result<()> {
            let rng = OsRng;
            let sim = Simulator::simulate(rng, |dr, mut rng| {
                let mu = Element::alloc(dr, rng.view_mut().map(Fp::random))?;
                let nu = Element::alloc(dr, rng.view_mut().map(Fp::random))?;
                let mu_prime = Element::alloc(dr, rng.view_mut().map(Fp::random))?;
                let nu_prime = Element::alloc(dr, rng.view_mut().map(Fp::random))?;

                // Layer 1: N instances of M-sized reductions (uses mu, nu).
                let fold_c_layer1 = FoldC::new(dr, &mu, &nu)?;
                let all_error_terms_m: FixedVec<
                    FixedVec<_, ErrorTermsLen<ConstLen<M>>>,
                    ConstLen<N>,
                > = FixedVec::try_from_fn(|_| {
                    FixedVec::try_from_fn(|_| Element::alloc(dr, rng.view_mut().map(Fp::random)))
                })?;
                let all_ky_values_m: FixedVec<FixedVec<_, ConstLen<M>>, ConstLen<N>> =
                    FixedVec::try_from_fn(|_| {
                        FixedVec::try_from_fn(|_| {
                            Element::alloc(dr, rng.view_mut().map(Fp::random))
                        })
                    })?;

                let collapsed: FixedVec<_, ConstLen<N>> = FixedVec::try_from_fn(|i| {
                    fold_c_layer1.compute_m::<TestParams<N, M>>(
                        dr,
                        &all_error_terms_m[i],
                        &all_ky_values_m[i],
                    )
                })?;

                // Layer 2: Single N-sized reduction (uses mu', nu' - separate FoldC).
                let fold_c_layer2 = FoldC::new(dr, &mu_prime, &nu_prime)?;
                let error_terms_n: FixedVec<_, ErrorTermsLen<ConstLen<N>>> =
                    FixedVec::try_from_fn(|_| Element::alloc(dr, rng.view_mut().map(Fp::random)))?;

                fold_c_layer2.compute_n::<TestParams<N, M>>(dr, &error_terms_n, &collapsed)?;
                Ok(())
            })?;

            assert_eq!(sim.num_multiplications(), muls(M, N));

            // Verify optimal parameters fit budget
            let effective_cost = 2 * muls(6, 17) + allocs(6, 17);
            assert!(
                effective_cost < (2 * (1 << 11)),
                "M = 6, N = 17 exceeds budget: {}",
                effective_cost / 2
            );

            Ok(())
        }

        verify::<6, 17>()?;
        verify::<7, 14>()?;
        Ok(())
    }
}
