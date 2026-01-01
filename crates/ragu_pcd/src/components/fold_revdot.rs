//! Operations and utilities for reasoning about folded revdot claims.

use ff::Field;
use ragu_circuits::polynomials::{Rank, structured};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use core::{borrow::Borrow, iter, marker::PhantomData};

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
    type N = ConstLen<18>;
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

/// Returns an iterator over off-diagonal (i, j) pairs where i != j.
fn off_diagonal_pairs(n: usize) -> impl Iterator<Item = (usize, usize)> {
    (0..n).flat_map(move |i| (0..n).filter_map(move |j| (i != j).then_some((i, j))))
}

/// Returns an iterator over all (i, j) pairs with a boolean indicating if diagonal.
fn cartesian_products(n: usize) -> impl Iterator<Item = (usize, usize, bool)> {
    (0..n).flat_map(move |i| (0..n).map(move |j| (i, j, i == j)))
}

/// Reduction step for polynomials in the first layer of revdot folding.
///
/// This takes a slice of polynomials (less than or equal to M * N in length)
/// and, assuming absent polynomials are zero, folds each group of M polynomials
/// into one polynomial using the provided scale factor.
///
/// # Panics
///
/// Panics if `source.len()` exceeds `M * N`, which would cause silent truncation.
pub fn fold_polys_m<F: Field, R: Rank, P: Parameters>(
    source: &[impl Borrow<structured::Polynomial<F, R>>],
    scale_factor: F,
) -> FixedVec<structured::Polynomial<F, R>, P::N> {
    assert!(
        source.len() <= P::M::len() * P::N::len(),
        "source length {} exceeds M*N = {}",
        source.len(),
        P::M::len() * P::N::len()
    );

    source
        .chunks(P::M::len())
        .map(|chunk| structured::Polynomial::fold(chunk.iter().map(Borrow::borrow), scale_factor))
        .chain(iter::repeat_with(structured::Polynomial::new))
        .take(P::N::len())
        .collect_fixed()
        .expect("iterator produces exactly N elements")
}

/// Reduction step for polynomials in the second layer of revdot folding.
///
/// This takes a length-N vector of polynomials and performs a simple folding
/// procedure with the scaling factor. This function exists mainly to complement
/// fold_polys_m as its behavior is trivial.
pub fn fold_polys_n<F: Field, R: Rank, P: Parameters>(
    source: FixedVec<structured::Polynomial<F, R>, P::N>,
    scale_factor: F,
) -> structured::Polynomial<F, R> {
    structured::Polynomial::fold(source.iter(), scale_factor)
}

/// Error computation for revdot folding.
///
/// This computes off-diagonal revdot products for each group of `Inner`
/// polynomials, producing `Outer` groups of error terms.
fn compute_errors_impl<F: Field, R: Rank, Outer: Len, Inner: Len>(
    a: &[impl Borrow<structured::Polynomial<F, R>>],
    b: &[impl Borrow<structured::Polynomial<F, R>>],
) -> FixedVec<FixedVec<F, ErrorTermsLen<Inner>>, Outer> {
    assert_eq!(a.len(), b.len(), "a and b must have same length");
    assert!(
        a.len() <= Outer::len() * Inner::len(),
        "input length {} exceeds Outer*Inner = {}",
        a.len(),
        Outer::len() * Inner::len()
    );

    // Iterate over `Inner::len()`-sized chunks of a and b as pairs.
    a.chunks(Inner::len())
        .zip(b.chunks(Inner::len()))
        // For each chunk, compute off-diagonal revdot products.
        .map(|(a_chunk, b_chunk)| {
            // Computed using the cartesian product of indices, filtering out
            // diagonal entries.
            off_diagonal_pairs(Inner::len())
                // Missing entries are zero polynomials, producing zero revdot products.
                .map(|(i, j)| {
                    a_chunk
                        .get(i)
                        .zip(b_chunk.get(j))
                        .map_or(F::ZERO, |(l, r)| l.borrow().revdot(r.borrow()))
                })
                .collect_fixed()
                .expect("lengths are correct")
        })
        // ... and missing pairs produce zeroed error term groups.
        .chain(iter::repeat_with(|| FixedVec::from_fn(|_| F::ZERO)))
        .take(Outer::len())
        .collect_fixed()
        .expect("lengths are correct")
}

/// Compute errors_m: N groups of M*(M-1) off-diagonal revdot products.
pub fn compute_errors_m<F: Field, R: Rank, P: Parameters>(
    a: &[impl Borrow<structured::Polynomial<F, R>>],
    b: &[impl Borrow<structured::Polynomial<F, R>>],
) -> FixedVec<FixedVec<F, ErrorTermsLen<P::M>>, P::N> {
    compute_errors_impl::<F, R, P::N, P::M>(a, b)
}

/// Compute errors_n: N*(N-1) off-diagonal revdot products.
pub fn compute_errors_n<F: Field, R: Rank, P: Parameters>(
    a: &[impl Borrow<structured::Polynomial<F, R>>],
    b: &[impl Borrow<structured::Polynomial<F, R>>],
) -> FixedVec<F, ErrorTermsLen<P::N>> {
    compute_errors_impl::<F, R, ConstLen<1>, P::N>(a, b)
        .into_iter()
        .next()
        .expect("Outer produces exactly one group")
}

/// Precomputed folding context for computing revdot claim `c`.
///
/// Computing `munu` and `mu_inv` once and reusing across multiple calls
/// saves 2*(N-1) multiplications in the two-layer reduction.
pub struct FoldProducts<'dr, D: Driver<'dr>> {
    munu: Element<'dr, D>,
    mu_inv: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> FoldProducts<'dr, D> {
    /// Create a folding context from mu and nu.
    pub fn new(dr: &mut D, mu: &Element<'dr, D>, nu: &Element<'dr, D>) -> Result<Self> {
        let munu = mu.mul(dr, nu)?;
        let mu_inv = mu.invert(dr)?;
        Ok(Self { munu, mu_inv })
    }

    /// Compute folded revdot claim `c` for layer 1 (M-sized reduction).
    pub fn fold_products_m<P: Parameters>(
        &self,
        dr: &mut D,
        error_terms: &FixedVec<Element<'dr, D>, ErrorTermsLen<P::M>>,
        ky_values: &FixedVec<Element<'dr, D>, P::M>,
    ) -> Result<Element<'dr, D>> {
        fold_products_impl::<_, P::M>(dr, &self.munu, &self.mu_inv, error_terms, ky_values)
    }

    /// Compute folded revdot claim `c` for layer 2 (N-sized reduction).
    pub fn fold_products_n<P: Parameters>(
        &self,
        dr: &mut D,
        error_terms: &FixedVec<Element<'dr, D>, ErrorTermsLen<P::N>>,
        ky_values: &FixedVec<Element<'dr, D>, P::N>,
    ) -> Result<Element<'dr, D>> {
        fold_products_impl::<_, P::N>(dr, &self.munu, &self.mu_inv, error_terms, ky_values)
    }
}

/// Core folding computation using precomputed munu and mu_inv.
fn fold_products_impl<'dr, D: Driver<'dr>, S: Len>(
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
    let mut col_power = row_power.clone();

    let n = S::len();
    for (i, j, is_diagonal) in cartesian_products(n) {
        let term = if is_diagonal {
            ky_values.next().expect("should exist")
        } else {
            error_terms.next().expect("should exist")
        };

        let contribution = col_power.mul(dr, term)?;
        result = result.add(dr, &contribution);

        // Update powers for next iteration.
        if j < n - 1 {
            col_power = col_power.mul(dr, munu)?;
        } else if i < n - 1 {
            row_power = row_power.mul(dr, mu_inv)?;
            col_power = row_power.clone();
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use ragu_circuits::polynomials::{R, structured};
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
        type TestRank = R<4>;
        let n = <P as Parameters>::N::len();
        let mut rng = OsRng;

        // Create N random polynomial pairs
        let lhs: Vec<structured::Polynomial<Fp, TestRank>> = (0..n)
            .map(|_| structured::Polynomial::random(&mut rng))
            .collect();
        let rhs: Vec<structured::Polynomial<Fp, TestRank>> = (0..n)
            .map(|_| structured::Polynomial::random(&mut rng))
            .collect();

        // Compute ky values: diagonal revdot products
        let ky: Vec<Fp> = lhs.iter().zip(&rhs).map(|(l, r)| l.revdot(r)).collect();

        // Compute error terms using compute_errors_n (single-layer N-sized reduction)
        let error_terms = compute_errors_n::<Fp, TestRank, P>(&lhs, &rhs);
        let error: Vec<Fp> = error_terms.iter().copied().collect();

        let mu = Fp::random(&mut rng);
        let nu = Fp::random(&mut rng);
        let mu_inv = mu.invert().unwrap();
        let munu = mu * nu;

        // Fold polynomials
        let folded_lhs = structured::Polynomial::fold(lhs.iter(), mu_inv);
        let folded_rhs = structured::Polynomial::fold(rhs.iter(), munu);

        // Run routine with Emulator
        let dr = &mut Emulator::execute();
        let mu_elem = Element::constant(dr, mu);
        let nu_elem = Element::constant(dr, nu);

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

        let fold_products = FoldProducts::new(dr, &mu_elem, &nu_elem)?;
        let result = fold_products.fold_products_n::<P>(dr, &error_terms, &ky_values)?;
        let computed_c = *result.value().take();

        // Verify the folding invariant: folded polynomials produce the same c
        assert_eq!(
            folded_lhs.revdot(&folded_rhs),
            computed_c,
            "Folded polynomials should produce the same c as FoldProducts"
        );

        Ok(())
    }

    #[test]
    fn test_fold_products_constraints() -> Result<()> {
        fn measure<P: Parameters>() -> Result<usize> {
            let sim = Simulator::simulate((), |dr, _| {
                let mu = Element::constant(dr, Fp::random(OsRng));
                let nu = Element::constant(dr, Fp::random(OsRng));
                let error_terms = FixedVec::from_fn(|_| Element::constant(dr, Fp::random(OsRng)));
                let ky_values = FixedVec::from_fn(|_| Element::constant(dr, Fp::random(OsRng)));

                let fold_products = FoldProducts::new(dr, &mu, &nu)?;
                fold_products.fold_products_n::<P>(dr, &error_terms, &ky_values)?;
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
        /// Verify two-layer folding correctness with actual polynomials.
        fn verify<P: Parameters>() -> Result<()> {
            type TestRank = R<4>;
            let mut rng = OsRng;
            let n = P::N::len();
            let m = P::M::len();
            let count = n * m;

            // Create N*M random polynomial pairs
            let lhs: Vec<structured::Polynomial<Fp, TestRank>> = (0..count)
                .map(|_| structured::Polynomial::random(&mut rng))
                .collect();
            let rhs: Vec<structured::Polynomial<Fp, TestRank>> = (0..count)
                .map(|_| structured::Polynomial::random(&mut rng))
                .collect();

            // Compute ky values: diagonal revdot products
            let ky_values: Vec<Fp> = lhs.iter().zip(&rhs).map(|(l, r)| l.revdot(r)).collect();

            // Layer 1 challenges
            let mu = Fp::random(&mut rng);
            let nu = Fp::random(&mut rng);
            let mu_inv = mu.invert().unwrap();
            let munu = mu * nu;

            // Compute error_m: N groups of M*(M-1) off-diagonal revdot products
            let error_m = compute_errors_m::<Fp, TestRank, P>(&lhs, &rhs);

            // Fold polynomials for layer 1
            let folded_lhs = fold_polys_m::<Fp, TestRank, P>(&lhs, mu_inv);
            let folded_rhs = fold_polys_m::<Fp, TestRank, P>(&rhs, munu);

            // Compute collapsed values via FoldProducts
            let collapsed: FixedVec<Fp, P::N> =
                Emulator::emulate_wireless((&error_m, &ky_values, mu, nu), |dr, witness| {
                    let (error_m, ky_values, mu, nu) = witness.cast();
                    let mu = Element::alloc(dr, mu)?;
                    let nu = Element::alloc(dr, nu)?;
                    let fold_products = FoldProducts::new(dr, &mu, &nu)?;

                    let mut ky_idx = 0;
                    let collapsed = FixedVec::try_from_fn(|group| {
                        let errors = FixedVec::try_from_fn(|j| {
                            Element::alloc(dr, error_m.view().map(|e| e[group][j]))
                        })?;
                        let ky = FixedVec::try_from_fn(|_| {
                            let idx = ky_idx;
                            ky_idx += 1;
                            Element::alloc(dr, ky_values.view().map(|kv| kv[idx]))
                        })?;
                        let v = fold_products.fold_products_m::<P>(dr, &errors, &ky)?;
                        Ok(*v.value().take())
                    })?;
                    Ok(collapsed)
                })?;

            // Verify layer 1 invariant: each collapsed[i] == folded_lhs[i].revdot(&folded_rhs[i])
            for i in 0..n {
                assert_eq!(
                    folded_lhs[i].revdot(&folded_rhs[i]),
                    collapsed[i],
                    "Layer 1 group {} invariant failed",
                    i
                );
            }

            // Layer 2 challenges
            let mu_prime = Fp::random(&mut rng);
            let nu_prime = Fp::random(&mut rng);
            let mu_prime_inv = mu_prime.invert().unwrap();
            let mu_prime_nu_prime = mu_prime * nu_prime;

            // Compute error_n from layer 1 folded polynomials
            let error_n = compute_errors_n::<Fp, TestRank, P>(&folded_lhs, &folded_rhs);

            // Fold to final polynomials
            let final_lhs = fold_polys_n::<Fp, TestRank, P>(folded_lhs, mu_prime_inv);
            let final_rhs = fold_polys_n::<Fp, TestRank, P>(folded_rhs, mu_prime_nu_prime);

            // Compute final c via FoldProducts
            let final_c: Fp = Emulator::emulate_wireless(
                (&error_n, &collapsed, mu_prime, nu_prime),
                |dr, witness| {
                    let (error_n, collapsed, mu_prime, nu_prime) = witness.cast();
                    let mu_prime = Element::alloc(dr, mu_prime)?;
                    let nu_prime = Element::alloc(dr, nu_prime)?;
                    let fold_products = FoldProducts::new(dr, &mu_prime, &nu_prime)?;

                    let error_terms = FixedVec::try_from_fn(|i| {
                        Element::alloc(dr, error_n.view().map(|e| e[i]))
                    })?;
                    let collapsed = FixedVec::try_from_fn(|i| {
                        Element::alloc(dr, collapsed.view().map(|c| c[i]))
                    })?;

                    let c = fold_products.fold_products_n::<P>(dr, &error_terms, &collapsed)?;
                    Ok(*c.value().take())
                },
            )?;

            // Verify final invariant: final_lhs.revdot(&final_rhs) == final_c
            assert_eq!(
                final_lhs.revdot(&final_rhs),
                final_c,
                "Final folding invariant failed"
            );

            Ok(())
        }

        // Test various parameter combinations
        verify::<TestParams<2, 2>>()?;
        verify::<TestParams<3, 3>>()?;
        verify::<TestParams<4, 3>>()?;
        verify::<TestParams<3, 4>>()?;

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
                let fold_products_layer1 = FoldProducts::new(dr, &mu, &nu)?;
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
                    fold_products_layer1.fold_products_m::<TestParams<N, M>>(
                        dr,
                        &all_error_terms_m[i],
                        &all_ky_values_m[i],
                    )
                })?;

                // Layer 2: Single N-sized reduction (uses mu', nu' - separate FoldProducts).
                let fold_products_layer2 = FoldProducts::new(dr, &mu_prime, &nu_prime)?;
                let error_terms_n: FixedVec<_, ErrorTermsLen<ConstLen<N>>> =
                    FixedVec::try_from_fn(|_| Element::alloc(dr, rng.view_mut().map(Fp::random)))?;

                fold_products_layer2.fold_products_n::<TestParams<N, M>>(
                    dr,
                    &error_terms_n,
                    &collapsed,
                )?;
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
