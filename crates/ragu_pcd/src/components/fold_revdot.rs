//! Operations and utilities for reasoning about folded revdot claims.

use ff::Field;
use ragu_circuits::polynomials::{Rank, structured};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{
    Element,
    io::Buffer,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::horner::Horner;

use core::{borrow::Borrow, iter, marker::PhantomData};

/// The parameters $(m, n)$ that dictate the multi-layer revdot reduction.
///
/// The first layer involves $n$ instances of size-$m$ revdot reductions, and
/// the second layer reduces these into a single revdot using a single size-$n$
/// revdot reduction.
///
/// The parameters here collapse as much as $m \cdot n$ claims into a single
/// claim using roughly $f(m, n) = nm^2 + n^2 - n + 3$ multiplication
/// constraints (using nested Horner evaluation).
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

    let m = P::M::len();
    source
        .chunks(m)
        .map(|chunk| {
            structured::Polynomial::fold(
                chunk
                    .iter()
                    .map(|p| p.borrow().clone())
                    .chain(iter::repeat_with(structured::Polynomial::new).take(m - chunk.len())),
                scale_factor,
            )
        })
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

    let mut outer_horner = Horner::new(mu_inv);

    let n = S::len();
    for i in 0..n {
        let mut inner_horner = Horner::new(munu);
        for j in 0..n {
            let term = if i == j {
                ky_values.next().expect("should exist")
            } else {
                error_terms.next().expect("should exist")
            };
            inner_horner.write(dr, term)?;
        }
        let row_result = inner_horner.finish(dr);
        outer_horner.write(dr, &row_result)?;
    }

    Ok(outer_horner.finish(dr))
}

pub fn fold_two_layer<'dr, D: Driver<'dr>, P: Parameters>(
    dr: &mut D,
    sources: &[Element<'dr, D>],
    layer1_scale: &Element<'dr, D>,
    layer2_scale: &Element<'dr, D>,
) -> Result<Element<'dr, D>> {
    let m = P::M::len();
    let mut results = alloc::vec::Vec::with_capacity(P::N::len());

    let zero = Element::zero(dr);
    for chunk in sources.chunks(m) {
        results.push(Element::fold(
            dr,
            chunk.iter().chain(iter::repeat_n(&zero, m - chunk.len())),
            layer1_scale,
        )?);
    }

    while results.len() < P::N::len() {
        results.push(zero.clone());
    }

    Element::fold(dr, results.iter(), layer2_scale)
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

    /// Test parameters with configurable N and M.
    #[derive(Clone, Copy, Default)]
    struct TestParams<const N: usize, const M: usize>;
    impl<const N: usize, const M: usize> Parameters for TestParams<N, M> {
        type N = ConstLen<N>;
        type M = ConstLen<M>;
    }

    #[test]
    fn test_revdot_folding() -> Result<()> {
        type P = TestParams<3, 3>;
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
    fn test_fold_polys_variable_sizes() -> Result<()> {
        use alloc::vec::Vec;

        type P = TestParams<6, 5>; // M=5, N=6, so max = 30
        type TestRank = R<4>;
        let m = <P as Parameters>::M::len();
        let n = <P as Parameters>::N::len();

        fn verify(count: usize, m: usize, n: usize) -> Result<()> {
            let mut rng = OsRng;

            // Create `count` random polynomial pairs
            let lhs: Vec<structured::Polynomial<Fp, TestRank>> = (0..count)
                .map(|_| structured::Polynomial::random(&mut rng))
                .collect();
            let rhs: Vec<structured::Polynomial<Fp, TestRank>> = (0..count)
                .map(|_| structured::Polynomial::random(&mut rng))
                .collect();

            // Compute diagonal revdot products (ky values)
            let ky_values: Vec<Fp> = lhs.iter().zip(&rhs).map(|(l, r)| l.revdot(r)).collect();

            // Layer 1 challenges
            let mu = Fp::random(&mut rng);
            let nu = Fp::random(&mut rng);
            let mu_inv = mu.invert().unwrap();
            let munu = mu * nu;

            // Compute error_m and fold polynomials for layer 1
            let error_m = compute_errors_m::<Fp, TestRank, P>(&lhs, &rhs);
            let folded_lhs_m = fold_polys_m::<Fp, TestRank, P>(&lhs, mu_inv);
            let folded_rhs_m = fold_polys_m::<Fp, TestRank, P>(&rhs, munu);

            // Verify layer 1 invariant for each group
            let dr = &mut Emulator::execute();
            let mu_elem = Element::constant(dr, mu);
            let nu_elem = Element::constant(dr, nu);
            let fold_products = FoldProducts::new(dr, &mu_elem, &nu_elem)?;

            for g in 0..n {
                // Compute expected claim from folded polynomials
                let expected = folded_lhs_m[g].revdot(&folded_rhs_m[g]);

                // Compute claim via FoldProducts
                let ky_start = g * m;
                let ky_end = (ky_start + m).min(count);
                let ky_group: FixedVec<Element<'_, _>, _> = FixedVec::from_fn(|i| {
                    let val = if ky_start + i < ky_end {
                        ky_values[ky_start + i]
                    } else {
                        Fp::ZERO
                    };
                    Element::constant(dr, val)
                });
                let error_group: FixedVec<Element<'_, _>, _> =
                    FixedVec::from_fn(|i| Element::constant(dr, error_m[g][i]));

                let computed = fold_products.fold_products_m::<P>(dr, &error_group, &ky_group)?;
                let computed_val = *computed.value().take();

                assert_eq!(
                    expected, computed_val,
                    "Layer 1 group {} invariant failed for count={}",
                    g, count
                );
            }

            Ok(())
        }

        // Test various sizes below or equal to M*N
        for &count in &[1, 2, 5, 7, 10, 15, 20, 25, 29, 30] {
            verify(count, m, n)?;
        }

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

        // Formula: N^2 + 1
        assert_eq!(measure::<TestParams<5, 1>>()?, 26);
        assert_eq!(measure::<TestParams<15, 1>>()?, 226);
        assert_eq!(measure::<TestParams<30, 1>>()?, 901);
        assert_eq!(measure::<TestParams<60, 1>>()?, 3601);

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

    #[test]
    fn test_fold_two_layer_evaluations() -> Result<()> {
        use alloc::vec::Vec;

        /// Verify fold_two_layer on evaluations matches evaluating folded polynomials
        /// for both lhs and rhs polynomial sets with their respective scale factors.
        fn verify<P: Parameters>(count: usize) -> Result<()> {
            type TestRank = R<4>;
            let mut rng = OsRng;

            // Create `count` random polynomial pairs (up to m*n)
            let lhs: Vec<structured::Polynomial<Fp, TestRank>> = (0..count)
                .map(|_| structured::Polynomial::random(&mut rng))
                .collect();
            let rhs: Vec<structured::Polynomial<Fp, TestRank>> = (0..count)
                .map(|_| structured::Polynomial::random(&mut rng))
                .collect();

            // Random evaluation point
            let x = Fp::random(&mut rng);

            // Challenge values (matching compute_v.rs usage pattern)
            let mu = Fp::random(&mut rng);
            let nu = Fp::random(&mut rng);
            let mu_prime = Fp::random(&mut rng);
            let nu_prime = Fp::random(&mut rng);

            // Derived scale factors for lhs: mu_inv, mu_prime_inv
            let mu_inv = mu.invert().unwrap();
            let mu_prime_inv = mu_prime.invert().unwrap();

            // Derived scale factors for rhs: munu, mu_prime_nu_prime
            let munu = mu * nu;
            let mu_prime_nu_prime = mu_prime * nu_prime;

            // === LHS: fold with mu_inv (layer1), mu_prime_inv (layer2) ===
            let folded_lhs_m = fold_polys_m::<Fp, TestRank, P>(&lhs, mu_inv);
            let folded_lhs_n = fold_polys_n::<Fp, TestRank, P>(folded_lhs_m, mu_prime_inv);
            let expected_lhs = folded_lhs_n.eval(x);

            // === RHS: fold with munu (layer1), mu_prime_nu_prime (layer2) ===
            let folded_rhs_m = fold_polys_m::<Fp, TestRank, P>(&rhs, munu);
            let folded_rhs_n = fold_polys_n::<Fp, TestRank, P>(folded_rhs_m, mu_prime_nu_prime);
            let expected_rhs = folded_rhs_n.eval(x);

            // Compute evaluations at x
            let lhs_evals: Vec<Fp> = lhs.iter().map(|p| p.eval(x)).collect();
            let rhs_evals: Vec<Fp> = rhs.iter().map(|p| p.eval(x)).collect();

            // Fold evaluations using fold_two_layer with Emulator
            let dr = &mut Emulator::execute();

            let lhs_elems: Vec<Element<'_, _>> = lhs_evals
                .iter()
                .map(|&v| Element::constant(dr, v))
                .collect();
            let rhs_elems: Vec<Element<'_, _>> = rhs_evals
                .iter()
                .map(|&v| Element::constant(dr, v))
                .collect();

            let mu_inv_elem = Element::constant(dr, mu_inv);
            let mu_prime_inv_elem = Element::constant(dr, mu_prime_inv);
            let munu_elem = Element::constant(dr, munu);
            let mu_prime_nu_prime_elem = Element::constant(dr, mu_prime_nu_prime);

            let lhs_result =
                fold_two_layer::<_, P>(dr, &lhs_elems, &mu_inv_elem, &mu_prime_inv_elem)?;
            let rhs_result =
                fold_two_layer::<_, P>(dr, &rhs_elems, &munu_elem, &mu_prime_nu_prime_elem)?;

            let computed_lhs = *lhs_result.value().take();
            let computed_rhs = *rhs_result.value().take();

            assert_eq!(
                expected_lhs, computed_lhs,
                "fold_two_layer(lhs_evals) should equal fold_polys(lhs).eval(x)"
            );
            assert_eq!(
                expected_rhs, computed_rhs,
                "fold_two_layer(rhs_evals) should equal fold_polys(rhs).eval(x)"
            );

            Ok(())
        }

        // Test with various parameter combinations and various sizes
        for &count in &[1, 2, 3, 4] {
            verify::<TestParams<2, 2>>(count)?;
        }
        for &count in &[1, 3, 5, 7, 9] {
            verify::<TestParams<3, 3>>(count)?;
        }
        for &count in &[1, 4, 7, 10, 12] {
            verify::<TestParams<4, 3>>(count)?;
        }
        for &count in &[1, 4, 7, 10, 12] {
            verify::<TestParams<3, 4>>(count)?;
        }

        // Test native parameters (6*18=108) with various sizes
        for &count in &[1, 10, 33, 50, 80, 100, 108] {
            verify::<TestParams<6, 18>>(count)?;
        }

        Ok(())
    }

    /// Computes the number of multiplication constraints for given M, N.
    ///
    /// Formula: NM^2 + N^2 - N + 3
    /// - Layer 1: 2 + N(M^2 - 1) = NM^2 - N + 2
    /// - Layer 2: 2 + (N^2 - 1) = N^2 + 1
    fn muls(m: usize, n: usize) -> usize {
        n * m * m + n * n - n + 3
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
            Ok(())
        }

        verify::<6, 17>()?;
        verify::<7, 14>()?;

        // Verify optimal parameters fit circuit budget (separate from verify loop)
        let effective_cost = 2 * muls(6, 17) + allocs(6, 17);
        assert!(
            effective_cost < (2 * (1 << 11)),
            "M = 6, N = 17 exceeds budget: {}",
            effective_cost / 2
        );

        Ok(())
    }

    #[test]
    fn test_empty_input() {
        type P = TestParams<3, 3>;
        type TestRank = R<4>;
        let n = <P as Parameters>::N::len();

        // Empty input should produce all-zero folded polynomials
        let empty: Vec<structured::Polynomial<Fp, TestRank>> = vec![];
        let folded = fold_polys_m::<Fp, TestRank, P>(&empty, Fp::ONE);

        // All N groups should be zero polynomials
        for g in 0..n {
            assert!(
                folded[g].iter_coeffs().all(|c| c == Fp::ZERO),
                "Group {} should be zero polynomial for empty input",
                g
            );
        }

        // Error computation on empty input should produce zero errors
        let error_m = compute_errors_m::<Fp, TestRank, P>(&empty, &empty);
        for g in 0..n {
            for e in error_m[g].iter() {
                assert_eq!(*e, Fp::ZERO, "Error terms should be zero for empty input");
            }
        }
    }

    #[test]
    #[should_panic(expected = "exceeds M*N")]
    fn test_fold_polys_m_overflow_panics() {
        type P = TestParams<2, 2>; // max = 4
        type TestRank = R<4>;

        // Create 5 polynomials, which exceeds M*N=4
        let polys: Vec<_> = (0..5)
            .map(|_| structured::Polynomial::<Fp, TestRank>::new())
            .collect();
        let _ = fold_polys_m::<Fp, TestRank, P>(&polys, Fp::ONE);
    }

    #[test]
    fn test_error_term_ordering() {
        type TestRank = R<4>;
        let mut rng = OsRng;

        // Create 3 distinct polynomial pairs
        let a: Vec<structured::Polynomial<Fp, TestRank>> = (0..3)
            .map(|_| structured::Polynomial::random(&mut rng))
            .collect();
        let b: Vec<structured::Polynomial<Fp, TestRank>> = (0..3)
            .map(|_| structured::Polynomial::random(&mut rng))
            .collect();

        // Compute error terms (should be 3*(3-1)=6 terms)
        let errors = compute_errors_n::<Fp, TestRank, TestParams<3, 3>>(&a, &b);

        // Verify row-major ordering: (0,1), (0,2), (1,0), (1,2), (2,0), (2,1)
        let expected_pairs = [(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)];
        for (idx, &(i, j)) in expected_pairs.iter().enumerate() {
            let expected = a[i].revdot(&b[j]);
            assert_eq!(
                errors[idx], expected,
                "Error term {} should be revdot(a[{}], b[{}])",
                idx, i, j
            );
        }
    }

    #[test]
    fn test_fold_products_m_constraints() -> Result<()> {
        // Verify layer 1 constraint count formula: 2M^2 + 1 per group
        fn measure_m<const M: usize>() -> Result<usize> {
            let sim = Simulator::simulate((), |dr, _| {
                let mu = Element::constant(dr, Fp::random(OsRng));
                let nu = Element::constant(dr, Fp::random(OsRng));
                let error_terms: FixedVec<_, ErrorTermsLen<ConstLen<M>>> =
                    FixedVec::from_fn(|_| Element::constant(dr, Fp::random(OsRng)));
                let ky_values: FixedVec<_, ConstLen<M>> =
                    FixedVec::from_fn(|_| Element::constant(dr, Fp::random(OsRng)));

                let fold_products = FoldProducts::new(dr, &mu, &nu)?;
                fold_products.fold_products_m::<TestParams<1, M>>(dr, &error_terms, &ky_values)?;
                Ok(())
            })?;

            Ok(sim.num_multiplications())
        }

        // Formula: M^2 + 1
        assert_eq!(measure_m::<3>()?, 9 + 1); // 10
        assert_eq!(measure_m::<5>()?, 25 + 1); // 26
        assert_eq!(measure_m::<6>()?, 36 + 1); // 37

        Ok(())
    }

    #[test]
    fn test_native_parameters_correctness() -> Result<()> {
        // Test with actual NativeParameters (M=6, N=18)
        type TestRank = R<4>;
        let mut rng = OsRng;
        let m = <NativeParameters as Parameters>::M::len();
        let _n = <NativeParameters as Parameters>::N::len();

        // Use a subset of the full capacity to keep test fast
        let count: usize = 20; // Less than M*N=108

        let lhs: Vec<structured::Polynomial<Fp, TestRank>> = (0..count)
            .map(|_| structured::Polynomial::random(&mut rng))
            .collect();
        let rhs: Vec<structured::Polynomial<Fp, TestRank>> = (0..count)
            .map(|_| structured::Polynomial::random(&mut rng))
            .collect();

        let mu = Fp::random(&mut rng);
        let nu = Fp::random(&mut rng);
        let mu_inv = mu.invert().unwrap();
        let munu = mu * nu;

        // Fold with NativeParameters
        let folded_lhs = fold_polys_m::<Fp, TestRank, NativeParameters>(&lhs, mu_inv);
        let folded_rhs = fold_polys_m::<Fp, TestRank, NativeParameters>(&rhs, munu);

        // Verify at least the first few groups
        let dr = &mut Emulator::execute();
        let mu_elem = Element::constant(dr, mu);
        let nu_elem = Element::constant(dr, nu);
        let fold_products = FoldProducts::new(dr, &mu_elem, &nu_elem)?;

        let ky_values: Vec<Fp> = lhs.iter().zip(&rhs).map(|(l, r)| l.revdot(r)).collect();
        let error_m = compute_errors_m::<Fp, TestRank, NativeParameters>(&lhs, &rhs);

        // Check first 4 groups (those with actual data)
        let num_groups = count.div_ceil(m);
        for g in 0..num_groups {
            let expected = folded_lhs[g].revdot(&folded_rhs[g]);

            let ky_start = g * m;
            let ky_end = (ky_start + m).min(count);
            let ky_group: FixedVec<Element<'_, _>, _> = FixedVec::from_fn(|i| {
                let val = if ky_start + i < ky_end {
                    ky_values[ky_start + i]
                } else {
                    Fp::ZERO
                };
                Element::constant(dr, val)
            });
            let error_group: FixedVec<Element<'_, _>, _> =
                FixedVec::from_fn(|i| Element::constant(dr, error_m[g][i]));

            let computed =
                fold_products.fold_products_m::<NativeParameters>(dr, &error_group, &ky_group)?;
            let computed_val = *computed.value().take();

            assert_eq!(
                expected, computed_val,
                "NativeParameters: group {} invariant failed",
                g
            );
        }

        Ok(())
    }
}
