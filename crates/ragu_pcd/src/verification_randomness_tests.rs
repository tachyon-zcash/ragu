//! O11: exact local countermodels for known verifier randomness, with the
//! production cache batch and polynomial evaluator. These use real fields
//! and curves, but grant the attacker the check's scalar before the edit.
//!
//! Calibration: dropping the first polynomial and cache from the production
//! batch fails the single-error assertion at position zero. This source
//! mutant was checked and restored.

use alloc::vec::Vec;

use ragu_arithmetic::{Cycle, group::Curve};
use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::TestRank;
use ragu_pasta::Pasta;
use rand::{SeedableRng, rngs::StdRng};

use super::*;

fn cache_batch<F, P, G>(generators: &G)
where
    F: PrimeField,
    P: CurveAffine<ScalarExt = F>,
    G: FixedGenerators<P>,
{
    const LEN: usize = 6;
    let polys: Vec<sparse::Polynomial<F, TestRank>> = (0..LEN)
        .map(|i| {
            sparse::Polynomial::from_coeffs(alloc::vec![
                F::from(i as u64 + 2),
                F::from(i as u64 + 13)
            ])
        })
        .collect();
    let refs: Vec<_> = polys.iter().collect();
    let honest: Vec<P> = polys
        .iter()
        .map(|p| ReferenceBackend::sparse_commit_to_affine(p, generators))
        .collect();
    let check = |points: &[P], r: F| {
        commitments_match::<ReferenceBackend, _, _, TestRank, _>(&refs, points, r, generators)
    };
    let chosen = F::from(7);
    let delta = generators.g()[0] * F::from(13);
    assert!(check(&honest, chosen));
    assert!(check(&honest, F::ZERO));

    // A single error has coefficient r^(LEN-1-i). At zero all but the
    // constant term disappear; at a nonzero scalar every position matters.
    for i in 0..LEN {
        let mut points = honest.clone();
        points[i] = (points[i].to_curve() + delta).to_affine();
        assert!(!check(&points, chosen), "single cache error at {i}");
        assert_eq!(check(&points, F::ZERO), i != LEN - 1);
    }

    for i in 0..LEN {
        for j in i + 1..LEN {
            let mut points = honest.clone();
            points[i] = (points[i].to_curve() + delta).to_affine();
            let repair = chosen.pow_vartime([(j - i) as u64]);
            points[j] = (points[j].to_curve() - delta * repair).to_affine();
            assert_ne!(points[i], honest[i]);
            assert_ne!(points[j], honest[j]);
            assert!(check(&points, chosen), "nonzero cancellation: {i}, {j}");

            // Independent coefficient formula predicts precisely which
            // scalar choices hide this fixed pair, including zero.
            let mut roots = 0;
            for r in (0..19).map(F::from) {
                let residual = r.pow_vartime([(LEN - 1 - i) as u64])
                    - repair * r.pow_vartime([(LEN - 1 - j) as u64]);
                let accepted = check(&points, r);
                assert_eq!(accepted, residual == F::ZERO, "pair {i}, {j}");
                roots += usize::from(accepted);
            }
            assert!(roots > 0 && roots <= LEN - 1 - i);
            // The degree bound gives at most (LEN-1-i)/|F| failure
            // probability for a uniform independent scalar. This finite
            // regression sample does not estimate that negligible rate.
            let mut rng = StdRng::seed_from_u64(0x0011_cace + (i * LEN + j) as u64);
            for _ in 0..4 {
                assert!(!check(&points, F::random(&mut rng)));
            }
        }
    }
}

#[test]
fn every_cache_pair_obeys_the_independent_error_polynomial() {
    cache_batch::<<Pasta as Cycle>::CircuitField, <Pasta as Cycle>::HostCurve, _>(
        Pasta::host_generators(Pasta::baked()),
    );
    cache_batch::<<Pasta as Cycle>::ScalarField, <Pasta as Cycle>::NestedCurve, _>(
        Pasta::nested_generators(Pasta::baked()),
    );
}

fn evaluation_roots<F: PrimeField>() {
    let roots = [F::ZERO, F::from(7), F::from(11)];
    // Dense coefficient multiplication is independent of the sparse
    // evaluator and quotient helpers used in production.
    let mut error = alloc::vec![F::from(13)];
    for root in roots {
        let mut product = alloc::vec![F::ZERO; error.len() + 1];
        for (i, coefficient) in error.iter().enumerate() {
            product[i] -= *coefficient * root;
            product[i + 1] += coefficient;
        }
        error = product;
    }
    let original = alloc::vec![F::from(19), F::from(23), F::from(29), F::from(31)];
    let changed: Vec<_> = original.iter().zip(&error).map(|(a, b)| *a + b).collect();
    assert_ne!(original, changed);
    let before = sparse::Polynomial::<F, TestRank>::from_coeffs(original);
    let after = sparse::Polynomial::<F, TestRank>::from_coeffs(changed);
    let residual =
        |x| ReferenceBackend::sparse_eval(&after, x) - ReferenceBackend::sparse_eval(&before, x);
    let mut root_count = 0;
    for x in (0..19).map(F::from) {
        let expected = F::from(13) * x * (x - roots[1]) * (x - roots[2]);
        assert_eq!(residual(x), expected);
        assert_eq!(expected == F::ZERO, roots.contains(&x));
        root_count += usize::from(expected == F::ZERO);
    }
    assert_eq!(root_count, error.len() - 1);
    let mut rng = StdRng::seed_from_u64(0x0011_ea17);
    for _ in 0..16 {
        assert_ne!(residual(F::random(&mut rng)), F::ZERO);
    }
}

#[test]
fn fixed_polynomial_errors_vanish_at_known_queries_but_not_fresh_ones() {
    evaluation_roots::<<Pasta as Cycle>::CircuitField>();
    evaluation_roots::<<Pasta as Cycle>::ScalarField>();
}
