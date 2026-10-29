//! Backend scheduling and dense-oracle checks for both quotient-fold layers.

use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use ragu_acceleration::{AcceleratedBackend, AcceleratedProver};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{Rank, TestRank, sparse};
use ragu_core::pasta::{Fp, Fq};
use ragu_primitives::vec::ConstLen;
use udon::field::Field;

use super::{Parameters, inner_error_terms_with_backend, outer_error_terms_with_backend};

#[derive(Clone, Copy, Default)]
struct TestParams<const N: usize, const M: usize>;

impl<const N: usize, const M: usize> Parameters for TestParams<N, M> {
    type NumGroups = ConstLen<N>;
    type GroupSize = ConstLen<M>;
}

/// Check Z(r) Q(r) = revdot(A(r), B(r)) - K(r) using dense coefficients.
/// The m distinct non-node points determine the quotient of degree at most m-2.
fn check_quotient<F: Field>(
    a: &[sparse::Polynomial<F, TestRank>],
    b: &[sparse::Polynomial<F, TestRank>],
    quotient: &[F],
    m: usize,
) {
    assert_eq!(quotient.len(), m - 1);
    for r in m..2 * m {
        let r = F::from(r as u64);
        let weights: Vec<_> = (0..m)
            .map(|i| {
                (0..m)
                    .filter(|&j| i != j)
                    .map(|j| {
                        (r - F::from(j as u64))
                            * (F::from(i as u64) - F::from(j as u64)).invert().unwrap()
                    })
                    .product::<F>()
            })
            .collect();
        let mut a_fold = vec![F::ZERO; TestRank::num_coeffs()];
        let mut b_fold = vec![F::ZERO; TestRank::num_coeffs()];
        let mut target = F::ZERO;
        for ((a, b), weight) in a.iter().zip(b).zip(weights) {
            for (sum, coefficient) in a_fold.iter_mut().zip(a.iter_coeffs()) {
                *sum += weight * coefficient;
            }
            for (sum, coefficient) in b_fold.iter_mut().zip(b.iter_coeffs()) {
                *sum += weight * coefficient;
            }
            target += weight
                * a.iter_coeffs()
                    .zip(b.iter_coeffs().rev())
                    .map(|(a, b)| a * b)
                    .sum::<F>();
        }
        let folded_product = a_fold
            .into_iter()
            .zip(b_fold.into_iter().rev())
            .map(|(a, b)| a * b)
            .sum::<F>();
        let z = (0..m).map(|i| r - F::from(i as u64)).product::<F>();
        let q = quotient.iter().rev().fold(F::ZERO, |sum, &c| sum * r + c);
        assert_eq!(z * q, folded_product - target);
    }
}

#[test]
fn parallel_quotients_match_dense_oracle_with_padding() {
    fn check<F: Field>() {
        type P = TestParams<3, 4>;
        let polys = |offset| {
            (0..12)
                .map(|i| {
                    sparse::Polynomial::<F, TestRank>::from_coeffs(
                        (0..TestRank::num_coeffs())
                            .map(|degree| {
                                if i == 0 || (degree + i + offset) % 4 == 0 {
                                    F::ZERO
                                } else {
                                    F::from((i * 31 + degree * 7 + offset) as u64)
                                }
                            })
                            .collect(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let (a, b) = (polys(1), polys(2));
        for count in [0, 1, 3, 4, 5, 11, 12] {
            let (a, b) = (&a[..count], &b[..count]);
            fn inner<B: Backend, F: Field>(
                a: &[sparse::Polynomial<F, TestRank>],
                b: &[sparse::Polynomial<F, TestRank>],
            ) -> Vec<F> {
                inner_error_terms_with_backend::<B, F, TestRank, P>(a, b)
                    .into_iter()
                    .flat_map(|group| group.into_iter())
                    .collect()
            }
            let expected = inner::<ReferenceBackend, F>(a, b);
            for (group, quotient) in expected.chunks(3).enumerate() {
                let start = (group * 4).min(count);
                let end = (start + 4).min(count);
                check_quotient(&a[start..end], &b[start..end], quotient, 4);
            }
            assert_eq!(inner::<AcceleratedBackend, F>(a, b), expected);
            assert_eq!(inner::<AcceleratedProver, F>(a, b), expected);
        }
        for count in 0..=3 {
            let (a, b) = (&a[..count], &b[..count]);
            let expected = outer_error_terms_with_backend::<ReferenceBackend, F, TestRank, P>(a, b);
            check_quotient(a, b, &expected, 3);
            assert_eq!(
                &*outer_error_terms_with_backend::<AcceleratedBackend, F, TestRank, P>(a, b),
                &*expected
            );
            assert_eq!(
                &*outer_error_terms_with_backend::<AcceleratedProver, F, TestRank, P>(a, b),
                &*expected
            );
        }
    }
    for workers in [1, 4] {
        maybe_rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                check::<Fp>();
                check::<Fq>();
            });
    }
}

static SCHEDULE_CALLS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Default)]
struct SchedulingBackend;

impl Backend for SchedulingBackend {
    fn map<I: IntoIterator, T: Send>(
        inputs: I,
        work: impl Fn(I::Item) -> T + Sync,
    ) -> impl Iterator<Item = T>
    where
        I::Item: Send,
    {
        SCHEDULE_CALLS.fetch_add(1, Ordering::Relaxed);
        AcceleratedBackend::map(inputs, work)
    }
}

#[test]
fn both_quotient_layers_use_backend_scheduling() {
    type P = TestParams<3, 4>;
    let polys: Vec<_> = (1..=5)
        .map(|i| {
            sparse::Polynomial::<Fp, TestRank>::from_coeffs(vec![
                Fp::from(i);
                TestRank::num_coeffs()
            ])
        })
        .collect();
    SCHEDULE_CALLS.store(0, Ordering::Relaxed);
    let inner = inner_error_terms_with_backend::<SchedulingBackend, _, TestRank, P>(&polys, &polys);
    assert!(SCHEDULE_CALLS.load(Ordering::Relaxed) > 0);
    for (group, quotient) in inner.iter().enumerate() {
        let start = (group * 4).min(polys.len());
        let end = (start + 4).min(polys.len());
        check_quotient(&polys[start..end], &polys[start..end], quotient, 4);
    }

    SCHEDULE_CALLS.store(0, Ordering::Relaxed);
    let outer = outer_error_terms_with_backend::<SchedulingBackend, _, TestRank, P>(
        &polys[..3],
        &polys[..3],
    );
    assert!(SCHEDULE_CALLS.load(Ordering::Relaxed) > 0);
    check_quotient(&polys[..3], &polys[..3], &outer, 3);
}
