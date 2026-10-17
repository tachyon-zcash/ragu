//! Backend equivalence for both folding error-term layers.

use alloc::vec::Vec;

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

#[test]
fn parallel_errors_match_dense_oracle_with_padding() {
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
        let dense = |a: Option<&sparse::Polynomial<F, TestRank>>,
                     b: Option<&sparse::Polynomial<F, TestRank>>| {
            a.zip(b).map_or(F::ZERO, |(a, b)| {
                a.iter_coeffs()
                    .zip(b.iter_coeffs().rev())
                    .fold(F::ZERO, |sum, (a, b)| sum + a * b)
            })
        };
        for count in [0, 1, 3, 4, 5, 11, 12] {
            let (a, b) = (&a[..count], &b[..count]);
            let mut expected = Vec::new();
            for group in 0..3 {
                for i in 0..4 {
                    for j in 0..4 {
                        if i != j {
                            expected.push(dense(a.get(group * 4 + i), b.get(group * 4 + j)));
                        }
                    }
                }
            }
            fn inner<B: Backend, F: Field>(
                a: &[sparse::Polynomial<F, TestRank>],
                b: &[sparse::Polynomial<F, TestRank>],
            ) -> Vec<F> {
                inner_error_terms_with_backend::<B, F, TestRank, P>(a, b)
                    .into_iter()
                    .flat_map(|group| group.into_iter())
                    .collect()
            }
            assert_eq!(inner::<ReferenceBackend, F>(a, b), expected);
            assert_eq!(inner::<AcceleratedBackend, F>(a, b), expected);
            assert_eq!(inner::<AcceleratedProver, F>(a, b), expected);
        }
        for count in 0..=3 {
            let (a, b) = (&a[..count], &b[..count]);
            let mut expected = Vec::new();
            for i in 0..3 {
                for j in 0..3 {
                    if i != j {
                        expected.push(dense(a.get(i), b.get(j)));
                    }
                }
            }
            assert_eq!(
                &*outer_error_terms_with_backend::<ReferenceBackend, F, TestRank, P>(a, b),
                expected
            );
            assert_eq!(
                &*outer_error_terms_with_backend::<AcceleratedBackend, F, TestRank, P>(a, b),
                expected
            );
            assert_eq!(
                &*outer_error_terms_with_backend::<AcceleratedProver, F, TestRank, P>(a, b),
                expected
            );
        }
    }
    for workers in [1, std::thread::available_parallelism().unwrap().get()] {
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
