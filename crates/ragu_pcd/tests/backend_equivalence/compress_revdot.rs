//! Backend equivalence for reduction error terms and fold commitments.

use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use ragu_acceleration::{AcceleratedBackend, AcceleratedProver};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{Rank, TestRank, sparse},
    registry::CircuitIndex,
};
use ragu_core::pasta::{Fp, Fq};
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::{
    curve::{Affine, Projective},
    field::Field,
};

use super::{
    claims::{Kind, Shape},
    fold::{self, GROUP, Layout},
    prover::errors,
};

/// Each derived commitment agrees with a sum of individual scalar
/// multiplications, including empty jobs and claims in a partial group.
#[test]
fn batched_fold_commitments_match_individual_sums() {
    fn check<C: Affine>() {
        let points = [C::generator(), -C::generator()];
        let shapes: Vec<_> = (0..2 * GROUP + 3)
            .map(|i| Shape {
                kind: match i % 4 {
                    0 => Kind::Raw,
                    1 => Kind::Circuit(CircuitIndex::new(0)),
                    2 => Kind::Bonding(CircuitIndex::new(1)),
                    _ => Kind::Masked(0),
                },
                a: vec![
                    (C::Scalar::from(i as u64), i % 2),
                    (-C::Scalar::ONE, i % 2),
                    (C::Scalar::ZERO, (i + 1) % 2),
                ],
                b: vec![(C::Scalar::from(3), (i + 1) % 2)],
            })
            .collect();
        let weights = fold::Weights {
            mu: C::Scalar::from(2),
            nu: C::Scalar::from(3),
            mu_prime: C::Scalar::from(5),
            nu_prime: C::Scalar::from(7),
        };
        let fold = fold::Fold {
            inner: points[0],
            outer: points[1],
            inner_epsilon: C::Scalar::ZERO,
            outer_epsilon: C::Scalar::ZERO,
        };
        for shapes in [&shapes[..0], &shapes[..1], &shapes[1..2], &shapes[..]] {
            let sum = |terms: &[(C::Scalar, usize)]| {
                terms
                    .iter()
                    .fold(C::Projective::identity(), |sum, &(coefficient, id)| {
                        let point: C::Projective = points[id].into();
                        sum + point * coefficient
                    })
            };
            let mut expected = [C::Projective::identity(); 3];
            for (i, shape) in shapes.iter().enumerate() {
                expected[0] += sum(&shape.a) * weights.a(i);
                match shape.kind {
                    Kind::Circuit(_) => expected[1] += sum(&shape.a) * weights.b(i),
                    Kind::Raw => expected[2] += sum(&shape.b) * weights.b(i),
                    _ => {}
                }
            }
            let [a, dilated, b] = expected.map(C::from);
            let expected = vec![a, dilated, b, fold.inner, fold.outer];
            assert_eq!(
                fold::commitments::<_, ReferenceBackend, _>(
                    shapes,
                    &weights,
                    |id| points[id],
                    &fold
                ),
                expected,
            );
            assert_eq!(
                fold::commitments::<_, AcceleratedBackend, _>(
                    shapes,
                    &weights,
                    |id| points[id],
                    &fold
                ),
                expected,
            );
            assert_eq!(
                fold::commitments::<_, AcceleratedProver, _>(
                    shapes,
                    &weights,
                    |id| points[id],
                    &fold
                ),
                expected,
            );
        }
    }
    for workers in [1, std::thread::available_parallelism().unwrap().get()] {
        maybe_rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                check::<ragu_core::pasta::EpAffine>();
                check::<ragu_core::pasta::EqAffine>();
            });
    }
}

static REVDOT_CALLS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Default)]
struct CountingBackend;

impl Backend for CountingBackend {
    fn sparse_revdot<F: Field, R: Rank>(
        lhs: &sparse::Polynomial<F, R>,
        rhs: &sparse::Polynomial<F, R>,
    ) -> F {
        REVDOT_CALLS.fetch_add(1, Ordering::Relaxed);
        lhs.revdot(rhs)
    }
}

fn check_error_coefficients<F: Field>() {
    let mut rng = StdRng::seed_from_u64(892);
    let layout = Layout::new(2 * fold::GROUP + 3);
    let mut polys = || {
        (0..2 * fold::GROUP + 3)
            .map(|i| {
                sparse::Polynomial::<F, TestRank>::from_coeffs(
                    (0..TestRank::num_coeffs())
                        .map(|degree| {
                            if i % 5 == 0 || (degree / 11 + i) % 3 == 0 {
                                F::ZERO
                            } else {
                                F::random(|bytes| rng.fill_bytes(bytes))
                            }
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>()
    };
    let (a, b) = (polys(), polys());
    let cases = [
        vec![],
        vec![(1, 2)],
        vec![(2, 1), (0, 1), (2, 1), (1, 0)],
        layout
            .inner()
            .map(|(g, i, j)| (g * fold::GROUP + i, g * fold::GROUP + j))
            .collect(),
        layout.outer().collect(),
    ];
    for pairs in cases {
        // An independent dense oracle checks the coefficient order,
        // including zero terms, duplicate pairs and a partial group.
        let expected: Vec<_> = pairs
            .iter()
            .map(|&(i, j)| {
                a[i].iter_coeffs()
                    .zip(b[j].iter_coeffs().rev())
                    .fold(F::ZERO, |sum, (a, b)| sum + a * b)
            })
            .collect();
        let calls = REVDOT_CALLS.load(Ordering::Relaxed);
        let actual = [
            errors::<_, TestRank, ReferenceBackend>(|i| &a[i], |j| &b[j], pairs.iter().copied()),
            errors::<_, TestRank, AcceleratedBackend>(|i| &a[i], |j| &b[j], pairs.iter().copied()),
            errors::<_, TestRank, AcceleratedProver>(|i| &a[i], |j| &b[j], pairs.iter().copied()),
            errors::<_, TestRank, CountingBackend>(|i| &a[i], |j| &b[j], pairs.iter().copied()),
        ];
        assert_eq!(REVDOT_CALLS.load(Ordering::Relaxed) - calls, expected.len());
        for actual in actual {
            assert_eq!(
                actual
                    .iter_coeffs()
                    .take(expected.len())
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(
                actual
                    .iter_coeffs()
                    .skip(expected.len())
                    .all(|c| c == F::ZERO)
            );
        }
    }
}

#[test]
fn error_terms_match_dense_oracle_across_worker_counts() {
    for workers in [1, std::thread::available_parallelism().unwrap().get()] {
        maybe_rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                check_error_coefficients::<Fp>();
                check_error_coefficients::<Fq>();
            });
    }
}
