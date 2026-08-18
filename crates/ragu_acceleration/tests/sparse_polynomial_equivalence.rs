use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::pasta_curves::pallas;
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{Rank, TestRank, sparse::Polynomial};

#[test]
fn accelerated_sparse_operations_match_reference() {
    let lhs = Polynomial::<pallas::Scalar, TestRank>::from_coeffs(
        (0..TestRank::num_coeffs())
            .map(|i| match i {
                0 | 3 | 17 | 64 | 127 => pallas::Scalar::from((i + 1) as u64),
                _ => pallas::Scalar::zero(),
            })
            .collect(),
    );
    let rhs = Polynomial::<pallas::Scalar, TestRank>::from_coeffs(
        (0..TestRank::num_coeffs())
            .map(|i| match i {
                0 | 63 | 110 | 124 | 127 => pallas::Scalar::from((2 * i + 1) as u64),
                _ => pallas::Scalar::zero(),
            })
            .collect(),
    );

    for point in [0, 1, 2, 17].map(pallas::Scalar::from) {
        assert_eq!(
            AcceleratedBackend::sparse_eval(&lhs, point),
            ReferenceBackend::sparse_eval(&lhs, point),
        );
        assert_eq!(
            AcceleratedBackend::sparse_eval(&rhs, point),
            ReferenceBackend::sparse_eval(&rhs, point),
        );
    }

    assert_eq!(
        AcceleratedBackend::sparse_revdot(&lhs, &rhs),
        ReferenceBackend::sparse_revdot(&lhs, &rhs),
    );
}
