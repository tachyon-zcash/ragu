use proptest::prelude::*;
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::pasta_curves::pallas;
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{Rank, TestRank, sparse::Polynomial};

fn arb_scalar() -> impl Strategy<Value = pallas::Scalar> {
    prop_oneof![
        4 => Just(pallas::Scalar::from(0)),
        1 => Just(pallas::Scalar::from(1)),
        3 => any::<u64>().prop_map(pallas::Scalar::from),
        2 => (any::<u64>(), any::<u64>()).prop_map(|(a, b)| {
            pallas::Scalar::from(a)
                + pallas::Scalar::from(b) * pallas::Scalar::from(u64::MAX)
        }),
    ]
}

fn arb_sparse_poly() -> impl Strategy<Value = Polynomial<pallas::Scalar, TestRank>> {
    proptest::collection::vec(arb_scalar(), TestRank::num_coeffs())
        .prop_map(Polynomial::from_coeffs)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn accelerated_sparse_operations_match_reference_and_canonical(
        lhs in arb_sparse_poly(),
        rhs in arb_sparse_poly(),
        point in arb_scalar(),
    ) {
        let canonical_lhs_eval = lhs.eval(point);
        let canonical_rhs_eval = rhs.eval(point);

        prop_assert_eq!(
            ReferenceBackend::sparse_eval(&lhs, point),
            canonical_lhs_eval,
        );
        prop_assert_eq!(
            AcceleratedBackend::sparse_eval(&lhs, point),
            canonical_lhs_eval,
        );
        prop_assert_eq!(
            ReferenceBackend::sparse_eval(&rhs, point),
            canonical_rhs_eval,
        );
        prop_assert_eq!(
            AcceleratedBackend::sparse_eval(&rhs, point),
            canonical_rhs_eval,
        );

        let canonical_revdot = lhs.revdot(&rhs);
        prop_assert_eq!(
            ReferenceBackend::sparse_revdot(&lhs, &rhs),
            canonical_revdot,
        );
        prop_assert_eq!(
            AcceleratedBackend::sparse_revdot(&lhs, &rhs),
            canonical_revdot,
        );
    }
}
