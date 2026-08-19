use proptest::prelude::*;
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{Cycle, group::Curve, pasta_curves::pallas};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{Rank, TestRank, sparse::Polynomial};
use ragu_pasta::Pasta;
use ragu_testing::strategies::prime_field_element;

fn arb_sparse_poly() -> impl Strategy<Value = Polynomial<pallas::Scalar, TestRank>> {
    proptest::collection::vec(prime_field_element(), TestRank::num_coeffs())
        .prop_map(Polynomial::from_coeffs)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn accelerated_sparse_operations_match_reference_and_canonical(
        lhs in arb_sparse_poly(),
        rhs in arb_sparse_poly(),
        point in prime_field_element(),
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn accelerated_sparse_commitment_matches_reference_and_canonical(
        poly in arb_sparse_poly(),
    ) {
        let generators = Pasta::nested_generators(Pasta::baked());
        let canonical = poly.commit(generators);

        prop_assert_eq!(ReferenceBackend::sparse_commit(&poly, generators), canonical);
        prop_assert_eq!(AcceleratedBackend::sparse_commit(&poly, generators), canonical);
        prop_assert_eq!(
            ReferenceBackend::sparse_commit_to_affine(&poly, generators),
            canonical.to_affine(),
        );
        prop_assert_eq!(
            AcceleratedBackend::sparse_commit_to_affine(&poly, generators),
            canonical.to_affine(),
        );
    }
}
