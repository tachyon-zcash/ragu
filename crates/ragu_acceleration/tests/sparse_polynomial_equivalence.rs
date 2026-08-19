use proptest::prelude::*;
use proptest::test_runner::TestCaseResult;
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{
    CurveAffine, Cycle, DeferredField, FixedGenerators,
    ff::PrimeField,
    group::Curve,
    pasta_curves::{pallas, vesta},
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{Rank, TestRank, sparse::Polynomial};
use ragu_pasta::Pasta;
use ragu_testing::strategies::prime_field_element;

fn arb_sparse_poly<F>() -> BoxedStrategy<Polynomial<F, TestRank>>
where
    F: PrimeField + From<u64> + 'static,
{
    let size = prop_oneof![
        1 => Just(0),
        1 => Just(1),
        1 => Just(2),
        1 => Just(3),
        1 => Just(TestRank::num_coeffs() / 2 - 1),
        1 => Just(TestRank::num_coeffs() / 2),
        1 => Just(TestRank::num_coeffs() / 2 + 1),
        1 => Just(TestRank::num_coeffs() - 1),
        1 => Just(TestRank::num_coeffs()),
        8 => 0..=TestRank::num_coeffs(),
    ];

    size.prop_flat_map(|size| {
        proptest::collection::vec(
            prop_oneof![
                6 => Just(F::ZERO),
                1 => Just(F::ONE),
                8 => prime_field_element(),
            ],
            size,
        )
    })
    .prop_map(Polynomial::from_coeffs)
    .boxed()
}

fn check_sparse_operations<F>(
    lhs: Polynomial<F, TestRank>,
    rhs: Polynomial<F, TestRank>,
    point: F,
) -> TestCaseResult
where
    F: DeferredField,
{
    let canonical_lhs_eval = lhs.eval(point);
    let canonical_rhs_eval = rhs.eval(point);

    prop_assert_eq!(
        ReferenceBackend::sparse_eval(&lhs, point),
        canonical_lhs_eval
    );
    prop_assert_eq!(
        AcceleratedBackend::sparse_eval(&lhs, point),
        canonical_lhs_eval,
    );
    prop_assert_eq!(
        ReferenceBackend::sparse_eval(&rhs, point),
        canonical_rhs_eval
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

    Ok(())
}

fn check_sparse_commitment<F, C, G>(poly: Polynomial<F, TestRank>, generators: &G) -> TestCaseResult
where
    F: PrimeField,
    C: CurveAffine<ScalarExt = F>,
    G: FixedGenerators<C>,
{
    let canonical = poly.commit(generators);

    prop_assert_eq!(
        ReferenceBackend::sparse_commit(&poly, generators),
        canonical
    );
    prop_assert_eq!(
        AcceleratedBackend::sparse_commit(&poly, generators),
        canonical
    );
    prop_assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(&poly, generators),
        canonical.to_affine(),
    );
    prop_assert_eq!(
        AcceleratedBackend::sparse_commit_to_affine(&poly, generators),
        canonical.to_affine(),
    );

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn accelerated_pallas_sparse_operations_match_reference_and_canonical(
        lhs in arb_sparse_poly::<pallas::Scalar>(),
        rhs in arb_sparse_poly::<pallas::Scalar>(),
        point in prime_field_element(),
    ) {
        check_sparse_operations(lhs, rhs, point)?;
    }

    #[test]
    fn accelerated_vesta_sparse_operations_match_reference_and_canonical(
        lhs in arb_sparse_poly::<vesta::Scalar>(),
        rhs in arb_sparse_poly::<vesta::Scalar>(),
        point in prime_field_element(),
    ) {
        check_sparse_operations(lhs, rhs, point)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn accelerated_pallas_sparse_commitment_matches_reference_and_canonical(
        poly in arb_sparse_poly::<pallas::Scalar>(),
    ) {
        check_sparse_commitment::<_, pallas::Affine, _>(
            poly,
            Pasta::nested_generators(Pasta::baked()),
        )?;
    }

    #[test]
    fn accelerated_vesta_sparse_commitment_matches_reference_and_canonical(
        poly in arb_sparse_poly::<vesta::Scalar>(),
    ) {
        check_sparse_commitment::<_, vesta::Affine, _>(
            poly,
            Pasta::host_generators(Pasta::baked()),
        )?;
    }
}
