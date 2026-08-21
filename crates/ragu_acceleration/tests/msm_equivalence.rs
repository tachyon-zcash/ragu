use proptest::{prelude::*, test_runner::TestCaseResult};
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{
    CurveAffine,
    group::{Curve, Group},
    pasta_curves::{pallas, vesta},
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{ProductionRank, Rank, TestRank};
use ragu_testing::strategies::{bounded_edge_usize, prime_field_element};

fn arb_msm_size() -> impl Strategy<Value = usize> {
    let window_boundaries = (0..=ProductionRank::RANK, -1i8..=1).prop_map(|(log_size, offset)| {
        let boundary = 1usize << log_size;
        match offset {
            -1 => boundary - 1,
            0 => boundary,
            1 => (boundary + 1).min(ProductionRank::num_coeffs()),
            _ => unreachable!("the generated offset is in -1..=1"),
        }
    });

    prop_oneof![
        bounded_edge_usize(TestRank::num_coeffs()),
        window_boundaries,
    ]
}

fn arb_msm_terms<F>() -> impl Strategy<Value = Vec<(F, F)>>
where
    F: ragu_arithmetic::ff::PrimeField + From<u64> + 'static,
{
    arb_msm_size().prop_flat_map(|size| {
        let independent = proptest::collection::vec(
            (prime_field_element::<F>(), prime_field_element::<F>()),
            size,
        );
        let repeated = (
            proptest::collection::vec(prime_field_element::<F>(), size),
            prime_field_element::<F>(),
        )
            .prop_map(|(scalars, base)| scalars.into_iter().map(|scalar| (scalar, base)).collect());
        let repeated_with_inverses = (
            proptest::collection::vec((prime_field_element::<F>(), any::<bool>()), size),
            prime_field_element::<F>(),
        )
            .prop_map(|(terms, base)| {
                terms
                    .into_iter()
                    .map(|(scalar, negate)| (scalar, if negate { -base } else { base }))
                    .collect()
            });
        let identity_bases =
            proptest::collection::vec(prime_field_element::<F>(), size).prop_map(|scalars| {
                scalars
                    .into_iter()
                    .map(|scalar| (scalar, F::ZERO))
                    .collect()
            });
        let zero_scalars = proptest::collection::vec(prime_field_element::<F>(), size)
            .prop_map(|bases| bases.into_iter().map(|base| (F::ZERO, base)).collect());

        prop_oneof![
            independent,
            repeated,
            repeated_with_inverses,
            identity_bases,
            zero_scalars,
        ]
    })
}

fn check_msm<C: CurveAffine>(terms: Vec<(C::ScalarExt, C::ScalarExt)>) -> TestCaseResult {
    let generator = C::CurveExt::generator();
    let (scalars, bases): (Vec<_>, Vec<_>) = terms
        .into_iter()
        .map(|(scalar, base_scalar)| (scalar, (generator * base_scalar).to_affine()))
        .unzip();

    let canonical = ragu_arithmetic::msm(scalars.iter(), bases.iter());
    let reference = ReferenceBackend::msm(scalars.iter(), bases.iter());
    let accelerated = AcceleratedBackend::msm(scalars.iter(), bases.iter());

    prop_assert_eq!(reference, canonical);
    prop_assert_eq!(accelerated, canonical);

    Ok(())
}

fn deterministic_terms<F: From<u64>>(size: usize) -> Vec<(F, F)> {
    (0..size)
        .map(|index| {
            let index = index as u64;
            (F::from(index + 1), F::from(index.wrapping_mul(17) + 3))
        })
        .collect()
}

#[test]
fn exact_algorithm_boundaries_match_canonical_msm() -> TestCaseResult {
    // Zakura's `best_multiexp` changes its Booth-window width at these
    // boundaries. Keep them deterministic: the proptest strategy is
    // power-of-two biased and cannot generate most of these transition points.
    const ZAKURA_WINDOW_TRANSITIONS: [usize; 8] = [4, 32, 55, 149, 404, 1097, 2981, 8104];

    let sizes = ZAKURA_WINDOW_TRANSITIONS
        .into_iter()
        .flat_map(|boundary| [boundary - 1, boundary])
        .chain(core::iter::once(ProductionRank::num_coeffs()));

    for size in sizes {
        check_msm::<pallas::Affine>(deterministic_terms(size))?;
        check_msm::<vesta::Affine>(deterministic_terms(size))?;
    }

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn accelerated_pallas_msm_matches_reference_and_canonical(
        terms in arb_msm_terms::<pallas::Scalar>(),
    ) {
        check_msm::<pallas::Affine>(terms)?;
    }

    #[test]
    fn accelerated_vesta_msm_matches_reference_and_canonical(
        terms in arb_msm_terms::<vesta::Scalar>(),
    ) {
        check_msm::<vesta::Affine>(terms)?;
    }
}
