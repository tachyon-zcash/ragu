use proptest::prelude::*;
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{
    group::{Curve, Group},
    pasta_curves::pallas,
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_testing::strategies::prime_field_element;

fn arb_msm_size() -> impl Strategy<Value = usize> {
    prop_oneof![
        1 => Just(0),
        1 => Just(1),
        1 => Just(2),
        1 => Just(3),
        1 => Just(15),
        1 => Just(16),
        1 => Just(17),
        1 => Just(31),
        1 => Just(32),
        1 => Just(33),
        1 => Just(255),
        8 => 0usize..=255,
    ]
}

fn arb_msm_terms() -> impl Strategy<Value = Vec<(pallas::Scalar, pallas::Scalar)>> {
    arb_msm_size().prop_flat_map(|size| {
        proptest::collection::vec((prime_field_element(), prime_field_element()), size)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn accelerated_msm_matches_reference_and_canonical(terms in arb_msm_terms()) {
        let generator = pallas::Point::generator();
        let (scalars, bases): (Vec<_>, Vec<_>) = terms
            .into_iter()
            .map(|(scalar, base_scalar)| (scalar, (generator * base_scalar).to_affine()))
            .unzip();

        let canonical = ragu_arithmetic::msm(scalars.iter(), bases.iter());
        let reference = ReferenceBackend::msm(scalars.iter(), bases.iter());
        let accelerated = AcceleratedBackend::msm(scalars.iter(), bases.iter());

        prop_assert_eq!(reference, canonical);
        prop_assert_eq!(accelerated, canonical);
    }
}
