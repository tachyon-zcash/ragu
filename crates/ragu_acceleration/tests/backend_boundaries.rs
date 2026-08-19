use std::sync::atomic::{AtomicUsize, Ordering};

use proptest::prelude::*;
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{
    CurveAffine, FixedGenerators,
    group::{Curve, Group},
    pasta_curves::pallas,
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{Rank, TestRank, sparse::Polynomial},
    registry::{CircuitIndex, RegistryBuilder},
};

static COMMITMENT_MSM_CALLS: AtomicUsize = AtomicUsize::new(0);

struct TrackingMsmBackend;

impl Backend for TrackingMsmBackend {
    fn msm<
        'a,
        C: CurveAffine,
        A: IntoIterator<Item = &'a C::Scalar>,
        Bases: IntoIterator<Item = &'a C>,
    >(
        coeffs: A,
        bases: Bases,
    ) -> C::Curve
    where
        Bases::IntoIter: Clone + Sync,
    {
        COMMITMENT_MSM_CALLS.fetch_add(1, Ordering::SeqCst);
        ReferenceBackend::msm(coeffs, bases)
    }
}

struct TestGenerators {
    g: Vec<pallas::Affine>,
    h: pallas::Affine,
}

impl TestGenerators {
    fn new() -> Self {
        let generator = pallas::Point::generator();
        Self {
            g: (0..TestRank::num_coeffs())
                .map(|index| (generator * pallas::Scalar::from(index as u64 + 1)).to_affine())
                .collect(),
            h: (generator * pallas::Scalar::from(TestRank::num_coeffs() as u64 + 1)).to_affine(),
        }
    }
}

impl FixedGenerators<pallas::Affine> for TestGenerators {
    fn g(&self) -> &[pallas::Affine] {
        &self.g
    }

    fn h(&self) -> &pallas::Affine {
        &self.h
    }
}

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

fn coeffs(poly: Polynomial<pallas::Scalar, TestRank>) -> Vec<pallas::Scalar> {
    poly.iter_coeffs().collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn accelerated_sparse_commitment_matches_reference_and_canonical(
        poly in arb_sparse_poly(),
    ) {
        COMMITMENT_MSM_CALLS.store(0, Ordering::SeqCst);
        let generators = TestGenerators::new();

        let canonical = poly.commit(&generators);
        let reference = ReferenceBackend::sparse_commit(&poly, &generators);
        let accelerated = AcceleratedBackend::sparse_commit(&poly, &generators);

        prop_assert_eq!(reference, canonical);
        prop_assert_eq!(accelerated, canonical);
        prop_assert_eq!(
            TrackingMsmBackend::sparse_commit(&poly, &generators),
            canonical,
        );
        prop_assert_eq!(COMMITMENT_MSM_CALLS.load(Ordering::SeqCst), 1);
        prop_assert_eq!(
            ReferenceBackend::sparse_commit_to_affine(&poly, &generators),
            canonical.to_affine(),
        );
        prop_assert_eq!(
            AcceleratedBackend::sparse_commit_to_affine(&poly, &generators),
            canonical.to_affine(),
        );
    }

    #[test]
    fn accelerated_registry_operations_match_reference_and_canonical(
        w in arb_scalar(),
        x in arb_scalar(),
        y in arb_scalar(),
        circuit_index in 0usize..8,
    ) {
        let registry = RegistryBuilder::<pallas::Scalar, TestRank>::new()
            .finalize()
            .unwrap();
        let registry_at = registry.at(w);
        let circuit = CircuitIndex::new(circuit_index);

        let accelerated_xy = coeffs(AcceleratedBackend::registry_xy(&registry, x, y));
        let reference_xy = coeffs(ReferenceBackend::registry_xy(&registry, x, y));
        let canonical_xy = coeffs(registry.xy(x, y));
        prop_assert_eq!(accelerated_xy.as_slice(), reference_xy.as_slice());
        prop_assert_eq!(reference_xy.as_slice(), canonical_xy.as_slice());

        let accelerated_circuit_y = coeffs(AcceleratedBackend::registry_circuit_y(
            &registry, circuit, y,
        ));
        let reference_circuit_y = coeffs(ReferenceBackend::registry_circuit_y(
            &registry, circuit, y,
        ));
        let canonical_circuit_y = coeffs(registry.circuit_y(circuit, y));
        prop_assert_eq!(
            accelerated_circuit_y.as_slice(),
            reference_circuit_y.as_slice(),
        );
        prop_assert_eq!(
            reference_circuit_y.as_slice(),
            canonical_circuit_y.as_slice(),
        );

        let accelerated_at_x = coeffs(AcceleratedBackend::registry_at_x(&registry_at, x));
        let reference_at_x = coeffs(ReferenceBackend::registry_at_x(&registry_at, x));
        let canonical_at_x = coeffs(registry_at.x(x));
        prop_assert_eq!(accelerated_at_x.as_slice(), reference_at_x.as_slice());
        prop_assert_eq!(reference_at_x.as_slice(), canonical_at_x.as_slice());

        let accelerated_at_y = coeffs(AcceleratedBackend::registry_at_y(&registry_at, y));
        let reference_at_y = coeffs(ReferenceBackend::registry_at_y(&registry_at, y));
        let canonical_at_y = coeffs(registry_at.y(y));
        prop_assert_eq!(accelerated_at_y.as_slice(), reference_at_y.as_slice());
        prop_assert_eq!(reference_at_y.as_slice(), canonical_at_y.as_slice());

        let accelerated_wxy = AcceleratedBackend::registry_wxy(&registry, w, x, y);
        let reference_wxy = ReferenceBackend::registry_wxy(&registry, w, x, y);
        let canonical_wxy = registry.wxy(w, x, y);
        prop_assert_eq!(accelerated_wxy, reference_wxy);
        prop_assert_eq!(reference_wxy, canonical_wxy);
    }
}
