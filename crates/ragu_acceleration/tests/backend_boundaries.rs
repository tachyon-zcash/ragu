use std::sync::atomic::{AtomicUsize, Ordering};

use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{
    CurveAffine, FixedGenerators,
    group::{Curve, Group},
    pasta_curves::pallas,
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
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{Rank, TestRank, sparse::Polynomial},
    registry::{CircuitIndex, RegistryBuilder},
};

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

#[test]
fn accelerated_sparse_commitment_matches_reference_and_canonical() {
    COMMITMENT_MSM_CALLS.store(0, Ordering::SeqCst);
    let poly = Polynomial::<pallas::Scalar, TestRank>::from_coeffs(
        (0..TestRank::num_coeffs())
            .map(|index| match index {
                0 | 3 | 17 | 64 | 127 => pallas::Scalar::from(index as u64 + 1),
                _ => pallas::Scalar::zero(),
            })
            .collect(),
    );
    let generators = TestGenerators::new();

    let canonical = poly.commit(&generators);
    let reference = ReferenceBackend::sparse_commit(&poly, &generators);
    let accelerated = AcceleratedBackend::sparse_commit(&poly, &generators);

    assert_eq!(reference, canonical);
    assert_eq!(accelerated, reference);
    assert_eq!(
        TrackingMsmBackend::sparse_commit(&poly, &generators),
        canonical,
    );
    assert_eq!(COMMITMENT_MSM_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(
        AcceleratedBackend::sparse_commit_to_affine(&poly, &generators),
        ReferenceBackend::sparse_commit_to_affine(&poly, &generators),
    );
}

#[test]
fn accelerated_registry_operations_match_reference_and_canonical() {
    let registry = RegistryBuilder::<pallas::Scalar, TestRank>::new()
        .finalize()
        .unwrap();
    let w = pallas::Scalar::from(7);
    let x = pallas::Scalar::from(11);
    let y = pallas::Scalar::from(13);
    let registry_at = registry.at(w);

    let coeffs =
        |poly: Polynomial<pallas::Scalar, TestRank>| poly.iter_coeffs().collect::<Vec<_>>();

    assert_eq!(
        coeffs(AcceleratedBackend::registry_xy(&registry, x, y)),
        coeffs(ReferenceBackend::registry_xy(&registry, x, y)),
    );
    assert_eq!(
        coeffs(ReferenceBackend::registry_xy(&registry, x, y)),
        coeffs(registry.xy(x, y)),
    );
    assert_eq!(
        coeffs(AcceleratedBackend::registry_circuit_y(
            &registry,
            CircuitIndex::new(0),
            y,
        )),
        coeffs(ReferenceBackend::registry_circuit_y(
            &registry,
            CircuitIndex::new(0),
            y,
        )),
    );
    assert_eq!(
        coeffs(AcceleratedBackend::registry_at_x(&registry_at, x)),
        coeffs(ReferenceBackend::registry_at_x(&registry_at, x)),
    );
    assert_eq!(
        coeffs(AcceleratedBackend::registry_at_y(&registry_at, y)),
        coeffs(ReferenceBackend::registry_at_y(&registry_at, y)),
    );
    assert_eq!(
        AcceleratedBackend::registry_wxy(&registry, w, x, y),
        ReferenceBackend::registry_wxy(&registry, w, x, y),
    );
    assert_eq!(
        ReferenceBackend::registry_wxy(&registry, w, x, y),
        registry.wxy(w, x, y),
    );
}
