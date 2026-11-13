//! Backend equivalence for ordered public claim evaluations.

use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use ragu_acceleration::{AcceleratedBackend, AcceleratedProver};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{Rank, TestRank},
    registry::CircuitIndex,
};
use ragu_core::pasta::{Fp, Fq};
use udon::field::Field;

use super::{public, public_parts, registry_public_parts};
use crate::compress::revdot::claims::{Kind, Masked, Shape};

fn check_public_parts<F: Field, B: Backend>() {
    let (r, z) = (F::from(7), F::from(11));
    let masked = [
        Masked::new(
            (),
            vec![0, 3, 17],
            vec![F::ONE, F::from(2), F::from(3)],
            F::from(5),
        ),
        Masked::new((), vec![2, 9], vec![F::from(7), F::ZERO], F::ZERO),
    ];
    let kinds = [
        Kind::Raw,
        Kind::Circuit(CircuitIndex::new(0)),
        Kind::Masked(0),
        Kind::Bonding(CircuitIndex::new(1)),
        Kind::Circuit(CircuitIndex::new(2)),
        Kind::Masked(1),
        Kind::Bonding(CircuitIndex::new(2)),
        Kind::Raw,
    ]
    .repeat(4);
    let restriction = |circuit: CircuitIndex| F::from(usize::from(circuit) as u64 + 1) * r;
    for len in [0, 1, kinds.len()] {
        let shapes: Vec<_> = kinds[..len]
            .iter()
            .map(|&kind| Shape::<(), F> {
                kind,
                a: vec![],
                b: vec![],
            })
            .collect();

        // Polynomial evaluation is an independent reference for the
        // masks' point formulas; each kind must stay in its claim slot.
        let expected: Vec<_> = kinds[..len]
            .iter()
            .map(|kind| match *kind {
                Kind::Raw => (F::ZERO, F::ZERO),
                Kind::Circuit(circuit) => (F::ZERO, restriction(circuit) + TestRank::tz(z).eval(r)),
                Kind::Bonding(circuit) => (F::ZERO, restriction(circuit)),
                Kind::Masked(i) => (
                    -masked[i].expected::<TestRank>().eval(r),
                    masked[i].mask::<TestRank>().eval(r),
                ),
            })
            .collect();
        let calls = AtomicUsize::new(0);
        let registry_calls = AtomicUsize::new(0);
        let actual = public_parts::<_, B, _>(&shapes, r, |kind, at| {
            assert_eq!(at, r);
            calls.fetch_add(1, Ordering::Relaxed);
            public::<_, TestRank, _>(
                kind,
                at,
                TestRank::txz(r, z),
                &|circuit| {
                    registry_calls.fetch_add(1, Ordering::Relaxed);
                    restriction(circuit)
                },
                &masked,
            )
        });
        assert_eq!(actual, expected);
        assert_eq!(calls.load(Ordering::Relaxed), len);
        assert_eq!(
            registry_calls.load(Ordering::Relaxed),
            kinds[..len]
                .iter()
                .filter(|kind| matches!(kind, Kind::Circuit(_) | Kind::Bonding(_)))
                .count()
        );
    }
}

/// The direct scalar formula agrees with the old coefficient construction,
/// including zero inputs and unit geometric ratios, on both Pasta fields.
#[test]
fn shared_gate_value_matches_polynomial_at_production_ranks() {
    fn check<F: Field, R: Rank>() {
        for (x, z) in [
            (F::ZERO, F::ZERO),
            (F::ZERO, F::ONE),
            (F::ONE, F::ZERO),
            (F::ONE, F::ONE),
            (-F::ONE, -F::ONE),
            (F::from(7), F::from(7)),
            (F::from(7), F::from(7).invert().unwrap()),
            (F::from(7), F::from(11)),
        ] {
            assert_eq!(R::txz(x, z), R::tz(z).eval(x));
        }
    }
    check::<Fp, ragu_circuits::polynomials::WalletRank>();
    check::<Fq, ragu_circuits::polynomials::WalletRank>();
    check::<Fp, ragu_circuits::polynomials::AggregatorRank>();
    check::<Fq, ragu_circuits::polynomials::AggregatorRank>();
}

/// Repeated circuit claims share an evaluation, while their claim positions
/// and the registry's tag and interpolation semantics are unchanged.
#[test]
fn selected_registry_queries_match_individual_evaluations() {
    #[derive(Clone, Copy, Debug, Default)]
    struct SelectedBackend;
    impl Backend for SelectedBackend {
        fn registry_circuits_xy<F: Field, R: Rank>(
            registry: &ragu_circuits::registry::Registry<'_, F, R>,
            circuits: &[CircuitIndex],
            x: F,
            y: F,
        ) -> Vec<F> {
            assert_eq!(
                circuits
                    .iter()
                    .map(|id| usize::from(*id))
                    .collect::<Vec<_>>(),
                [0, 4, 7, 8]
            );
            ReferenceBackend::registry_circuits_xy(registry, circuits, x, y)
        }
    }
    fn check<F: Field>() {
        let mut builder = ragu_circuits::registry::RegistryBuilder::<F, TestRank>::new()
            .with_tag(ragu_circuits::registry::Tag::new(F::from(17)));
        for times in 1..=5 {
            builder = builder
                .register_circuit(ragu_testing::circuits::SquareCircuit { times })
                .unwrap();
        }
        let registry = builder.finalize().unwrap();
        let kinds = [
            Kind::Circuit(CircuitIndex::new(8)),
            Kind::Raw,
            Kind::Circuit(CircuitIndex::new(0)),
            Kind::Bonding(CircuitIndex::new(4)),
            Kind::Circuit(CircuitIndex::new(0)),
            Kind::Circuit(CircuitIndex::new(7)),
        ];
        let shapes = kinds.map(|kind| Shape::<(), F> {
            kind,
            a: vec![],
            b: vec![],
        });
        for r in [F::ZERO, F::ONE, F::from(7)] {
            let (y, z) = (F::from(11), F::from(13));
            let expected: Vec<_> = kinds
                .iter()
                .map(|kind| match kind {
                    Kind::Circuit(circuit) => (
                        F::ZERO,
                        registry.wxy(circuit.omega_j(), r, y) + TestRank::tz(z).eval(r),
                    ),
                    Kind::Bonding(circuit) => (F::ZERO, registry.wxy(circuit.omega_j(), r, y)),
                    _ => (F::ZERO, F::ZERO),
                })
                .collect();
            assert_eq!(
                registry_public_parts::<_, TestRank, SelectedBackend, _>(
                    &shapes,
                    &registry,
                    r,
                    y,
                    z,
                    &[]
                ),
                expected
            );
            assert_eq!(
                registry_public_parts::<_, TestRank, AcceleratedBackend, _>(
                    &shapes,
                    &registry,
                    r,
                    y,
                    z,
                    &[]
                ),
                expected
            );
        }
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn public_parts_preserve_claims_on_both_fields_and_worker_counts() {
    for workers in [1, 4] {
        maybe_rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                check_public_parts::<Fp, ReferenceBackend>();
                check_public_parts::<Fq, ReferenceBackend>();
                check_public_parts::<Fp, AcceleratedBackend>();
                check_public_parts::<Fq, AcceleratedBackend>();
                check_public_parts::<Fp, AcceleratedProver>();
                check_public_parts::<Fq, AcceleratedProver>();
            });
    }
}

/// Leaves the last item unvisited, as a faulty scheduler might.
#[derive(Clone, Copy, Debug, Default)]
struct SkippingBackend;

impl Backend for SkippingBackend {
    fn for_each_mut<T: Send>(values: &mut [T], work: impl Fn(usize, &mut T) + Sync) {
        let visited = values.len().saturating_sub(1);
        for (index, value) in values.iter_mut().enumerate().take(visited) {
            work(index, value);
        }
    }
}

/// An unevaluated claim must not leave zero public parts for the reduction
/// check to accept.
#[test]
#[should_panic(expected = "the backend evaluates every claim's public parts")]
fn public_parts_reject_an_unevaluated_claim() {
    let shapes = [Kind::Raw, Kind::Circuit(CircuitIndex::new(0))].map(|kind| Shape::<(), Fp> {
        kind,
        a: vec![],
        b: vec![],
    });
    public_parts::<_, SkippingBackend, _>(&shapes, Fp::ONE, |_, _| (Fp::ONE, Fp::ONE));
}
