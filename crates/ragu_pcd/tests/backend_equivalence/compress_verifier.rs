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

use super::{public, public_parts};
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
                z,
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
