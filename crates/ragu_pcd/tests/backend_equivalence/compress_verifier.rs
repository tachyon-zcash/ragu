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
    for workers in [1, std::thread::available_parallelism().unwrap().get()] {
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
