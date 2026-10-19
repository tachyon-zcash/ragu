//! Memoized $s(x, y)$ evaluation must agree with the plain evaluators.
//!
//! The circuits here place the same routines at different absolute offsets,
//! with different input wires, repeated within one circuit, and nested inside
//! other routines, so that recordings are replayed under every kind of shift.

use alloc::vec::Vec;

use ragu_core::{Result, pasta::Fp};
use rand::Rng;
use udon::field::Field;

use super::{RoutineCircuit, RoutineLayout, consistency_checks};
use crate::{
    floor_planner, into_wiring_object,
    polynomials::TestRank,
    registry::{CircuitIndex, Registry, RegistryBuilder},
    wiring::MemoCache,
};

const LAYOUTS: [RoutineLayout; 6] = [
    RoutineLayout::Single,
    RoutineLayout::Shifted(2),
    RoutineLayout::Nested,
    RoutineLayout::FeedFirst,
    RoutineLayout::FeedSecond,
    RoutineLayout::Repeated,
];

fn random() -> Fp {
    Fp::random(|bytes| rand::rng().fill_bytes(bytes))
}

fn registry(layouts: &[RoutineLayout]) -> Result<Registry<'static, Fp, TestRank>> {
    let mut builder = RegistryBuilder::<Fp, TestRank>::new();
    for layout in layouts {
        builder = builder.register_circuit(RoutineCircuit(*layout))?;
    }
    builder.finalize()
}

/// The three plain evaluators agree on circuits whose routines emit
/// constraints, including a routine nested inside another one.
#[test]
fn routine_circuits_consistency() -> Result<()> {
    for layout in LAYOUTS {
        let obj = into_wiring_object::<Fp, _, TestRank>(RoutineCircuit(layout))?;
        consistency_checks(&*obj);
    }
    Ok(())
}

/// `wxy_combined` equals `wxy` under every kind of replay.
#[test]
fn wxy_combined_matches_wxy_across_layouts() -> Result<()> {
    use RoutineLayout::*;
    let cases: &[&[RoutineLayout]] = &[
        // Identical layout.
        &[Single, Single],
        // Same routine, different gate offset.
        &[Single, Shifted(2)],
        // Same layout, different input wire.
        &[FeedFirst, FeedSecond],
        // A hit on a routine with a nested call must skip the nested segment.
        &[Nested, Nested],
        // The same routine twice within one circuit.
        &[Repeated, Single],
        &[
            Nested,
            Single,
            Shifted(1),
            Repeated,
            Nested,
            FeedSecond,
            FeedFirst,
        ],
    ];

    for layouts in cases {
        let registry = registry(layouts)?;
        let (w, x, y) = (random(), random(), random());
        let w_in_domain = CircuitIndex::new(1).omega_j::<Fp>();

        for (w, x, y) in [
            (w, x, y),
            (w_in_domain, x, y),
            (w, Fp::ZERO, y),
            (w, x, Fp::ZERO),
        ] {
            assert_eq!(
                registry.wxy(w, x, y),
                registry.wxy_combined(w, x, y),
                "layouts {layouts:?}"
            );
        }
    }
    Ok(())
}

/// The domain evaluation behind `xy` memoizes across circuits; it must agree
/// with the per-circuit Lagrange evaluation `wxy`, which does not.
#[test]
fn domain_evaluation_matches_wxy() -> Result<()> {
    use RoutineLayout::*;
    let registry = registry(&[
        Nested,
        Single,
        Shifted(1),
        Repeated,
        Nested,
        FeedSecond,
        FeedFirst,
    ])?;
    let (w, x, y) = (random(), random(), random());
    assert_eq!(registry.xy(x, y).eval(w), registry.wxy(w, x, y));
    let w_in_domain = CircuitIndex::new(3).omega_j::<Fp>();
    assert_eq!(
        registry.xy(x, y).eval(w_in_domain),
        registry.wxy(w_in_domain, x, y)
    );
    Ok(())
}

/// A recording is replayed for every later invocation with the same
/// fingerprint — shifted, with other inputs, within the same circuit — and
/// the memoized value always equals the plain evaluation.
#[test]
fn recordings_replay_at_any_placement() -> Result<()> {
    use RoutineLayout::*;
    // (layout, expected new hits when evaluated in this order)
    let sequence = [
        (Single, 0),
        // Identical to the first circuit.
        (Single, 1),
        // Same routine, shifted gate offset.
        (Shifted(2), 1),
        // Same offsets as `Single`, but the routine reads a different wire.
        (FeedSecond, 1),
        // Both the nested routine and the one after it are new recordings.
        (Nested, 0),
        // Both replayed; the hit on the nested routine skips its child segment.
        (Nested, 2),
        // Two invocations in one circuit: both replayed.
        (Repeated, 2),
    ];

    let objs = sequence
        .iter()
        .map(|(layout, _)| into_wiring_object::<Fp, _, TestRank>(RoutineCircuit(*layout)))
        .collect::<Result<Vec<_>>>()?;

    let (x, y) = (random(), random());
    let mut cache = MemoCache::new();
    let mut hits = 0;
    for (obj, (layout, expected_hits)) in objs.iter().zip(sequence) {
        let plan = floor_planner::floor_plan(obj.segment_records());
        let memoized = obj.sxy_with_cache(x, y, &plan, &mut cache);
        assert_eq!(memoized, obj.sxy(x, y, &plan), "{layout:?}");
        assert_eq!(cache.hits() - hits, expected_hits, "{layout:?}");
        hits = cache.hits();
    }
    assert!(cache.len() > 0);
    Ok(())
}
