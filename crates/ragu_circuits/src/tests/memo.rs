//! Memoized $s(x, y)$ evaluation must agree with the plain evaluators.
//!
//! The circuits here place the same routines at different absolute offsets,
//! with different input wires, repeated within one circuit, and nested inside
//! other routines, so that recordings are replayed under every kind of shift.

use alloc::vec::Vec;

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    pasta::Fp,
    routines::{Prediction, Routine},
};
use ragu_primitives::{Element, allocator::Standard};
use rand::Rng;
use udon::field::Field;

use super::{RoutineCircuit, RoutineLayout, consistency_checks};
use crate::{
    Circuit, CircuitExt, WithAux, floor_planner, into_wiring_object,
    polynomials::{Rank, TestRank},
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

/// Returns its input unchanged: no gates, no constraints.
#[derive(Clone)]
struct PassThrough;

impl Routine<Fp> for PassThrough {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(input)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// `PassThrough(in)` when `false`, `PassThrough(in + in)` when `true`.
#[derive(Clone)]
struct FeedChild(bool);

impl Routine<Fp> for FeedChild {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let fed = if self.0 { input.add(dr, &input) } else { input };
        dr.routine(PassThrough, fed)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// Feeding a child a different linear combination of the caller's wires
/// emits no constraint, but it changes the caller's output, so the deep
/// fingerprints must differ; otherwise one recording would be replayed for
/// the other.
#[test]
fn child_input_map_is_bound_by_the_deep_fingerprint() -> Result<()> {
    struct Feed(bool);
    impl Circuit<Fp> for Feed {
        type Instance<'i> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        type Witness<'w> = Fp;
        type Aux<'w> = ();
        fn instance<'dr, 'i: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Self::Instance<'i>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, &mut Standard::new(), instance)
        }
        fn witness<'dr, 'w: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'w>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'w>>>> {
            let w = Element::alloc(dr, &mut Standard::new(), witness)?;
            Ok(WithAux::new(dr.routine(FeedChild(self.0), w)?, D::unit()))
        }
    }

    let fingerprint = |doubled: bool| {
        let metrics = crate::metrics::eval::<Fp, _>(&Feed(doubled)).unwrap();
        match metrics.segments[1].identity() {
            crate::RoutineIdentity::Routine(fp) => *fp,
            crate::RoutineIdentity::Root => unreachable!(),
        }
    };
    assert_eq!(fingerprint(true).base(), fingerprint(false).base());
    assert_ne!(fingerprint(true), fingerprint(false));

    let registry = {
        let mut builder = RegistryBuilder::<Fp, TestRank>::new();
        builder = builder.register_circuit(Feed(true))?;
        builder = builder.register_circuit(Feed(false))?;
        builder.finalize()?
    };
    let (w, x, y) = (random(), random(), random());
    assert_eq!(registry.xy(x, y).eval(w), registry.wxy(w, x, y));
    Ok(())
}

/// Output of a [`RoutineCircuit`] for witness `w`, by plain arithmetic.
fn expected_output(layout: RoutineLayout, w: Fp) -> Fp {
    let pow2 = |v: Fp, times: usize| (0..times).fold(v, |acc, _| acc.square());
    match layout {
        RoutineLayout::Single | RoutineLayout::FeedFirst | RoutineLayout::FeedSecond => pow2(w, 2),
        RoutineLayout::Shifted(gates) => pow2(w, gates + 2),
        RoutineLayout::Nested => pow2(w, 5),
        RoutineLayout::Repeated => pow2(w, 4),
    }
}

/// With the registry's aligned floor plans: shared routines sit at the same
/// offsets in every circuit, the three evaluators still agree, and the trace
/// assembled against the plan satisfies the revdot identity against `s(X, y)`.
#[test]
fn aligned_plans_are_consistent() -> Result<()> {
    use RoutineLayout::*;
    let layouts = [
        Single,
        Shifted(2),
        Nested,
        FeedSecond,
        Repeated,
        Nested,
        Single,
    ];
    let registry = registry(&layouts)?;
    let plans = registry.floor_plans();

    // `DoubleSquare` at circuit scope: Single[1], Shifted[1], FeedSecond[1],
    // Repeated[1] share one slot; Repeated[2] follows it.
    let slot = (plans[0][1].gate_start, plans[0][1].constraint_start);
    for i in [1, 3] {
        assert_eq!((plans[i][1].gate_start, plans[i][1].constraint_start), slot);
    }
    assert_eq!((plans[4][1].gate_start, plans[4][1].constraint_start), slot);
    assert_eq!(plans[4][2].gate_start, slot.0 + plans[0][1].num_gates);
    // The two `Nested` circuits share their block, nested segment included.
    assert_eq!(plans[2][1].gate_start, plans[5][1].gate_start);
    assert_eq!(plans[2][2].gate_start, plans[5][2].gate_start);
    assert_eq!(
        plans[2][2].gate_start,
        plans[2][1].gate_start + plans[2][1].num_gates
    );

    let (x, y, z) = (random(), random(), random());
    for ((layout, circuit), plan) in layouts.iter().zip(registry.circuits()).zip(plans) {
        let sxy = circuit.sxy(x, y, plan);
        assert_eq!(sxy, circuit.sx(x, plan).eval(y), "{layout:?}");
        assert_eq!(sxy, circuit.sy(y, plan).eval(x), "{layout:?}");

        let w = random();
        let trace = RoutineCircuit(*layout).trace(w)?.into_output();
        let a = trace.assemble::<TestRank>(plan, Fp::ZERO)?;
        let mut b = a.clone();
        b.dilate(z);
        b.add_assign(&circuit.sy(y, plan));
        b.add_assign(&TestRank::tz(z));
        let expected = RoutineCircuit(*layout).ky(expected_output(*layout, w), y)?;
        assert_eq!(a.revdot(&b), expected, "{layout:?}");
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

    // The same recordings serve `s(x, Y)` and `s(X, y)`: one cache each
    // across all objects.
    let mut cache = MemoCache::new();
    for (obj, (layout, _)) in objs.iter().zip(sequence) {
        let plan = floor_planner::floor_plan(obj.segment_records());
        let memoized = obj.sx_with_cache(x, &plan, &mut cache);
        assert!(
            memoized.iter_coeffs().eq(obj.sx(x, &plan).iter_coeffs()),
            "{layout:?}"
        );
    }
    assert_eq!(cache.hits(), hits);
    let mut cache = MemoCache::new();
    for (obj, (layout, _)) in objs.iter().zip(sequence) {
        let plan = floor_planner::floor_plan(obj.segment_records());
        let memoized = obj.sy_with_cache(y, &plan, &mut cache);
        assert!(
            memoized.iter_coeffs().eq(obj.sy(y, &plan).iter_coeffs()),
            "{layout:?}"
        );
    }
    assert_eq!(cache.hits(), hits);
    Ok(())
}

/// `wy` memoizes across circuits; it must agree with the per-circuit
/// evaluation `wxy` at every `x`.
#[test]
fn wy_matches_wxy() -> Result<()> {
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
    let w_in_domain = CircuitIndex::new(2).omega_j::<Fp>();
    for w in [w, w_in_domain] {
        assert_eq!(registry.wy(w, y).eval(x), registry.wxy(w, x, y));
        assert_eq!(
            registry.wy(w, Fp::ZERO).eval(x),
            registry.wxy(w, x, Fp::ZERO)
        );
    }
    Ok(())
}

/// `wx` memoizes across circuits; it must agree with the per-circuit
/// evaluation `wxy` at every `y`.
#[test]
fn wx_matches_wxy() -> Result<()> {
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
    let w_in_domain = CircuitIndex::new(2).omega_j::<Fp>();
    for w in [w, w_in_domain] {
        assert_eq!(registry.wx(w, x).eval(y), registry.wxy(w, x, y));
        assert_eq!(
            registry.wx(w, Fp::ZERO).eval(y),
            registry.wxy(w, Fp::ZERO, y)
        );
    }
    Ok(())
}
