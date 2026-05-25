//! Fuzz floor-planner invariants over real circuit topologies.
//!
//! The current planner is a prefix sum, but consumers already depend on a
//! stronger public contract that should survive future reordering planners:
//! segment 0 is pinned at the polynomial origin, every planned segment keeps
//! the size observed during synthesis, and planned gate/constraint ranges do
//! not overlap. This target drives the planner through ordinary `Circuit`
//! implementations instead of synthetic `SegmentRecord` values so routine
//! boundaries and nested-routine DFS order stay covered.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::Coeff;
use ragu_circuits::{
    Circuit, SegmentRecord, WithAux,
    floor_planner::{self, ConstraintSegment},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    routines::{Prediction, Routine},
};
use ragu_primitives::{Element, allocator::Standard};
use ragu_testing::circuits::{MySimpleCircuit, SquareCircuit};

#[derive(Arbitrary, Debug)]
enum CircuitChoice {
    Square { times: u8 },
    Simple,
    Routine,
    NestedRoutine,
}

#[derive(Arbitrary, Debug)]
struct Input {
    circuit: CircuitChoice,
}

fn check_non_overlapping_ranges(
    label: &str,
    ranges: &mut [(usize, usize, usize)],
    segments: &[ConstraintSegment],
) {
    ranges.sort_by_key(|(start, _, idx)| (*start, *idx));
    for pair in ranges.windows(2) {
        let (prev_start, prev_end, prev_idx) = pair[0];
        let (start, end, idx) = pair[1];
        assert!(
            prev_end <= start,
            "{label} ranges overlap: segment {prev_idx} [{prev_start}, {prev_end}) \
             intersects segment {idx} [{start}, {end}); plan={segments:?}"
        );
    }
}

fn check_plan(records: &[SegmentRecord], segments: &[ConstraintSegment]) {
    assert!(!segments.is_empty(), "floor plan must include root segment");
    assert_eq!(
        records.len(),
        segments.len(),
        "floor plan and segment records disagree on segment count"
    );
    assert_eq!(
        segments[0].gate_start(),
        0,
        "root segment gate offset must be pinned at zero: {segments:?}"
    );
    assert_eq!(
        segments[0].constraint_start(),
        0,
        "root segment constraint offset must be pinned at zero: {segments:?}"
    );

    let mut gate_ranges = Vec::new();
    let mut constraint_ranges = Vec::new();
    for (idx, (record, segment)) in records.iter().zip(segments.iter()).enumerate() {
        assert_eq!(
            segment.num_gates(),
            record.num_gates(),
            "segment {idx} gate count changed during planning"
        );
        assert_eq!(
            segment.num_constraints(),
            record.num_constraints(),
            "segment {idx} constraint count changed during planning"
        );

        let gate_end = segment
            .gate_start()
            .checked_add(segment.num_gates())
            .expect("gate range overflow");
        let constraint_end = segment
            .constraint_start()
            .checked_add(segment.num_constraints())
            .expect("constraint range overflow");

        if segment.num_gates() > 0 {
            gate_ranges.push((segment.gate_start(), gate_end, idx));
        }
        if segment.num_constraints() > 0 {
            constraint_ranges.push((segment.constraint_start(), constraint_end, idx));
        }
    }

    check_non_overlapping_ranges("gate", &mut gate_ranges, segments);
    check_non_overlapping_ranges("constraint", &mut constraint_ranges, segments);
}

fn check_circuit<C: Circuit<Fp>>(circuit: &C) {
    let records = floor_planner::segment_records_for::<Fp, _>(circuit)
        .expect("metrics collection should succeed");
    let plan = floor_planner::floor_plan(&records);
    check_plan(&records, &plan);
}

#[derive(Clone)]
struct ScaleByThree;

impl Routine<Fp> for ScaleByThree {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = Fp;

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let output = Element::alloc(dr, allocator, aux)?;
        let three_input = input.scale(dr, Coeff::Arbitrary(Fp::from(3u64)));
        dr.enforce_zero(|lc| lc.add(three_input.wire()).sub(output.wire()))?;
        Ok(output)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp, Wire = ()>>(
        &self,
        _dr: &mut D,
        input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        let aux = input.value().map(|v| *v * Fp::from(3u64));
        Ok(Prediction::Unknown(aux))
    }
}

#[derive(Clone)]
struct DoubleAfterNestedTriple;

impl Routine<Fp> for DoubleAfterNestedTriple {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = Fp;

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let tripled = dr.routine(ScaleByThree, input)?;
        let allocator = &mut Standard::new();
        let output = Element::alloc(dr, allocator, aux)?;
        let doubled_tripled = tripled.double(dr);
        dr.enforce_zero(|lc| lc.add(doubled_tripled.wire()).sub(output.wire()))?;
        Ok(output)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp, Wire = ()>>(
        &self,
        _dr: &mut D,
        input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        let aux = input.value().map(|v| *v * Fp::from(6u64));
        Ok(Prediction::Unknown(aux))
    }
}

struct RoutineCircuit;

impl Circuit<Fp> for RoutineCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witness> = Fp;
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        Element::alloc(dr, allocator, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let x = Element::alloc(dr, allocator, witness)?;
        let result = dr.routine(ScaleByThree, x)?;
        Ok(WithAux::new(result, D::unit()))
    }
}

struct NestedRoutineCircuit;

impl Circuit<Fp> for NestedRoutineCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witness> = Fp;
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        Element::alloc(dr, allocator, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let x = Element::alloc(dr, allocator, witness)?;
        let result = dr.routine(DoubleAfterNestedTriple, x)?;
        Ok(WithAux::new(result, D::unit()))
    }
}

fuzz_target!(|input: Input| {
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }

    match input.circuit {
        CircuitChoice::Square { times } => {
            let times = ((times as usize) % 120) + 1;
            check_circuit(&SquareCircuit { times });
        }
        CircuitChoice::Simple => check_circuit(&MySimpleCircuit),
        CircuitChoice::Routine => check_circuit(&RoutineCircuit),
        CircuitChoice::NestedRoutine => check_circuit(&NestedRoutineCircuit),
    }
});
