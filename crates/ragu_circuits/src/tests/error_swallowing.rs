//! Error-swallowing trust boundary.
//!
//! Circuits are trusted to propagate driver errors with `?`. A malicious
//! circuit can instead drop an error and keep running. These tests pin what
//! actually happens on each driver path when it does. For direct gate failures,
//! the trace evaluator records nothing while the metrics counter still counts
//! the gate, and assembly catches the resulting desynchronization. For partially
//! executed routine failures, the trace evaluator stops the routine after the
//! failing witness closure while the metrics counter, which does not run that
//! closure, walks the complete routine. Assembly then catches the short routine
//! segment.

use alloc::format;

use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::Fp,
    routines::{Prediction, Routine},
};
use ragu_primitives::{Element, allocator::Standard};
use udon::field::Field;

use crate::{Circuit, CircuitExt, WithAux, into_wiring_object, polynomials::TestRank};

/// Well-behaved reference circuit: allocates `a` and `b`, outputs `(a + b, a - b)`.
///
/// Serves as the control for the error-swallowing circuits below: same
/// constraints, same allocations, no dropped errors.
struct WellBehavedCircuit;

impl Circuit<Fp> for WellBehavedCircuit {
    type Instance<'instance> = (Fp, Fp);
    type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Witness<'witness> = (Fp, Fp);
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let c = Element::alloc(dr, allocator, instance.as_ref().map(|v| v.0))?;
        let d = Element::alloc(dr, allocator, instance.as_ref().map(|v| v.1))?;
        Ok((c, d))
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>> {
        let allocator = &mut Standard::new();
        let a = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.0))?;
        let b = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.1))?;
        let c = a.add(dr, &b);
        let d = a.sub(dr, &b);
        Ok(WithAux::new((c, d), D::unit()))
    }
}

/// Malicious circuit: identical to [`WellBehavedCircuit`], but drops the error
/// from a bogus gate placed between the two real allocations.
///
/// Exercises the trust boundary where circuits are expected to propagate driver
/// errors with `?`. The two driver paths disagree about whether that gate
/// exists:
///
/// * [`trace`](crate::trace)'s evaluator has `MaybeKind = Always`, so
///   [`gate`](ragu_core::drivers::DriverTypes::gate) evaluates the closure
///   before touching any segment. The closure fails, nothing is recorded, and
///   the swallowed error leaves the trace byte-identical to the well-behaved
///   one.
/// * [`metrics`](crate::metrics)'s counter has `MaybeKind = Empty` and never
///   calls the closure, so it counts the gate.
///
/// The result is a gate-count desynchronization rather than corrupted wire
/// values; see [`test_error_swallowing_desyncs_trace_and_metrics`].
struct ErrorSwallowingCircuit;

impl Circuit<Fp> for ErrorSwallowingCircuit {
    type Instance<'instance> = (Fp, Fp);
    type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Witness<'witness> = (Fp, Fp);
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let c = Element::alloc(dr, allocator, instance.as_ref().map(|v| v.0))?;
        let d = Element::alloc(dr, allocator, instance.as_ref().map(|v| v.1))?;
        Ok((c, d))
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>> {
        let allocator = &mut Standard::new();
        let a = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.0))?;
        // Swallow the error rather than propagating it with `?`.
        let _ = dr.mul(|| Err(Error::InvalidWitness("swallowed".into())));
        let b = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.1))?;
        let c = a.add(dr, &b);
        let d = a.sub(dr, &b);
        Ok(WithAux::new((c, d), D::unit()))
    }
}

/// Routine that records one gate before a witness-only allocation error.
///
/// The trace driver evaluates `D::try_just`, so it records the square and then
/// returns the allocation error. Empty structure drivers do not evaluate that
/// closure, so they record the allocation and complete the routine.
#[derive(Clone)]
struct PartiallyExecutedFailingRoutine;

impl Routine<Fp> for PartiallyExecutedFailingRoutine {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let _partial_output = input.square(dr)?;
        let failed_value: DriverValue<D, Fp> =
            D::try_just(|| Err(Error::InvalidWitness("routine failed".into())))?;
        Element::alloc(dr, &mut Standard::new(), failed_value)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// Propagates a partially executed routine's error back to the calling
/// circuit.
struct RoutineErrorPropagatingCircuit;

impl Circuit<Fp> for RoutineErrorPropagatingCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witness> = Fp;
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>> {
        let input = Element::alloc(dr, &mut Standard::new(), witness)?;
        let output = dr.routine(PartiallyExecutedFailingRoutine, input)?;
        Ok(WithAux::new(output, D::unit()))
    }
}

/// Malicious circuit that ignores a partially executed routine's error and
/// continues allocating in its parent scope.
struct RoutineErrorSwallowingCircuit;

impl Circuit<Fp> for RoutineErrorSwallowingCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witness> = (Fp, Fp);
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>> {
        let allocator = &mut Standard::new();
        let routine_input = Element::alloc(dr, allocator, witness.as_ref().map(|value| value.0))?;

        // Swallow the error rather than propagating it with `?`.
        let _ = dr.routine(PartiallyExecutedFailingRoutine, routine_input);

        // Trace evaluation restores the parent scope before returning the error.
        let output = Element::alloc(dr, allocator, witness.as_ref().map(|value| value.1))?;
        Ok(WithAux::new(output, D::unit()))
    }
}

/// Positive control: a circuit that propagates a gate error with `?` causes
/// [`CircuitExt::trace`] to fail, confirming that the trace driver surfaces the
/// error. This is the complement to the [`ErrorSwallowingCircuit`] tests.
#[test]
fn test_propagated_gate_error_caught() {
    struct ErrorPropagatingCircuit;

    impl Circuit<Fp> for ErrorPropagatingCircuit {
        type Instance<'instance> = (Fp, Fp);
        type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
        type Witness<'witness> = (Fp, Fp);
        type Aux<'witness> = ();

        fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Self::Instance<'instance>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            let allocator = &mut Standard::new();
            let c = Element::alloc(dr, allocator, instance.as_ref().map(|v| v.0))?;
            let d = Element::alloc(dr, allocator, instance.as_ref().map(|v| v.1))?;
            Ok((c, d))
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>>
        {
            let allocator = &mut Standard::new();
            let a = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.0))?;
            // Propagate the error with `?` — unlike ErrorSwallowingCircuit.
            let _bogus = dr.mul(|| Err(Error::InvalidWitness("propagated".into())))?;
            let b = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.1))?;
            let c = a.add(dr, &b);
            let d = a.sub(dr, &b);
            Ok(WithAux::new((c, d), D::unit()))
        }
    }

    let witness = (Fp::from(3u64), Fp::from(7u64));
    match ErrorPropagatingCircuit.trace(witness) {
        Err(Error::InvalidWitness(err)) => {
            assert_eq!(format!("{err}"), "propagated");
        }
        Err(other) => panic!("expected InvalidWitness, got {other:?}"),
        Ok(_) => panic!("trace should fail when a gate error is propagated with `?`"),
    }
}

/// Positive control for the routine boundary: propagating the error returned
/// by `dr.routine` aborts trace evaluation with that same error.
#[test]
fn test_propagated_routine_error_caught() {
    let witness = Fp::from(3u64);
    match RoutineErrorPropagatingCircuit.trace(witness) {
        Err(Error::InvalidWitness(err)) => {
            assert_eq!(format!("{err}"), "routine failed");
        }
        Err(other) => panic!("expected InvalidWitness, got {other:?}"),
        Ok(_) => panic!("trace should fail when a routine error is propagated with `?`"),
    }

    let obj = into_wiring_object::<_, _, TestRank>(RoutineErrorPropagatingCircuit)
        .expect("structure drivers must not evaluate the failing witness closure");
    assert_eq!(obj.floor_plan().len(), 2);
}

/// A swallowed routine error leaves the routine trace one gate shorter than the
/// structure recorded by metrics, so assembly rejects the routine segment.
#[test]
#[should_panic(expected = "segment 1 size must match floor plan")]
fn test_swallowed_routine_error_rejected_during_assembly() {
    let witness = (Fp::from(3u64), Fp::from(7u64));

    let trace = RoutineErrorSwallowingCircuit
        .trace(witness)
        .expect("the malicious circuit swallowed the routine error")
        .into_output();
    assert_eq!(trace.segments.len(), 2);
    assert_eq!(trace.segments[0].a.len(), 2);
    assert_eq!(trace.segments[0].a[1], Fp::from(3u64));
    assert_eq!(trace.segments[0].d[1], Fp::from(7u64));
    assert_eq!(trace.segments[1].a.len(), 1);

    let obj = into_wiring_object::<_, _, TestRank>(RoutineErrorSwallowingCircuit).unwrap();
    let plan = obj.floor_plan();
    assert_eq!(trace.segments[1].a.len() + 1, plan[1].num_gates);

    let _ = trace.assemble::<TestRank>(plan, Fp::ZERO);
}

/// The trace driver evaluates a gate's closure before recording anything, so a
/// swallowed error leaves no residue: the malicious trace is identical to the
/// well-behaved one, wire for wire.
///
/// Note that `b` and `c` are zero in both traces. [`Standard`] packs two
/// allocations into one gate's unconstrained $A$ and $D$ wires, so allocation
/// never writes to the $B$ or $C$ slots.
#[test]
fn test_error_swallowing_is_invisible_to_trace() {
    let witness = (Fp::from(3u64), Fp::from(7u64));

    let good = WellBehavedCircuit.trace(witness).unwrap().into_output();
    let bad = ErrorSwallowingCircuit.trace(witness).unwrap().into_output();

    assert_eq!(good.segments.len(), 1);
    assert_eq!(bad.segments.len(), 1);

    let (good, bad) = (&good.segments[0], &bad.segments[0]);
    assert_eq!(
        good.a.len(),
        bad.a.len(),
        "the swallowed gate must not appear in the trace"
    );
    assert_eq!(good.a, bad.a);
    assert_eq!(good.b, bad.b);
    assert_eq!(good.c, bad.c);
    assert_eq!(good.d, bad.d);

    // Segment 0 holds the SYSTEM gate plus the one gate that carries both
    // paired allocations in its A and D wires.
    assert_eq!(good.a.len(), 2);
    assert_eq!(good.a[1], Fp::from(3u64));
    assert_eq!(good.d[1], Fp::from(7u64));
    assert_eq!(good.b[1], Fp::ZERO);
    assert_eq!(good.c[1], Fp::ZERO);
}

/// The swallowed error is visible to the metrics driver but not to the trace
/// driver, so the two disagree on the gate count. This desynchronization — not
/// corrupted wire values — is what a swallowed error actually produces. The
/// wiring drivers themselves stay self-consistent throughout: `sx`, `sy` and
/// `sxy` never run witness closures, so the bogus gate perturbs only the gate
/// count, never $s(X, Y)$.
#[test]
fn test_error_swallowing_desyncs_trace_and_metrics() {
    let witness = (Fp::from(3u64), Fp::from(7u64));

    let good_metrics = crate::metrics::eval(&WellBehavedCircuit).unwrap();
    let bad_metrics = crate::metrics::eval(&ErrorSwallowingCircuit).unwrap();

    let (good_gates, good_constraints) = (good_metrics.num_gates, good_metrics.num_constraints);
    let (bad_gates, bad_constraints) = (bad_metrics.num_gates, bad_metrics.num_constraints);

    assert_eq!(
        good_gates + 1,
        bad_gates,
        "the metrics driver never calls the closure, so it counts the bogus gate"
    );
    assert_eq!(
        good_constraints, bad_constraints,
        "the bogus gate adds no linear constraint"
    );

    let trace = ErrorSwallowingCircuit.trace(witness).unwrap().into_output();
    assert_eq!(
        trace.segments[0].a.len() + 1,
        bad_gates,
        "the trace is one gate short of what the wiring object expects"
    );
}

/// The gate-count desynchronization is caught when the trace is assembled
/// against its own floor plan.
#[test]
#[should_panic(expected = "segment 0 size must match floor plan")]
fn test_error_swallowing_trace_assembly_rejected() {
    let witness = (Fp::from(3u64), Fp::from(7u64));

    let obj = into_wiring_object::<_, _, TestRank>(ErrorSwallowingCircuit).unwrap();
    let plan = obj.floor_plan();
    let trace = ErrorSwallowingCircuit.trace(witness).unwrap().into_output();

    let _ = trace.assemble::<TestRank>(plan, Fp::ZERO);
}
