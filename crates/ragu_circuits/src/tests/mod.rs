#![allow(non_snake_case)]

use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pasta::Fp;
use ragu_primitives::Element;

use crate::{
    Circuit, CircuitExt, CircuitObject,
    polynomials::{Rank, TestRank},
    registry,
};
use ragu_core::maybe::Always;
use ragu_core::routines::Prediction;
use ragu_core::routines::Routine;
use ragu_primitives::Simulator;

/// Dummy circuit.
pub struct SquareCircuit {
    pub times: usize,
}

impl Circuit<Fp> for SquareCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witness> = Fp;
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<(
        Bound<'dr, D, Self::Output>,
        DriverValue<D, Self::Aux<'witness>>,
    )> {
        let mut a = Element::alloc(dr, witness)?;

        for _ in 0..self.times {
            a = a.square(dr)?;
        }

        Ok((a, D::just(|| ())))
    }
}

fn consistency_checks<R: Rank>(circuit: &dyn CircuitObject<Fp, R>) {
    let x = Fp::random(&mut rand::rng());
    let y = Fp::random(&mut rand::rng());
    let k = registry::Key::new(Fp::random(&mut rand::rng()));
    let floor_plan = crate::floor_planner::floor_plan(circuit.segment_records());

    let sxy_eval = circuit.sxy(x, y, &k, &floor_plan);
    let s0y_eval = circuit.sxy(Fp::ZERO, y, &k, &floor_plan);
    let sx0_eval = circuit.sxy(x, Fp::ZERO, &k, &floor_plan);
    let s00_eval = circuit.sxy(Fp::ZERO, Fp::ZERO, &k, &floor_plan);

    let sxY_poly = circuit.sx(x, &k, &floor_plan);
    let sXy_poly = circuit.sy(y, &k, &floor_plan).unstructured();
    let s0Y_poly = circuit.sx(Fp::ZERO, &k, &floor_plan);
    let sX0_poly = circuit.sy(Fp::ZERO, &k, &floor_plan).unstructured();

    assert_eq!(sxy_eval, ragu_arithmetic::eval(&sXy_poly[..], x));
    assert_eq!(sxy_eval, ragu_arithmetic::eval(&sxY_poly[..], y));
    assert_eq!(s0y_eval, ragu_arithmetic::eval(&sXy_poly[..], Fp::ZERO));
    assert_eq!(sx0_eval, ragu_arithmetic::eval(&sxY_poly[..], Fp::ZERO));
    assert_eq!(s0y_eval, ragu_arithmetic::eval(&s0Y_poly[..], y));
    assert_eq!(sx0_eval, ragu_arithmetic::eval(&sX0_poly[..], x));
    assert_eq!(s00_eval, ragu_arithmetic::eval(&s0Y_poly[..], Fp::ZERO));
    assert_eq!(s00_eval, ragu_arithmetic::eval(&sX0_poly[..], Fp::ZERO));
}

#[test]
fn test_simple_circuit() {
    // Simple circuit: prove knowledge of a and b such that a^5 = b^2 and a + b = c
    // and a - b = d where c and d are public inputs.
    struct MySimpleCircuit;

    impl Circuit<Fp> for MySimpleCircuit {
        type Instance<'instance> = (Fp, Fp); // Public inputs: c and d
        type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
        type Witness<'witness> = (Fp, Fp); // Witness: a and b
        type Aux<'witness> = ();

        fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Self::Instance<'instance>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            let c = Element::alloc(dr, instance.view().map(|v| v.0))?;
            let d = Element::alloc(dr, instance.view().map(|v| v.1))?;

            Ok((c, d))
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<(
            Bound<'dr, D, Self::Output>,
            DriverValue<D, Self::Aux<'witness>>,
        )> {
            let a = Element::alloc(dr, witness.view().map(|w| w.0))?;
            let b = Element::alloc(dr, witness.view().map(|w| w.1))?;

            let a2 = a.square(dr)?;
            let a4 = a2.square(dr)?;
            let a5 = a4.mul(dr, &a)?;

            let b2 = b.square(dr)?;

            dr.enforce_zero(|lc| lc.add(a5.wire()).sub(b2.wire()))?;

            let c = a.add(dr, &b);
            let d = a.sub(dr, &b);

            Ok(((c, d), D::just(|| ())))
        }
    }

    let (trace, _) = MySimpleCircuit
        .rx((
            Fp::from_raw([
                1833481853729904510,
                5119040798866070668,
                13106006979685074791,
                104139735293675522,
            ]),
            Fp::from_raw([
                1114250137190507128,
                15522336584428696251,
                4689053926428793931,
                2277752110332726989,
            ]),
        ))
        .unwrap();
    let assignment = trace.assemble_trivial::<MyRank>().unwrap();

    type MyRank = TestRank;
    let circuit = MySimpleCircuit.into_object::<MyRank>().unwrap();

    consistency_checks(&*circuit);

    let y = Fp::random(&mut rand::rng());
    let z = Fp::random(&mut rand::rng());
    let k = registry::Key::default();
    let floor_plan = crate::floor_planner::floor_plan(circuit.segment_records());

    let a = assignment.clone();
    let mut b = assignment.clone();
    b.dilate(z);
    b.add_assign(&circuit.sy(y, &k, &floor_plan));
    b.add_assign(&MyRank::tz(z));

    let expected = ragu_arithmetic::eval(
        &MySimpleCircuit
            .ky((
                Fp::from_raw([
                    2947731990920411638,
                    2194633309585215303,
                    17795060906113868723,
                    2381891845626402511,
                ]),
                Fp::from_raw([
                    11756763772759733511,
                    10513277942061441772,
                    8416953053256280859,
                    2438073643388336437,
                ]),
            ))
            .unwrap(),
        y,
    );

    let a = a.unstructured();
    let b = b.unstructured();

    assert_eq!(expected, ragu_arithmetic::dot(a.iter(), b.iter().rev()),);
}

#[derive(Clone)]
struct TestRoutine;

impl Routine<Fp> for TestRoutine {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = Fp;

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let precomputed_value = aux.take();
        let element_from_aux = Element::alloc(dr, D::just(|| precomputed_value))?;
        let other = Element::alloc(dr, D::just(|| Fp::from(5u64)))?;
        let result = element_from_aux.add(dr, &other);
        Ok(result)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| Fp::from(10u64))))
    }
}

#[test]
fn test_element() {
    let mut simulator = Simulator::<Fp>::new();
    let input = Element::alloc(&mut simulator, Always::<Fp>::just(|| Fp::from(5u64))).unwrap();
    let result = simulator.routine(TestRoutine, input).unwrap();
    assert_eq!(*result.value().take(), Fp::from(15u64));
    assert_eq!(simulator.num_allocations(), 3);
}

/// Well-behaved reference circuit: allocates a, b, outputs (a+b, a-b).
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
        let c = Element::alloc(dr, instance.view().map(|v| v.0))?;
        let d = Element::alloc(dr, instance.view().map(|v| v.1))?;
        Ok((c, d))
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<(
        Bound<'dr, D, Self::Output>,
        DriverValue<D, Self::Aux<'witness>>,
    )> {
        let a = Element::alloc(dr, witness.view().map(|w| w.0))?;
        let b = Element::alloc(dr, witness.view().map(|w| w.1))?;
        let c = a.add(dr, &b);
        let d = a.sub(dr, &b);
        Ok(((c, d), D::just(|| ())))
    }
}

/// Malicious circuit: identical shape to WellBehavedCircuit, but swallows an
/// error from a bogus allocation between the two real allocations.
///
/// Exercises the trust boundary where circuits are expected to propagate
/// driver errors with `?`. A malicious circuit can instead drop the error,
/// corrupting the rx polynomial while leaving s-polynomial drivers unaffected.
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
        let c = Element::alloc(dr, instance.view().map(|v| v.0))?;
        let d = Element::alloc(dr, instance.view().map(|v| v.1))?;
        Ok((c, d))
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<(
        Bound<'dr, D, Self::Output>,
        DriverValue<D, Self::Aux<'witness>>,
    )> {
        let a = Element::alloc(dr, witness.view().map(|w| w.0))?;
        // Swallow the error: available_b was consumed, but the closure's error
        // is silently dropped. In rx, this corrupts gate b/c slots (they stay
        // zero). In sx/sy/sxy/Counter, the closure is never called, so the
        // allocation succeeds and the returned wire is simply dropped.
        let _ = dr.alloc(|| Err(Error::InvalidWitness("swallowed".into())));
        let b = Element::alloc(dr, witness.view().map(|w| w.1))?;
        let c = a.add(dr, &b);
        let d = a.sub(dr, &b);
        Ok(((c, d), D::just(|| ())))
    }
}

/// Positive control: a circuit that properly propagates an alloc error with
/// `?` causes rx() to fail, confirming that the rx driver surfaces the error.
/// This is the complement to the ErrorSwallowingCircuit negative test.
#[test]
fn test_propagated_alloc_error_caught() {
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
            let c = Element::alloc(dr, instance.view().map(|v| v.0))?;
            let d = Element::alloc(dr, instance.view().map(|v| v.1))?;
            Ok((c, d))
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<(
            Bound<'dr, D, Self::Output>,
            DriverValue<D, Self::Aux<'witness>>,
        )> {
            let a = Element::alloc(dr, witness.view().map(|w| w.0))?;
            // Properly propagate the error with `?` — unlike ErrorSwallowingCircuit.
            let _bogus = dr.alloc(|| Err(Error::InvalidWitness("propagated".into())))?;
            let b = Element::alloc(dr, witness.view().map(|w| w.1))?;
            let c = a.add(dr, &b);
            let d = a.sub(dr, &b);
            Ok(((c, d), D::just(|| ())))
        }
    }

    let witness = (Fp::from(3u64), Fp::from(7u64));
    let result = ErrorPropagatingCircuit.rx(witness);
    match result {
        Err(Error::InvalidWitness(err)) => {
            assert_eq!(err.to_string(), "propagated");
        }
        Err(other) => panic!("expected InvalidWitness, got {:?}", other),
        Ok(_) => panic!("rx should fail when alloc error is properly propagated with `?`"),
    }
}

/// The swallowed alloc consumes available_b in the rx driver, causing the
/// closure error to corrupt gate b/c slots. The well-behaved circuit produces
/// a different rx trace because it fills those slots correctly.
#[test]
fn test_error_swallowing_corrupts_rx() {
    let witness = (Fp::from(3u64), Fp::from(7u64));

    let (trace_good, _) = WellBehavedCircuit.rx(witness).unwrap();
    let (trace_bad, _) = ErrorSwallowingCircuit.rx(witness).unwrap();

    // The traces must differ because the swallowed alloc left gate b/c
    // slots as zeros in the malicious version and introduced an extra gate.
    let good_len = trace_good.segments[0].a.len();
    let bad_len = trace_bad.segments[0].a.len();
    assert_eq!(
        good_len + 1,
        bad_len,
        "swallowed alloc should create an extra gate in rx"
    );
    // Contract check: rx::Evaluator::alloc reserves a gate before executing
    // the closure, so a failing closure still consumes the b/c slots.
    assert!(
        good_len > 1 && bad_len > 1,
        "rx should contain at least two gates (key + allocation)"
    );

    assert_ne!(
        trace_good.segments[0].b[1],
        Fp::ZERO,
        "well-behaved b slot should be nonzero"
    );
    assert_ne!(
        trace_good.segments[0].c[1],
        Fp::ZERO,
        "well-behaved c slot should be nonzero"
    );
    assert_eq!(
        trace_bad.segments[0].b[1],
        Fp::ZERO,
        "malicious b slot should be zero"
    );
    assert_eq!(
        trace_bad.segments[0].c[1],
        Fp::ZERO,
        "malicious c slot should be zero"
    );
}

/// Cross-circuit revdot check: the malicious circuit's rx is used with the
/// well-behaved circuit's sy. Since the two circuits have different gate
/// structures (the swallowed alloc adds an extra gate in the malicious
/// version), the revdot identity breaks when polynomials from different
/// synthesis paths are mixed.
#[test]
fn test_error_swallowing_breaks_revdot() {
    let a_val = Fp::from(3u64);
    let b_val = Fp::from(7u64);
    let witness = (a_val, b_val);
    let instance = (a_val + b_val, a_val - b_val);

    // rx from the malicious circuit (has corrupted gate slots)
    let (malicious_trace, _) = ErrorSwallowingCircuit.rx(witness).unwrap();
    let malicious_rx = malicious_trace.assemble_trivial::<TestRank>().unwrap();

    // sy from the well-behaved circuit (different gate structure)
    let good_circuit = WellBehavedCircuit.into_object::<TestRank>().unwrap();
    let floor_plan = crate::floor_planner::floor_plan(good_circuit.routine_records());
    let key = registry::Key::default();

    let y = Fp::from(2u64);
    let z = Fp::from(3u64);

    let rx_poly = malicious_rx.clone();
    let mut b_poly = malicious_rx;
    b_poly.dilate(z);
    b_poly.add_assign(&good_circuit.sy(y, &key, &floor_plan));
    b_poly.add_assign(&TestRank::tz(z));

    let ky_eval = ragu_arithmetic::eval(&WellBehavedCircuit.ky(instance).unwrap(), y);

    let rx_u = rx_poly.unstructured();
    let b_u = b_poly.unstructured();
    let revdot = ragu_arithmetic::dot(rx_u.iter(), b_u.iter().rev());

    assert_ne!(
        ky_eval, revdot,
        "revdot identity should break when mixing malicious rx with well-behaved sy"
    );
}

/// consistency_checks passes for the malicious circuit because sx, sy, and sxy
/// all ignore closures and see a consistent synthesis. The corruption is
/// isolated to rx.
#[test]
fn test_error_swallowing_consistency_passes() {
    let circuit = ErrorSwallowingCircuit.into_object::<TestRank>().unwrap();
    // This should not panic: all s-polynomial drivers agree.
    consistency_checks(&*circuit);
}

/// Run SquareCircuit through consistency_checks for small and medium sizes.
#[test]
fn test_square_circuit_consistency() {
    for times in [1, 5] {
        let circuit = SquareCircuit { times }.into_object::<TestRank>().unwrap();
        consistency_checks(&*circuit);
    }
}

/// SquareCircuit { times: 30 } with TestRank (R<7>, n=32).
/// Total gates: 1(key) + 1(alloc) + 30(squares) = 32 = n(). Should succeed.
#[test]
fn test_multiplication_bound_exact() {
    let result = SquareCircuit { times: 30 }.into_object::<TestRank>();
    assert!(result.is_ok(), "32 gates should fit exactly in n()=32");
}

/// SquareCircuit { times: 31 } needs 33 gates > n()=32. Should fail with
/// MultiplicationBoundExceeded.
#[test]
fn test_multiplication_bound_exceeded() {
    let result = SquareCircuit { times: 31 }.into_object::<TestRank>();
    match result {
        Err(Error::MultiplicationBoundExceeded(bound)) => {
            assert_eq!(bound, TestRank::n());
        }
        other => panic!(
            "expected MultiplicationBoundExceeded({}), got {:?}",
            TestRank::n(),
            other.map(|_| "(ok)")
        ),
    }
}

/// Circuit with many enforce_zero calls to exceed the linear bound.
/// With TestRank (R<7>): num_coeffs = 128.
/// Each enforce_zero adds 1 linear constraint.
/// Overhead: degree_ky(1 output) + 2 = 3 (1 output + 1 key + 1 ONE).
/// So 126 enforce_zero calls give total = 126 + 3 = 129 > 128.
#[test]
fn test_linear_bound_exceeded() {
    struct ManyLinearCircuit;

    impl Circuit<Fp> for ManyLinearCircuit {
        type Instance<'instance> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        type Witness<'witness> = Fp;
        type Aux<'witness> = ();

        fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Self::Instance<'instance>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, instance)
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<(
            Bound<'dr, D, Self::Output>,
            DriverValue<D, Self::Aux<'witness>>,
        )> {
            let a = Element::alloc(dr, witness)?;
            for _ in 0..126 {
                dr.enforce_zero(|lc| lc.add(a.wire()))?;
            }
            Ok((a, D::just(|| ())))
        }
    }

    let result = ManyLinearCircuit.into_object::<TestRank>();
    match result {
        Err(Error::LinearBoundExceeded(bound)) => {
            assert_eq!(bound, TestRank::num_coeffs());
        }
        other => panic!(
            "expected LinearBoundExceeded({}), got {:?}",
            TestRank::num_coeffs(),
            other.map(|_| "(ok)")
        ),
    }
}

/// A routine compatible with all drivers (including Empty-typed ones).
/// Allocates two elements (to keep paired allocation counts even) and
/// returns their sum with the input, without calling .take() on aux.
#[derive(Clone)]
struct SimpleRoutine;

impl Routine<Fp> for SimpleRoutine {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let elem1 = Element::alloc(dr, D::just(|| Fp::from(5u64)))?;
        let elem2 = Element::alloc(dr, D::just(|| Fp::from(7u64)))?;
        let sum = elem1.add(dr, &elem2);
        let result = input.add(dr, &sum);
        Ok(result)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| ())))
    }
}

/// Circuit that calls dr.routine(SimpleRoutine, input) in its witness method.
/// Tests the available_b save/restore logic in all evaluators.
#[test]
fn test_routine_consistency() {
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
            Element::alloc(dr, instance)
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<(
            Bound<'dr, D, Self::Output>,
            DriverValue<D, Self::Aux<'witness>>,
        )> {
            let input = Element::alloc(dr, witness)?;
            let result = dr.routine(SimpleRoutine, input)?;
            Ok((result, D::just(|| ())))
        }
    }

    let circuit = RoutineCircuit.into_object::<TestRank>().unwrap();
    consistency_checks(&*circuit);
}
