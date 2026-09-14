#![allow(non_snake_case)]

mod error_swallowing;
mod identity;
mod known_routine_soundness;
mod segment_order;

use ragu_arithmetic::ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Kind},
    maybe::{Always, Maybe},
    routines::{Prediction, Routine},
};
use ragu_pasta::Fp;
use ragu_primitives::{Element, Simulator, allocator::Standard};

use crate::{
    Circuit, CircuitExt, WiringObject, WithAux, floor_planner, into_wiring_object,
    polynomials::{Rank, TestRank},
};

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
        let allocator = &mut Standard::new();
        Element::alloc(dr, allocator, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>> {
        let allocator = &mut Standard::new();
        let mut a = Element::alloc(dr, allocator, witness)?;

        for _ in 0..self.times {
            a = a.square(dr)?;
        }

        Ok(WithAux::new(a, D::unit()))
    }
}

/// Circuit with a configurable number of linear constraints.
struct ManyLinearCircuit {
    constraints: usize,
}

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
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>> {
        let a = Element::alloc(dr, &mut Standard::new(), witness)?;
        for _ in 0..self.constraints {
            dr.enforce_zero(|lc| lc.add(a.wire()))?;
        }
        Ok(WithAux::new(a, D::unit()))
    }
}

fn consistency_checks<R: Rank>(obj: &dyn WiringObject<Fp, R>) {
    let x = Fp::random(&mut ragu_arithmetic::rand::rng());
    let y = Fp::random(&mut ragu_arithmetic::rand::rng());
    let plan = floor_planner::floor_plan(obj.segment_records());

    let sxy_eval = obj.sxy(x, y, &plan);
    let s0y_eval = obj.sxy(Fp::ZERO, y, &plan);
    let sx0_eval = obj.sxy(x, Fp::ZERO, &plan);
    let s00_eval = obj.sxy(Fp::ZERO, Fp::ZERO, &plan);

    let sxY_poly = obj.sx(x, &plan);
    let sXy_poly = obj.sy(y, &plan);
    let s0Y_poly = obj.sx(Fp::ZERO, &plan);
    let sX0_poly = obj.sy(Fp::ZERO, &plan);

    assert_eq!(sxy_eval, sXy_poly.eval(x));
    assert_eq!(sxy_eval, sxY_poly.eval(y));
    assert_eq!(s0y_eval, sXy_poly.eval(Fp::ZERO));
    assert_eq!(sx0_eval, sxY_poly.eval(Fp::ZERO));
    assert_eq!(s0y_eval, s0Y_poly.eval(y));
    assert_eq!(sx0_eval, sX0_poly.eval(x));
    assert_eq!(s00_eval, s0Y_poly.eval(Fp::ZERO));
    assert_eq!(s00_eval, sX0_poly.eval(Fp::ZERO));
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
            let b = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.1))?;

            let a2 = a.square(dr)?;
            let a4 = a2.square(dr)?;
            let a5 = a4.mul(dr, &a)?;

            let b2 = b.square(dr)?;

            dr.enforce_zero(|lc| lc.add(a5.wire()).sub(b2.wire()))?;

            let c = a.add(dr, &b);
            let d = a.sub(dr, &b);

            Ok(WithAux::new((c, d), D::unit()))
        }
    }

    let trace = MySimpleCircuit
        .trace((
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
        .unwrap()
        .into_output();
    type MyRank = TestRank;

    let obj = into_wiring_object::<_, _, MyRank>(MySimpleCircuit).unwrap();
    let plan = floor_planner::floor_plan(obj.segment_records());

    let assignment = trace.assemble(&plan, Fp::ZERO).unwrap();

    consistency_checks::<MyRank>(&*obj);

    let y = Fp::random(&mut ragu_arithmetic::rand::rng());
    let z = Fp::random(&mut ragu_arithmetic::rand::rng());

    let a = assignment.clone();
    let mut b = assignment.clone();
    b.dilate(z);
    b.add_assign(&obj.sy(y, &plan));
    b.add_assign(&MyRank::tz(z));

    let expected = MySimpleCircuit
        .ky(
            (
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
            ),
            y,
        )
        .unwrap();

    assert_eq!(expected, a.revdot(&b));
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
        let allocator = &mut Standard::new();
        let element_from_aux = Element::alloc(dr, allocator, D::just(|| precomputed_value))?;
        let other = Element::alloc(dr, allocator, D::just(|| Fp::from(5u64)))?;
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
    let allocator = &mut Standard::new();
    let input = Element::alloc(
        &mut simulator,
        allocator,
        Always::<Fp>::just(|| Fp::from(5u64)),
    )
    .unwrap();
    let result = simulator.routine(TestRoutine, input).unwrap();
    assert_eq!(*result.value().take(), Fp::from(15u64));
}

/// `SquareCircuit { times: 30 }` with `TestRank` (`R<7>`, `n = 32`).
/// Total gates: 1 (SYSTEM) + 1 (allocation) + 30 (squares) = 32 = `n()`.
#[test]
fn test_gate_bound_exact() {
    let result = into_wiring_object::<_, _, TestRank>(SquareCircuit { times: 30 });
    assert!(result.is_ok(), "32 gates should fit exactly in n() = 32");
}

/// `SquareCircuit { times: 31 }` needs 33 gates > `n()` = 32, so it must fail
/// with [`Error::GateBoundExceeded`].
#[test]
fn test_gate_bound_exceeded() {
    match into_wiring_object::<_, _, TestRank>(SquareCircuit { times: 31 }) {
        Err(Error::GateBoundExceeded { limit }) => {
            assert_eq!(limit, TestRank::n());
        }
        other => panic!(
            "expected GateBoundExceeded {{ limit: {} }}, got {:?}",
            TestRank::n(),
            other.map(|_| "(ok)")
        ),
    }
}

/// With `TestRank` (`R<7>`): `num_coeffs` = 128, of which `into_wiring_object`
/// reserves the last slot ($Y^{4n-1}$) for the registry tag constraint, leaving
/// 127 usable. Overhead is 2 constraints (1 output + 1 ONE), so 125
/// `enforce_zero` calls exactly fill the available slots.
#[test]
fn test_constraint_bound_exact() {
    let result = into_wiring_object::<_, _, TestRank>(ManyLinearCircuit { constraints: 125 });
    assert!(
        result.is_ok(),
        "127 constraints should fit exactly below the reserved registry slot"
    );
}

/// One additional `enforce_zero` call produces 128 constraints and must exceed
/// the 127 usable coefficient slots.
#[test]
fn test_constraint_bound_exceeded() {
    let limit = TestRank::num_coeffs() - 1;
    match into_wiring_object::<_, _, TestRank>(ManyLinearCircuit { constraints: 126 }) {
        Err(Error::ConstraintBoundExceeded { limit: reported }) => {
            assert_eq!(reported, limit);
        }
        other => panic!(
            "expected ConstraintBoundExceeded {{ limit: {limit} }}, got {:?}",
            other.map(|_| "(ok)")
        ),
    }
}

/// A routine compatible with all drivers (including `Empty`-typed ones).
/// Allocates two elements and returns their sum with the input, without
/// calling `.take()` on aux.
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
        let allocator = &mut Standard::new();
        let elem1 = Element::alloc(dr, allocator, D::just(|| Fp::from(5u64)))?;
        let elem2 = Element::alloc(dr, allocator, D::just(|| Fp::from(7u64)))?;
        let sum = elem1.add(dr, &elem2);
        let result = input.add(dr, &sum);
        Ok(result)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// Circuit that calls `dr.routine(SimpleRoutine, input)` in its `witness`
/// method, exercising per-routine scope save/restore across trace, metrics, and
/// wiring evaluation.
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
            let allocator = &mut Standard::new();
            Element::alloc(dr, allocator, instance)
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'witness>>>>
        {
            let allocator = &mut Standard::new();
            let input = Element::alloc(dr, allocator, witness)?;
            let result = dr.routine(SimpleRoutine, input)?;
            Ok(WithAux::new(result, D::unit()))
        }
    }

    let trace = RoutineCircuit.trace(Fp::from(3u64)).unwrap().into_output();
    let obj = into_wiring_object::<_, _, TestRank>(RoutineCircuit).unwrap();
    let plan = floor_planner::floor_plan(obj.segment_records());

    trace.assemble::<TestRank>(&plan, Fp::ZERO).unwrap();
    consistency_checks(&*obj);
}
