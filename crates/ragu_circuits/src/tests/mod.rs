#![allow(non_snake_case)]

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_pasta::Fp;
use ragu_primitives::Element;
use rand::thread_rng;

use crate::{
    Circuit, CircuitExt, CircuitObject,
    polynomials::{R, Rank},
    registry,
};
use ragu_core::maybe::Always;
use ragu_core::routines::{Prediction, Routine, RoutineShape};
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
    ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
        Element::alloc(dr, instance)
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<(
        <Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>,
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
    let x = Fp::random(thread_rng());
    let y = Fp::random(thread_rng());
    let k = registry::Key::new(Fp::random(thread_rng()));

    let sxy_eval = circuit.sxy(x, y, &k);
    let s0y_eval = circuit.sxy(Fp::ZERO, y, &k);
    let sx0_eval = circuit.sxy(x, Fp::ZERO, &k);
    let s00_eval = circuit.sxy(Fp::ZERO, Fp::ZERO, &k);

    let sxY_poly = circuit.sx(x, &k);
    let sXy_poly = circuit.sy(y, &k).unstructured();
    let s0Y_poly = circuit.sx(Fp::ZERO, &k);
    let sX0_poly = circuit.sy(Fp::ZERO, &k).unstructured();

    assert_eq!(sxy_eval, arithmetic::eval(&sXy_poly[..], x));
    assert_eq!(sxy_eval, arithmetic::eval(&sxY_poly[..], y));
    assert_eq!(s0y_eval, arithmetic::eval(&sXy_poly[..], Fp::ZERO));
    assert_eq!(sx0_eval, arithmetic::eval(&sxY_poly[..], Fp::ZERO));
    assert_eq!(s0y_eval, arithmetic::eval(&s0Y_poly[..], y));
    assert_eq!(sx0_eval, arithmetic::eval(&sX0_poly[..], x));
    assert_eq!(s00_eval, arithmetic::eval(&s0Y_poly[..], Fp::ZERO));
    assert_eq!(s00_eval, arithmetic::eval(&sX0_poly[..], Fp::ZERO));
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
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            let c = Element::alloc(dr, instance.view().map(|v| v.0))?;
            let d = Element::alloc(dr, instance.view().map(|v| v.1))?;

            Ok((c, d))
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<(
            <Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>,
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

    let assignment = MySimpleCircuit
        .rx::<MyRank>(
            (
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
            ),
            &registry::Key::default(),
        )
        .unwrap()
        .0;

    type MyRank = R<5>;
    let circuit = MySimpleCircuit.into_object::<MyRank>().unwrap();

    consistency_checks(&*circuit);

    let y = Fp::random(thread_rng());
    let z = Fp::random(thread_rng());
    let k = registry::Key::default();

    let a = assignment.clone();
    let mut b = assignment.clone();
    b.dilate(z);
    b.add_assign(&circuit.sy(y, &k));
    b.add_assign(&MyRank::tz(z));

    let expected = arithmetic::eval(
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

    assert_eq!(expected, arithmetic::dot(a.iter(), b.iter().rev()),);
}

#[derive(Clone)]
struct TestRoutine;

impl Routine<Fp> for TestRoutine {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = Fp;

    fn shape(&self) -> RoutineShape {
        RoutineShape::new(0, 0)
    }

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _input: <Self::Input as GadgetKind<Fp>>::Rebind<'dr, D>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
        let precomputed_value = aux.take();
        let element_from_aux = Element::alloc(dr, D::just(|| precomputed_value))?;
        let other = Element::alloc(dr, D::just(|| Fp::from(5u64)))?;
        let result = element_from_aux.add(dr, &other);
        Ok(result)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &<Self::Input as GadgetKind<Fp>>::Rebind<'dr, D>,
    ) -> Result<
        Prediction<
            <Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>,
            DriverValue<D, Self::Aux<'dr>>,
        >,
    > {
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
