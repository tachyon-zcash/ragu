use ff::Field;
use proptest::prelude::*;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::{Always, Maybe},
    routines::{Prediction, Routine},
};
use ragu_pasta::Fp;
use ragu_primitives::{Element, Simulator};

use crate::{
    Circuit, CircuitExt,
    metrics::{self, RoutineIdentity},
    polynomials::{Rank, TestRank},
    registry,
    tests::consistency_checks,
};

type MyRank = TestRank;

fn arb_fe() -> impl Strategy<Value = Fp> {
    (any::<u64>(), any::<u64>()).prop_map(|(a, b)| {
        Fp::from(a) + Fp::from(b) * <Fp as ff::PrimeField>::MULTIPLICATIVE_GENERATOR
    })
}

fn arb_fe_with_edges() -> impl Strategy<Value = Fp> {
    prop_oneof![
        Just(Fp::ZERO),
        Just(Fp::ONE),
        Just(-Fp::ONE),
        Just(Fp::ONE.double()),
        (0u64..1000).prop_map(Fp::from),
        arb_fe(),
    ]
}

fn arb_zero_product_pair() -> impl Strategy<Value = (Fp, Fp)> {
    prop_oneof![
        arb_fe_with_edges().prop_map(|b| (Fp::ZERO, b)),
        arb_fe_with_edges().prop_map(|a| (a, Fp::ZERO)),
        Just((Fp::ZERO, Fp::ZERO)),
    ]
}

/// Allocates N zero-product gates, summing their d-wires.
struct AllZeroProductCircuit {
    num_gates: usize,
}

impl Circuit<Fp> for AllZeroProductCircuit {
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
        let mut sum = Element::zero(dr);
        for _ in 0..self.num_gates {
            let (_a, _b, d) = Element::alloc_zero_product(
                dr,
                D::just(|| Fp::ONE),
                D::just(|| Fp::ZERO),
                witness.as_ref().map(|v| *v),
            )?;
            sum = sum.add(dr, &d);
        }
        Ok((sum, D::unit()))
    }
}

/// Single zero-product gate parameterized by (a, b, d). Output = a + d.
struct SingleZPCircuit;

impl Circuit<Fp> for SingleZPCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witnesses> = (Fp, Fp, Fp);
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
        let (a, _b, d) = Element::alloc_zero_product(
            dr,
            witness.as_ref().map(|w| w.0),
            witness.as_ref().map(|w| w.1),
            witness.as_ref().map(|w| w.2),
        )?;
        Ok((a.add(dr, &d), D::unit()))
    }
}

/// Interleaves alloc and zero_product_mul. Output = x1 + x2 + a + d + 1.
struct MixedAllocCircuit;

impl Circuit<Fp> for MixedAllocCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witnesses> = (Fp, Fp, Fp, Fp);
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
        let x1 = Element::alloc(dr, witness.as_ref().map(|w| w.0))?;
        let x2 = Element::alloc(dr, witness.as_ref().map(|w| w.1))?;
        let (a, _b, d) = Element::alloc_zero_product(
            dr,
            witness.as_ref().map(|w| w.2),
            D::just(|| Fp::ZERO),
            witness.as_ref().map(|w| w.3),
        )?;
        let x3 = Element::alloc(dr, D::just(|| Fp::from(1u64)))?;

        let sum = x1.add(dr, &x2);
        let sum = sum.add(dr, &a);
        let sum = sum.add(dr, &d);
        let sum = sum.add(dr, &x3);

        Ok((sum, D::unit()))
    }
}

/// Calls zero_product_mul with a*b != 0 (a=3, b=5, d=99). Output = a + d.
struct BadWitnessCircuit;

impl Circuit<Fp> for BadWitnessCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witnesses> = ();
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
        _witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<(
        Bound<'dr, D, Self::Output>,
        DriverValue<D, Self::Aux<'witness>>,
    )> {
        let (a, _b, d) = Element::alloc_zero_product(
            dr,
            D::just(|| Fp::from(3u64)),
            D::just(|| Fp::from(5u64)),
            D::just(|| Fp::from(99u64)),
        )?;
        Ok((a.add(dr, &d), D::unit()))
    }
}

/// Allocates a ZP gate then enforces a == d. Output = a.
struct DWireEnforceCircuit;

impl Circuit<Fp> for DWireEnforceCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witnesses> = (Fp, Fp);
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
        let a_val = witness.as_ref().map(|w| w.0);
        let d_val = witness.as_ref().map(|w| w.1);
        let (a, _b, d) = Element::alloc_zero_product(dr, a_val, D::just(|| Fp::ZERO), d_val)?;
        dr.enforce_equal(a.wire(), d.wire())?;
        Ok((a, D::unit()))
    }
}

/// ZP gate followed by d * x. Output = d * x.
struct DWireMulCircuit;

impl Circuit<Fp> for DWireMulCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witnesses> = (Fp, Fp, Fp);
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
        let (_a, _b, d) = Element::alloc_zero_product(
            dr,
            witness.as_ref().map(|w| w.0),
            D::just(|| Fp::ZERO),
            witness.as_ref().map(|w| w.1),
        )?;
        let x = Element::alloc(dr, witness.as_ref().map(|w| w.2))?;
        Ok((d.mul(dr, &x)?, D::unit()))
    }
}

/// Single alloc then ZP gate. Output = x + d.
struct AllocThenZPCircuit;

impl Circuit<Fp> for AllocThenZPCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witnesses> = (Fp, Fp, Fp);
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
        let x = Element::alloc(dr, witness.as_ref().map(|w| w.0))?;
        let (_a, _b, d) = Element::alloc_zero_product(
            dr,
            witness.as_ref().map(|w| w.1),
            D::just(|| Fp::ZERO),
            witness.as_ref().map(|w| w.2),
        )?;
        Ok((x.add(dr, &d), D::unit()))
    }
}

/// ZP gate then alloc. Output = a + d + x.
struct ZPThenAllocCircuit;

impl Circuit<Fp> for ZPThenAllocCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witnesses> = (Fp, Fp, Fp);
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
        let (a, _b, d) = Element::alloc_zero_product(
            dr,
            witness.as_ref().map(|w| w.0),
            D::just(|| Fp::ZERO),
            witness.as_ref().map(|w| w.1),
        )?;
        let x = Element::alloc(dr, witness.as_ref().map(|w| w.2))?;
        Ok((a.add(dr, &d).add(dr, &x), D::unit()))
    }
}

/// Five consecutive ZP gates with d_i = i*10. Output = sum(d_i).
struct ConsecutiveZPCircuit;

impl Circuit<Fp> for ConsecutiveZPCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witnesses> = ();
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
        _witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<(
        Bound<'dr, D, Self::Output>,
        DriverValue<D, Self::Aux<'witness>>,
    )> {
        let mut sum = Element::zero(dr);
        for i in 0..5u64 {
            let (_a, _b, d) = Element::alloc_zero_product(
                dr,
                D::just(move || Fp::from(i)),
                D::just(|| Fp::ZERO),
                D::just(move || Fp::from(i * 10)),
            )?;
            sum = sum.add(dr, &d);
        }
        Ok((sum, D::unit()))
    }
}

/// Regular mul then ZP gate. Output = x1^2 + d.
struct MixedMulZPCircuit;

impl Circuit<Fp> for MixedMulZPCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witnesses> = (Fp, Fp, Fp);
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
        let x1 = Element::alloc(dr, witness.as_ref().map(|w| w.0))?;
        let x1_sq = x1.square(dr)?;
        let (_a, _b, d) = Element::alloc_zero_product(
            dr,
            witness.as_ref().map(|w| w.1),
            D::just(|| Fp::ZERO),
            witness.as_ref().map(|w| w.2),
        )?;
        Ok((x1_sq.add(dr, &d), D::unit()))
    }
}

/// ZP gate inside a routine: a=input, b=0, d=aux. Enforces a == input.
#[derive(Clone)]
struct ZeroProductRoutine;

impl Routine<Fp> for ZeroProductRoutine {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = Fp;

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (a, _b, d) =
            Element::alloc_zero_product(dr, input.value().map(|v| *v), D::just(|| Fp::ZERO), aux)?;
        dr.enforce_equal(a.wire(), input.wire())?;
        Ok(a.add(dr, &d))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| Fp::from(100u64))))
    }
}

/// Wraps ZeroProductRoutine in a circuit.
struct ZeroProductRoutineCircuit;

impl Circuit<Fp> for ZeroProductRoutineCircuit {
    type Instance<'instance> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'witnesses> = (Fp, Fp);
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
        let input = Element::alloc(dr, witness.as_ref().map(|w| w.0))?;
        let result = dr.routine(ZeroProductRoutine, input)?;
        Ok((result, D::unit()))
    }
}

/// Regular mul routine for fingerprint comparison.
#[derive(Clone)]
struct MulRoutine;

impl Routine<Fp> for MulRoutine {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let x = Element::alloc(dr, D::just(|| Fp::from(2u64)))?;
        input.mul(dr, &x)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// ZP routine for fingerprint comparison.
#[derive(Clone)]
struct ZPRoutine;

impl Routine<Fp> for ZPRoutine {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (_a, _b, d) = Element::alloc_zero_product(
            dr,
            D::just(|| Fp::from(2u64)),
            D::just(|| Fp::ZERO),
            D::just(|| Fp::from(3u64)),
        )?;
        Ok(d)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// ZP routine with input-dependent a-wire, for determinism testing.
#[derive(Clone)]
struct ZPRoutine2;

impl Routine<Fp> for ZPRoutine2 {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (_a, _b, d) = Element::alloc_zero_product(
            dr,
            input.value().map(|v| *v),
            D::just(|| Fp::ZERO),
            D::just(|| Fp::from(42u64)),
        )?;
        Ok(d)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

fn full_check<C: Circuit<Fp, Instance<'static> = Fp>>(
    circuit_for_rx: &C,
    circuit_for_obj: C,
    witness: C::Witness<'_>,
    expected_instance: Fp,
) {
    let (trace, _) = circuit_for_rx.rx(witness).unwrap();
    let assignment = trace.assemble_trivial::<MyRank>().unwrap();

    let circuit = circuit_for_obj.into_object::<MyRank>().unwrap();
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

    let a = a.unstructured();
    let b = b.unstructured();

    let expected = C::ky(&circuit_for_rx, expected_instance, y).unwrap();
    assert_eq!(expected, ragu_arithmetic::dot(a.iter(), b.iter().rev()));
}

proptest! {
    /// Simulator rejects witnesses where a*b != 0.
    #[test]
    fn adversarial_nonzero_product_rejected(
        a_val in arb_fe().prop_filter("a must be nonzero", |v| *v != Fp::ZERO),
        b_val in arb_fe().prop_filter("b must be nonzero", |v| *v != Fp::ZERO),
        d_val in arb_fe(),
    ) {
        let result = Simulator::<Fp>::simulate((a_val, b_val, d_val), |dr, witness| {
            let (a, b, d) = witness.cast();
            Element::alloc_zero_product(dr, a, b, d)?;
            Ok(())
        });
        prop_assert!(result.is_err(), "a*b != 0 must be rejected by Simulator");
    }

    /// Coeff::One * Coeff::One = 1 != 0 is rejected.
    #[test]
    fn adversarial_coeff_one_one_rejected(d_val in arb_fe()) {
        let mut sim = Simulator::<Fp>::new();
        let result = sim.zero_product_mul(|| {
            Ok((Coeff::One, Coeff::One, Coeff::Arbitrary(d_val)))
        });
        prop_assert!(result.is_err());
    }

    /// Coeff::NegativeOne * Coeff::One = -1 != 0 is rejected.
    #[test]
    fn adversarial_neg_one_times_one_rejected(d_val in arb_fe()) {
        let mut sim = Simulator::<Fp>::new();
        let result = sim.zero_product_mul(|| {
            Ok((Coeff::NegativeOne, Coeff::One, Coeff::Arbitrary(d_val)))
        });
        prop_assert!(result.is_err());
    }

    /// rx always sets c=0 for zero_product_mul regardless of the a*b product.
    #[test]
    fn adversarial_rx_always_sets_c_zero(_dummy in Just(())) {
        use crate::rx;

        let (trace, _) = rx::eval(&BadWitnessCircuit, ()).unwrap();
        let seg = &trace.segments[0];
        prop_assert_eq!(seg.c[1], Fp::ZERO);
        prop_assert_eq!(seg.d[1], Fp::from(99u64));
        prop_assert_eq!(seg.a[1], Fp::from(3u64));
        prop_assert_eq!(seg.b[1], Fp::from(5u64));
    }

    /// SingleZPCircuit satisfies the revdot identity for valid zero-product pairs.
    #[test]
    fn boundary_single_zp(
        (a_val, b_val) in arb_zero_product_pair(),
        d_val in arb_fe_with_edges(),
    ) {
        full_check(
            &SingleZPCircuit,
            SingleZPCircuit,
            (a_val, b_val, d_val),
            a_val + d_val,
        );
    }

    /// AllZeroProductCircuit with variable gate count satisfies the revdot identity.
    #[test]
    fn boundary_all_zp_variable_count(
        num_gates in 1usize..15,
        d_val in arb_fe_with_edges(),
    ) {
        full_check(
            &AllZeroProductCircuit { num_gates },
            AllZeroProductCircuit { num_gates },
            d_val,
            d_val * Fp::from(num_gates as u64),
        );
    }

    /// 20 ZP gates (near TestRank capacity of 32) satisfies the revdot identity.
    #[test]
    fn boundary_many_zero_product_gates(d_val in arb_fe_with_edges()) {
        let num_gates = 20;
        full_check(
            &AllZeroProductCircuit { num_gates },
            AllZeroProductCircuit { num_gates },
            d_val,
            d_val * Fp::from(num_gates as u64),
        );
    }

    /// Interleaved alloc and ZP satisfies the revdot identity.
    #[test]
    fn boundary_mixed_alloc(
        x1 in arb_fe_with_edges(),
        x2 in arb_fe_with_edges(),
        a in arb_fe_with_edges(),
        d in arb_fe_with_edges(),
    ) {
        full_check(
            &MixedAllocCircuit,
            MixedAllocCircuit,
            (x1, x2, a, d),
            x1 + x2 + a + d + Fp::from(1u64),
        );
    }

    /// Simulator accepts valid zero-product witnesses.
    #[test]
    fn domain_simulator_accepts_valid_zp(
        (a_val, b_val) in arb_zero_product_pair(),
        d_val in arb_fe_with_edges(),
    ) {
        let result = Simulator::<Fp>::simulate((a_val, b_val, d_val), |dr, witness| {
            let (a, b, d) = witness.cast();
            Element::alloc_zero_product(dr, a, b, d)?;
            Ok(())
        });
        prop_assert!(result.is_ok());
    }

    /// All-zero witness (a=0, b=0, d=0) is accepted and wires read back as zero.
    #[test]
    fn domain_zero_witness(_dummy in Just(())) {
        let sim = Simulator::<Fp>::simulate((), |dr, _witness| {
            let (a, b, d) = Element::alloc_zero_product(
                dr,
                Simulator::<Fp>::just(|| Fp::ZERO),
                Simulator::<Fp>::just(|| Fp::ZERO),
                Simulator::<Fp>::just(|| Fp::ZERO),
            )?;
            assert_eq!(*a.value().take(), Fp::ZERO);
            assert_eq!(*b.value().take(), Fp::ZERO);
            assert_eq!(*d.value().take(), Fp::ZERO);
            Ok(())
        });
        prop_assert!(sim.is_ok());
    }

    /// Each zero_product_mul call counts as exactly one multiplication gate.
    #[test]
    fn domain_simulator_counts(n in 1usize..10) {
        let sim = Simulator::<Fp>::simulate((), |dr, _| {
            for _ in 0..n {
                Element::alloc_zero_product(
                    dr,
                    Simulator::<Fp>::just(|| Fp::ZERO),
                    Simulator::<Fp>::just(|| Fp::ZERO),
                    Simulator::<Fp>::just(|| Fp::from(1u64)),
                )?;
            }
            Ok(())
        })
        .unwrap();

        prop_assert_eq!(sim.num_multiplications(), n);
        prop_assert_eq!(sim.num_allocations(), 0);
        prop_assert_eq!(sim.num_linear_constraints(), 0);
    }

    /// Coeff::Zero a/b with various Coeff types for d all resolve correctly.
    #[test]
    fn domain_coeff_zero_variants(d_val in arb_fe_with_edges()) {
        let mut sim = Simulator::<Fp>::new();

        let (a, b, d) = sim
            .zero_product_mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Arbitrary(d_val))))
            .unwrap();
        prop_assert_eq!(a, Fp::ZERO);
        prop_assert_eq!(b, Fp::ZERO);
        prop_assert_eq!(d, d_val);

        let (a, b, d) = sim
            .zero_product_mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))
            .unwrap();
        prop_assert_eq!(a, Fp::ZERO);
        prop_assert_eq!(b, Fp::ZERO);
        prop_assert_eq!(d, Fp::ZERO);

        let (a, b, d) = sim
            .zero_product_mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::One)))
            .unwrap();
        prop_assert_eq!(a, Fp::ZERO);
        prop_assert_eq!(b, Fp::ZERO);
        prop_assert_eq!(d, Fp::ONE);

        let (a, b, d) = sim
            .zero_product_mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::NegativeOne)))
            .unwrap();
        prop_assert_eq!(a, Fp::ZERO);
        prop_assert_eq!(b, Fp::ZERO);
        prop_assert_eq!(d, -Fp::ONE);
    }

    /// Metrics eval and rx eval agree on gate counts for ZP circuits.
    #[test]
    fn domain_metrics_rx_segment_agreement(
        (a_val, b_val) in arb_zero_product_pair(),
        d_val in arb_fe_with_edges(),
    ) {
        let circuit = SingleZPCircuit;
        let metrics = metrics::eval(&circuit).unwrap();
        let (trace, _) = circuit.rx((a_val, b_val, d_val)).unwrap();

        prop_assert_eq!(
            metrics.segments[0].num_multiplication_constraints,
            trace.segments[0].a.len(),
        );
    }

    /// zero_product_mul counts as a multiplication constraint in metrics.
    #[test]
    fn domain_zp_counted_as_mul(_dummy in Just(())) {
        let metrics = metrics::eval(&SingleZPCircuit).unwrap();
        prop_assert_eq!(metrics.num_multiplication_constraints, 2);
    }

    /// c-wire is zero and a/b/d hold expected values at ZP gates in rx trace.
    #[test]
    fn domain_rx_trace_c_zero_d_populated(
        a_val in arb_fe_with_edges(),
        d_val in arb_fe_with_edges(),
    ) {
        let (trace, _) = SingleZPCircuit.rx((a_val, Fp::ZERO, d_val)).unwrap();
        let seg = &trace.segments[0];

        prop_assert_eq!(seg.c[1], Fp::ZERO);
        prop_assert_eq!(seg.d[1], d_val);
        prop_assert_eq!(seg.a[1], a_val);
        prop_assert_eq!(seg.b[1], Fp::ZERO);
    }

    /// Forward c (w in storage) is zero at ZP gates, so tz contribution vanishes.
    #[test]
    fn domain_tz_vanishes_at_zp_gates(
        a_val in arb_fe_with_edges(),
        d_val in arb_fe_with_edges(),
    ) {
        let (trace, _) = SingleZPCircuit.rx((a_val, Fp::ZERO, d_val)).unwrap();
        let mut assignment = trace.assemble_trivial::<MyRank>().unwrap();
        let fw = assignment.forward();
        prop_assert_eq!(fw.c[1], Fp::ZERO);
    }

    /// d-wire participates correctly in enforce_equal constraints.
    #[test]
    fn domain_d_wire_in_enforce_zero(val in arb_fe_with_edges()) {
        let sim = Simulator::<Fp>::simulate((val, val), |dr, witness| {
            let (a, d) = witness.cast();
            let (ae, _be, de) =
                Element::alloc_zero_product(dr, a, Simulator::<Fp>::just(|| Fp::ZERO), d)?;
            dr.enforce_equal(ae.wire(), de.wire())?;
            Ok(())
        });
        prop_assert!(sim.is_ok());

        let other = val + Fp::ONE;
        if val != other {
            let sim = Simulator::<Fp>::simulate((val, other), |dr, witness| {
                let (a, d) = witness.cast();
                let (ae, _be, de) =
                    Element::alloc_zero_product(dr, a, Simulator::<Fp>::just(|| Fp::ZERO), d)?;
                dr.enforce_equal(ae.wire(), de.wire())?;
                Ok(())
            });
            prop_assert!(sim.is_err());
        }

        let (trace, _) = DWireEnforceCircuit.rx((val, val)).unwrap();
        let assignment = trace.assemble_trivial::<MyRank>().unwrap();
        let circuit = DWireEnforceCircuit.into_object::<MyRank>().unwrap();
        consistency_checks(&*circuit);

        let y = Fp::random(&mut rand::rng());
        let z = Fp::random(&mut rand::rng());
        let k = registry::Key::default();
        let floor_plan = crate::floor_planner::floor_plan(circuit.segment_records());

        let rx = assignment.clone();
        let mut b = assignment.clone();
        b.dilate(z);
        b.add_assign(&circuit.sy(y, &k, &floor_plan));
        b.add_assign(&MyRank::tz(z));

        let expected = DWireEnforceCircuit.ky(val, y).unwrap();
        let rx_u = rx.unstructured();
        let b_u = b.unstructured();
        prop_assert_eq!(
            expected,
            ragu_arithmetic::dot(rx_u.iter(), b_u.iter().rev())
        );
    }

    /// d-wire element can be multiplied with another element.
    #[test]
    fn domain_d_wire_as_mul_input(
        d_val in arb_fe_with_edges(),
        x_val in arb_fe_with_edges(),
    ) {
        let a_val = Fp::from(5u64);

        let sim = Simulator::<Fp>::simulate((a_val, d_val, x_val), |dr, witness| {
            let (a_v, d_v, x_v) = witness.cast();
            let (_ae, _be, de) =
                Element::alloc_zero_product(dr, a_v, Simulator::<Fp>::just(|| Fp::ZERO), d_v)?;
            let xe = Element::alloc(dr, x_v)?;
            let product = de.mul(dr, &xe)?;
            assert_eq!(*product.value().take(), d_val * x_val);
            Ok(())
        });
        prop_assert!(sim.is_ok());

        full_check(
            &DWireMulCircuit,
            DWireMulCircuit,
            (a_val, d_val, x_val),
            d_val * x_val,
        );
    }

    /// Pending b-wire from alloc is flushed before the ZP gate starts.
    #[test]
    fn domain_alloc_then_zp_flush(
        x in arb_fe_with_edges(),
        a in arb_fe_with_edges(),
        d in arb_fe_with_edges(),
    ) {
        full_check(
            &AllocThenZPCircuit,
            AllocThenZPCircuit,
            (x, a, d),
            x + d,
        );
    }

    /// Alloc after ZP starts a new gate correctly.
    #[test]
    fn domain_zp_then_alloc(
        a in arb_fe_with_edges(),
        d in arb_fe_with_edges(),
        x in arb_fe_with_edges(),
    ) {
        full_check(
            &ZPThenAllocCircuit,
            ZPThenAllocCircuit,
            (a, d, x),
            a + d + x,
        );
    }

    /// Five consecutive ZP gates satisfy the revdot identity.
    #[test]
    fn domain_consecutive_zp_gates(_dummy in Just(())) {
        let expected_sum = Fp::from(0u64)
            + Fp::from(10u64)
            + Fp::from(20u64)
            + Fp::from(30u64)
            + Fp::from(40u64);

        let (trace, _) = ConsecutiveZPCircuit.rx(()).unwrap();
        let assignment = trace.assemble_trivial::<MyRank>().unwrap();
        let circuit = ConsecutiveZPCircuit.into_object::<MyRank>().unwrap();
        consistency_checks(&*circuit);

        let y = Fp::random(&mut rand::rng());
        let z = Fp::random(&mut rand::rng());
        let k = registry::Key::default();
        let floor_plan = crate::floor_planner::floor_plan(circuit.segment_records());

        let rx = assignment.clone();
        let mut b = assignment.clone();
        b.dilate(z);
        b.add_assign(&circuit.sy(y, &k, &floor_plan));
        b.add_assign(&MyRank::tz(z));

        let expected = ConsecutiveZPCircuit.ky(expected_sum, y).unwrap();
        let rx_u = rx.unstructured();
        let b_u = b.unstructured();
        prop_assert_eq!(
            expected,
            ragu_arithmetic::dot(rx_u.iter(), b_u.iter().rev())
        );
    }

    /// ZP inside a routine boundary satisfies the revdot identity.
    #[test]
    fn domain_zp_routine(input_val in arb_fe_with_edges()) {
        let d_val = Fp::from(100u64);
        full_check(
            &ZeroProductRoutineCircuit,
            ZeroProductRoutineCircuit,
            (input_val, d_val),
            input_val + d_val,
        );
    }

    /// Circuit mixing regular mul and ZP satisfies the revdot identity.
    #[test]
    fn domain_mixed_mul_zp_revdot(
        x1 in arb_fe_with_edges(),
        x3 in arb_fe_with_edges(),
    ) {
        full_check(
            &MixedMulZPCircuit,
            MixedMulZPCircuit,
            (x1, Fp::ZERO, x3),
            x1.square() + x3,
        );
    }

    /// Structured revdot agrees with unstructured dot for ZP circuits.
    #[test]
    fn domain_structured_vs_unstructured_revdot(
        a_val in arb_fe_with_edges(),
        d_val in arb_fe_with_edges(),
    ) {
        let (trace, _) = SingleZPCircuit
            .rx((a_val, Fp::ZERO, d_val))
            .unwrap();
        let assignment = trace.assemble_trivial::<MyRank>().unwrap();
        let circuit = SingleZPCircuit.into_object::<MyRank>().unwrap();

        let y = Fp::random(&mut rand::rng());
        let z = Fp::random(&mut rand::rng());
        let k = registry::Key::default();
        let floor_plan = crate::floor_planner::floor_plan(circuit.segment_records());

        let rx = assignment.clone();
        let mut b = assignment.clone();
        b.dilate(z);
        b.add_assign(&circuit.sy(y, &k, &floor_plan));
        b.add_assign(&MyRank::tz(z));

        let structured_result = rx.revdot(&b);
        let rx_u = rx.unstructured();
        let b_u = b.unstructured();
        prop_assert_eq!(structured_result, ragu_arithmetic::dot(rx_u.iter(), b_u.iter().rev()));
    }

    /// Mul routine and ZP routine produce different fingerprints.
    #[test]
    fn domain_fingerprint_mul_vs_zp(_dummy in Just(())) {
        use crate::metrics::tests::fingerprint_routine;

        let mut sim = Simulator::<Fp>::new();
        let input = Element::alloc(&mut sim, Always::<Fp>::just(|| Fp::from(1u64))).unwrap();

        let fp_mul = fingerprint_routine(&MulRoutine, &input).unwrap();
        let fp_zp = fingerprint_routine(&ZPRoutine, &input).unwrap();

        let mul_fp = match fp_mul {
            RoutineIdentity::Routine(fp) => fp,
            _ => panic!("expected Routine identity"),
        };
        let zp_fp = match fp_zp {
            RoutineIdentity::Routine(fp) => fp,
            _ => panic!("expected Routine identity"),
        };

        prop_assert_ne!(mul_fp.eval(), zp_fp.eval());
    }

    /// Same ZP routine fingerprinted twice produces identical results.
    #[test]
    fn domain_fingerprint_determinism(_dummy in Just(())) {
        use crate::metrics::tests::fingerprint_routine;

        let mut sim = Simulator::<Fp>::new();
        let input = Element::alloc(&mut sim, Always::<Fp>::just(|| Fp::from(1u64))).unwrap();

        let fp1 = fingerprint_routine(&ZPRoutine2, &input).unwrap();
        let fp2 = fingerprint_routine(&ZPRoutine2, &input).unwrap();

        let eval1 = match fp1 {
            RoutineIdentity::Routine(fp) => fp.eval(),
            _ => panic!("expected Routine"),
        };
        let eval2 = match fp2 {
            RoutineIdentity::Routine(fp) => fp.eval(),
            _ => panic!("expected Routine"),
        };
        prop_assert_eq!(eval1, eval2);
    }
}
