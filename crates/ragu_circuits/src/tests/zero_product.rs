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

/// Allocates N d-wire gates, summing their b-values.
struct AllDAllocCircuit {
    num_gates: usize,
}

impl Circuit<Fp> for AllDAllocCircuit {
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
            let (_a, b) = Element::dual_alloc(
                dr,
                D::just(|| Fp::ONE),
                witness.as_ref().map(|v| *v),
            )?;
            sum = sum.add(dr, &b);
        }
        Ok((sum, D::unit()))
    }
}

/// Single d-wire allocation gate parameterized by (a, b). Output = a + b.
struct SingleDAllocCircuit;

impl Circuit<Fp> for SingleDAllocCircuit {
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
        let (a, b) = Element::dual_alloc(
            dr,
            witness.as_ref().map(|w| w.0),
            witness.as_ref().map(|w| w.1),
        )?;
        Ok((a.add(dr, &b), D::unit()))
    }
}

/// Interleaves alloc and dual_alloc. Output = x1 + x2 + a + b + 1.
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
        let (a, b) = Element::dual_alloc(
            dr,
            witness.as_ref().map(|w| w.2),
            witness.as_ref().map(|w| w.3),
        )?;
        let x3 = Element::alloc(dr, D::just(|| Fp::from(1u64)))?;

        let sum = x1.add(dr, &x2);
        let sum = sum.add(dr, &a);
        let sum = sum.add(dr, &b);
        let sum = sum.add(dr, &x3);

        Ok((sum, D::unit()))
    }
}

/// Allocates a d-wire gate then enforces a == b. Output = a.
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
        let b_val = witness.as_ref().map(|w| w.1);
        let (a, b) = Element::dual_alloc(dr, a_val, b_val)?;
        dr.enforce_equal(a.wire(), b.wire())?;
        Ok((a, D::unit()))
    }
}

/// d-wire gate followed by b * x. Output = b * x.
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
        let (_a, b) = Element::dual_alloc(
            dr,
            witness.as_ref().map(|w| w.0),
            witness.as_ref().map(|w| w.1),
        )?;
        let x = Element::alloc(dr, witness.as_ref().map(|w| w.2))?;
        Ok((b.mul(dr, &x)?, D::unit()))
    }
}

/// Single alloc then d-wire gate. Output = x + b.
struct AllocThenDAllocCircuit;

impl Circuit<Fp> for AllocThenDAllocCircuit {
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
        let (_a, b) = Element::dual_alloc(
            dr,
            witness.as_ref().map(|w| w.1),
            witness.as_ref().map(|w| w.2),
        )?;
        Ok((x.add(dr, &b), D::unit()))
    }
}

/// d-wire gate then alloc. Output = a + b + x.
struct DAllocThenAllocCircuit;

impl Circuit<Fp> for DAllocThenAllocCircuit {
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
        let (a, b) = Element::dual_alloc(
            dr,
            witness.as_ref().map(|w| w.0),
            witness.as_ref().map(|w| w.1),
        )?;
        let x = Element::alloc(dr, witness.as_ref().map(|w| w.2))?;
        Ok((a.add(dr, &b).add(dr, &x), D::unit()))
    }
}

/// Five consecutive d-wire gates with b_i = i*10. Output = sum(b_i).
struct ConsecutiveDAllocCircuit;

impl Circuit<Fp> for ConsecutiveDAllocCircuit {
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
            let (_a, b) = Element::dual_alloc(
                dr,
                D::just(move || Fp::from(i)),
                D::just(move || Fp::from(i * 10)),
            )?;
            sum = sum.add(dr, &b);
        }
        Ok((sum, D::unit()))
    }
}

/// Regular mul then d-wire gate. Output = x1^2 + b.
struct MixedMulDAllocCircuit;

impl Circuit<Fp> for MixedMulDAllocCircuit {
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
        let (_a, b) = Element::dual_alloc(
            dr,
            witness.as_ref().map(|w| w.1),
            witness.as_ref().map(|w| w.2),
        )?;
        Ok((x1_sq.add(dr, &b), D::unit()))
    }
}

/// d-wire gate inside a routine: a=input, b=aux. Enforces a == input.
#[derive(Clone)]
struct DAllocRoutine;

impl Routine<Fp> for DAllocRoutine {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = Fp;

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (a, b) = Element::dual_alloc(dr, input.value().map(|v| *v), aux)?;
        dr.enforce_equal(a.wire(), input.wire())?;
        Ok(a.add(dr, &b))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| Fp::from(100u64))))
    }
}

/// Wraps DAllocRoutine in a circuit.
struct DAllocRoutineCircuit;

impl Circuit<Fp> for DAllocRoutineCircuit {
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
        let result = dr.routine(DAllocRoutine, input)?;
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

/// d-wire routine for fingerprint comparison.
#[derive(Clone)]
struct DAllocRoutineFP;

impl Routine<Fp> for DAllocRoutineFP {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (_a, b) = Element::dual_alloc(
            dr,
            D::just(|| Fp::from(2u64)),
            D::just(|| Fp::from(3u64)),
        )?;
        Ok(b)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// d-wire routine with input-dependent a-value, for determinism testing.
#[derive(Clone)]
struct DAllocRoutineFP2;

impl Routine<Fp> for DAllocRoutineFP2 {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (_a, b) = Element::dual_alloc(
            dr,
            input.value().map(|v| *v),
            D::just(|| Fp::from(42u64)),
        )?;
        Ok(b)
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

    let rx = assignment.clone();
    let mut sy = assignment.clone();
    sy.dilate(z);
    sy.add_assign(&circuit.sy(y, &k, &floor_plan));
    sy.add_assign(&MyRank::tz(z));

    let rx = rx.unstructured();
    let sy = sy.unstructured();

    let expected = C::ky(circuit_for_rx, expected_instance, y).unwrap();
    assert_eq!(expected, ragu_arithmetic::dot(rx.iter(), sy.iter().rev()));
}

proptest! {
    /// rx always sets wire positions 0 and 2 to zero for dual_alloc gates.
    #[test]
    fn structural_rx_zeros(
        a_val in arb_fe_with_edges(),
        b_val in arb_fe_with_edges(),
    ) {
        let (trace, _) = SingleDAllocCircuit.rx((a_val, b_val)).unwrap();
        let seg = &trace.segments[0];

        // Gate 0 is the instance alloc; gate 1 is the dual_alloc gate.
        prop_assert_eq!(seg.a[1], Fp::ZERO);
        prop_assert_eq!(seg.c[1], Fp::ZERO);
        prop_assert_eq!(seg.b[1], a_val);
        prop_assert_eq!(seg.d[1], b_val);
    }

    /// SingleDAllocCircuit satisfies the revdot identity.
    #[test]
    fn boundary_single_d_alloc(
        a_val in arb_fe_with_edges(),
        b_val in arb_fe_with_edges(),
    ) {
        full_check(
            &SingleDAllocCircuit,
            SingleDAllocCircuit,
            (a_val, b_val),
            a_val + b_val,
        );
    }

    /// AllDAllocCircuit with variable gate count satisfies the revdot identity.
    #[test]
    fn boundary_all_d_alloc_variable_count(
        num_gates in 1usize..15,
        b_val in arb_fe_with_edges(),
    ) {
        full_check(
            &AllDAllocCircuit { num_gates },
            AllDAllocCircuit { num_gates },
            b_val,
            b_val * Fp::from(num_gates as u64),
        );
    }

    /// 20 d-wire gates (near TestRank capacity of 32) satisfies the revdot identity.
    #[test]
    fn boundary_many_d_alloc_gates(b_val in arb_fe_with_edges()) {
        let num_gates = 20;
        full_check(
            &AllDAllocCircuit { num_gates },
            AllDAllocCircuit { num_gates },
            b_val,
            b_val * Fp::from(num_gates as u64),
        );
    }

    /// Interleaved alloc and dual_alloc satisfies the revdot identity.
    #[test]
    fn boundary_mixed_alloc(
        x1 in arb_fe_with_edges(),
        x2 in arb_fe_with_edges(),
        a in arb_fe_with_edges(),
        b in arb_fe_with_edges(),
    ) {
        full_check(
            &MixedAllocCircuit,
            MixedAllocCircuit,
            (x1, x2, a, b),
            x1 + x2 + a + b + Fp::from(1u64),
        );
    }

    /// Simulator accepts any values for dual_alloc (no constraint to violate).
    #[test]
    fn domain_simulator_accepts_dual_alloc(
        a_val in arb_fe_with_edges(),
        b_val in arb_fe_with_edges(),
    ) {
        let result = Simulator::<Fp>::simulate((a_val, b_val), |dr, witness| {
            let (a, b) = witness.cast();
            Element::dual_alloc(dr, a, b)?;
            Ok(())
        });
        prop_assert!(result.is_ok());
    }

    /// All-zero witness (a=0, b=0) is accepted and wires read back as zero.
    #[test]
    fn domain_zero_witness(_dummy in Just(())) {
        let sim = Simulator::<Fp>::simulate((), |dr, _witness| {
            let (a, b) = Element::dual_alloc(
                dr,
                Simulator::<Fp>::just(|| Fp::ZERO),
                Simulator::<Fp>::just(|| Fp::ZERO),
            )?;
            assert_eq!(*a.value().take(), Fp::ZERO);
            assert_eq!(*b.value().take(), Fp::ZERO);
            Ok(())
        });
        prop_assert!(sim.is_ok());
    }

    /// Each dual_alloc call counts as exactly one multiplication gate.
    #[test]
    fn domain_simulator_counts(n in 1usize..10) {
        let sim = Simulator::<Fp>::simulate((), |dr, _| {
            for _ in 0..n {
                Element::dual_alloc(
                    dr,
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

    /// Coeff variants for a and b all resolve correctly.
    #[test]
    fn domain_coeff_variants(b_val in arb_fe_with_edges()) {
        let mut sim = Simulator::<Fp>::new();

        let (a, b) = sim
            .dual_alloc(|| Ok((Coeff::Zero, Coeff::Arbitrary(b_val))))
            .unwrap();
        prop_assert_eq!(a, Fp::ZERO);
        prop_assert_eq!(b, b_val);

        let (a, b) = sim
            .dual_alloc(|| Ok((Coeff::Zero, Coeff::Zero)))
            .unwrap();
        prop_assert_eq!(a, Fp::ZERO);
        prop_assert_eq!(b, Fp::ZERO);

        let (a, b) = sim
            .dual_alloc(|| Ok((Coeff::Zero, Coeff::One)))
            .unwrap();
        prop_assert_eq!(a, Fp::ZERO);
        prop_assert_eq!(b, Fp::ONE);

        let (a, b) = sim
            .dual_alloc(|| Ok((Coeff::Zero, Coeff::NegativeOne)))
            .unwrap();
        prop_assert_eq!(a, Fp::ZERO);
        prop_assert_eq!(b, -Fp::ONE);
    }

    /// Metrics eval and rx eval agree on gate counts for d-wire circuits.
    #[test]
    fn domain_metrics_rx_segment_agreement(
        a_val in arb_fe_with_edges(),
        b_val in arb_fe_with_edges(),
    ) {
        let circuit = SingleDAllocCircuit;
        let metrics = metrics::eval(&circuit).unwrap();
        let (trace, _) = circuit.rx((a_val, b_val)).unwrap();

        prop_assert_eq!(
            metrics.segments[0].num_multiplication_constraints,
            trace.segments[0].a.len(),
        );
    }

    /// dual_alloc counts as a multiplication constraint in metrics.
    #[test]
    fn domain_d_alloc_counted_as_mul(_dummy in Just(())) {
        let metrics = metrics::eval(&SingleDAllocCircuit).unwrap();
        prop_assert_eq!(metrics.num_multiplication_constraints, 2);
    }

    /// Wire positions 0 and 2 are zero; a and b hold expected values at dual_alloc gates.
    #[test]
    fn domain_rx_trace_layout(
        a_val in arb_fe_with_edges(),
        b_val in arb_fe_with_edges(),
    ) {
        let (trace, _) = SingleDAllocCircuit.rx((a_val, b_val)).unwrap();
        let seg = &trace.segments[0];

        prop_assert_eq!(seg.a[1], Fp::ZERO);
        prop_assert_eq!(seg.c[1], Fp::ZERO);
        prop_assert_eq!(seg.b[1], a_val);
        prop_assert_eq!(seg.d[1], b_val);
    }

    /// Forward c (w in storage) is zero at dual_alloc gates, so tz contribution vanishes.
    #[test]
    fn domain_tz_vanishes_at_d_alloc_gates(
        a_val in arb_fe_with_edges(),
        b_val in arb_fe_with_edges(),
    ) {
        let (trace, _) = SingleDAllocCircuit.rx((a_val, b_val)).unwrap();
        let mut assignment = trace.assemble_trivial::<MyRank>().unwrap();
        let fw = assignment.forward();
        prop_assert_eq!(fw.c[1], Fp::ZERO);
    }

    /// b-value participates correctly in enforce_equal constraints.
    #[test]
    fn domain_b_wire_in_enforce_equal(val in arb_fe_with_edges()) {
        let sim = Simulator::<Fp>::simulate((val, val), |dr, witness| {
            let (a, b) = witness.cast();
            let (ae, be) = Element::dual_alloc(dr, a, b)?;
            dr.enforce_equal(ae.wire(), be.wire())?;
            Ok(())
        });
        prop_assert!(sim.is_ok());

        let other = val + Fp::ONE;
        if val != other {
            let sim = Simulator::<Fp>::simulate((val, other), |dr, witness| {
                let (a, b) = witness.cast();
                let (ae, be) = Element::dual_alloc(dr, a, b)?;
                dr.enforce_equal(ae.wire(), be.wire())?;
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
        let mut sy = assignment.clone();
        sy.dilate(z);
        sy.add_assign(&circuit.sy(y, &k, &floor_plan));
        sy.add_assign(&MyRank::tz(z));

        let expected = DWireEnforceCircuit.ky(val, y).unwrap();
        let rx_u = rx.unstructured();
        let sy_u = sy.unstructured();
        prop_assert_eq!(
            expected,
            ragu_arithmetic::dot(rx_u.iter(), sy_u.iter().rev())
        );
    }

    /// b-value element can be multiplied with another element.
    #[test]
    fn domain_b_wire_as_mul_input(
        b_val in arb_fe_with_edges(),
        x_val in arb_fe_with_edges(),
    ) {
        let a_val = Fp::from(5u64);

        let sim = Simulator::<Fp>::simulate((a_val, b_val, x_val), |dr, witness| {
            let (a_v, b_v, x_v) = witness.cast();
            let (_ae, be) = Element::dual_alloc(dr, a_v, b_v)?;
            let xe = Element::alloc(dr, x_v)?;
            let product = be.mul(dr, &xe)?;
            assert_eq!(*product.value().take(), b_val * x_val);
            Ok(())
        });
        prop_assert!(sim.is_ok());

        full_check(
            &DWireMulCircuit,
            DWireMulCircuit,
            (a_val, b_val, x_val),
            b_val * x_val,
        );
    }

    /// Pending b-wire from alloc is flushed before the dual_alloc gate starts.
    #[test]
    fn domain_alloc_then_d_alloc_flush(
        x in arb_fe_with_edges(),
        a in arb_fe_with_edges(),
        b in arb_fe_with_edges(),
    ) {
        full_check(
            &AllocThenDAllocCircuit,
            AllocThenDAllocCircuit,
            (x, a, b),
            x + b,
        );
    }

    /// Alloc after dual_alloc starts a new gate correctly.
    #[test]
    fn domain_d_alloc_then_alloc(
        a in arb_fe_with_edges(),
        b in arb_fe_with_edges(),
        x in arb_fe_with_edges(),
    ) {
        full_check(
            &DAllocThenAllocCircuit,
            DAllocThenAllocCircuit,
            (a, b, x),
            a + b + x,
        );
    }

    /// Five consecutive dual_alloc gates satisfy the revdot identity.
    #[test]
    fn domain_consecutive_d_alloc_gates(_dummy in Just(())) {
        let expected_sum = Fp::from(0u64)
            + Fp::from(10u64)
            + Fp::from(20u64)
            + Fp::from(30u64)
            + Fp::from(40u64);

        let (trace, _) = ConsecutiveDAllocCircuit.rx(()).unwrap();
        let assignment = trace.assemble_trivial::<MyRank>().unwrap();
        let circuit = ConsecutiveDAllocCircuit.into_object::<MyRank>().unwrap();
        consistency_checks(&*circuit);

        let y = Fp::random(&mut rand::rng());
        let z = Fp::random(&mut rand::rng());
        let k = registry::Key::default();
        let floor_plan = crate::floor_planner::floor_plan(circuit.segment_records());

        let rx = assignment.clone();
        let mut sy = assignment.clone();
        sy.dilate(z);
        sy.add_assign(&circuit.sy(y, &k, &floor_plan));
        sy.add_assign(&MyRank::tz(z));

        let expected = ConsecutiveDAllocCircuit.ky(expected_sum, y).unwrap();
        let rx_u = rx.unstructured();
        let sy_u = sy.unstructured();
        prop_assert_eq!(
            expected,
            ragu_arithmetic::dot(rx_u.iter(), sy_u.iter().rev())
        );
    }

    /// dual_alloc inside a routine boundary satisfies the revdot identity.
    #[test]
    fn domain_d_alloc_routine(input_val in arb_fe_with_edges()) {
        let b_val = Fp::from(100u64);
        full_check(
            &DAllocRoutineCircuit,
            DAllocRoutineCircuit,
            (input_val, b_val),
            input_val + b_val,
        );
    }

    /// Circuit mixing regular mul and dual_alloc satisfies the revdot identity.
    #[test]
    fn domain_mixed_mul_d_alloc_revdot(
        x1 in arb_fe_with_edges(),
        x3 in arb_fe_with_edges(),
    ) {
        full_check(
            &MixedMulDAllocCircuit,
            MixedMulDAllocCircuit,
            (x1, Fp::ZERO, x3),
            x1.square() + x3,
        );
    }

    /// Structured revdot agrees with unstructured dot for dual_alloc circuits.
    #[test]
    fn domain_structured_vs_unstructured_revdot(
        a_val in arb_fe_with_edges(),
        b_val in arb_fe_with_edges(),
    ) {
        let (trace, _) = SingleDAllocCircuit
            .rx((a_val, b_val))
            .unwrap();
        let assignment = trace.assemble_trivial::<MyRank>().unwrap();
        let circuit = SingleDAllocCircuit.into_object::<MyRank>().unwrap();

        let y = Fp::random(&mut rand::rng());
        let z = Fp::random(&mut rand::rng());
        let k = registry::Key::default();
        let floor_plan = crate::floor_planner::floor_plan(circuit.segment_records());

        let rx = assignment.clone();
        let mut sy = assignment.clone();
        sy.dilate(z);
        sy.add_assign(&circuit.sy(y, &k, &floor_plan));
        sy.add_assign(&MyRank::tz(z));

        let structured_result = rx.revdot(&sy);
        let rx_u = rx.unstructured();
        let sy_u = sy.unstructured();
        prop_assert_eq!(structured_result, ragu_arithmetic::dot(rx_u.iter(), sy_u.iter().rev()));
    }

    /// Mul routine and d-wire routine produce different fingerprints.
    #[test]
    fn domain_fingerprint_mul_vs_d_alloc(_dummy in Just(())) {
        use crate::metrics::tests::fingerprint_routine;

        let mut sim = Simulator::<Fp>::new();
        let input = Element::alloc(&mut sim, Always::<Fp>::just(|| Fp::from(1u64))).unwrap();

        let fp_mul = fingerprint_routine(&MulRoutine, &input).unwrap();
        let fp_d = fingerprint_routine(&DAllocRoutineFP, &input).unwrap();

        let mul_fp = match fp_mul {
            RoutineIdentity::Routine(fp) => fp,
            _ => panic!("expected Routine identity"),
        };
        let d_fp = match fp_d {
            RoutineIdentity::Routine(fp) => fp,
            _ => panic!("expected Routine identity"),
        };

        prop_assert_ne!(mul_fp.eval(), d_fp.eval());
    }

    /// Same d-wire routine fingerprinted twice produces identical results.
    #[test]
    fn domain_fingerprint_determinism(_dummy in Just(())) {
        use crate::metrics::tests::fingerprint_routine;

        let mut sim = Simulator::<Fp>::new();
        let input = Element::alloc(&mut sim, Always::<Fp>::just(|| Fp::from(1u64))).unwrap();

        let fp1 = fingerprint_routine(&DAllocRoutineFP2, &input).unwrap();
        let fp2 = fingerprint_routine(&DAllocRoutineFP2, &input).unwrap();

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
