use ff::Field;
use ragu_core::Result;

use alloc::vec::Vec;

use crate::{
    CircuitObject,
    polynomials::{Rank, sparse},
};

#[derive(Clone)]
pub struct StageMask<R: Rank> {
    skip_multiplications: usize,
    num_multiplications: usize,
    _marker: core::marker::PhantomData<R>,
}

impl<R: Rank> StageMask<R> {
    /// Creates a new staging wiring polynomial with the given
    /// `skip_multiplications` and `num_multiplications` values. Witnesses that
    /// satisfy this circuit will have all non-`ONE` multiplication gate wires
    /// enforced to equal zero except for the
    /// `skip_multiplications..(skip_multiplications + num_multiplications)`
    /// multiplication gates.
    pub fn new(skip_multiplications: usize, num_multiplications: usize) -> Result<Self> {
        if skip_multiplications + num_multiplications + 1 > R::n() {
            return Err(ragu_core::Error::MultiplicationBoundExceeded { limit: R::n() });
        }
        assert!(skip_multiplications + num_multiplications < R::n()); // Technically a redundant assertion.

        Ok(Self {
            skip_multiplications,
            num_multiplications,
            _marker: core::marker::PhantomData,
        })
    }

    /// Creates the final staging wiring polynomial with the given
    /// `skip_multiplications` and maximum possible multiplications.
    /// The number of multiplications will be `R::n() - skip_multiplications - 1`,
    /// which is the maximum before bounds are reached.
    pub fn new_final(skip_multiplications: usize) -> Result<Self> {
        if skip_multiplications + 1 > R::n() {
            return Err(ragu_core::Error::MultiplicationBoundExceeded { limit: R::n() });
        }

        let num_multiplications = R::n() - skip_multiplications - 1;
        assert!(skip_multiplications + num_multiplications < R::n()); // Technically a redundant assertion.

        Ok(Self {
            skip_multiplications,
            num_multiplications,
            _marker: core::marker::PhantomData,
        })
    }
}

impl<F: Field, R: Rank> CircuitObject<F, R> for StageMask<R> {
    fn sxy(&self, x: F, y: F, _floor_plan: &[crate::floor_planner::ConstraintSegment]) -> F {
        // Bound is enforced in `StageMask::new`.
        assert!(self.skip_multiplications + self.num_multiplications < R::n());
        let reserved: usize = R::n() - self.skip_multiplications - self.num_multiplications - 1;

        if x == F::ZERO || y == F::ZERO {
            // If either x or y is zero, the polynomial evaluates to zero
            // (the constant term of a bonding polynomial is always zero).
            return F::ZERO;
        }

        let x_inv = x.invert().expect("x is not zero");
        let y2 = y.square();
        let y3 = y * y2;
        let x_y3 = x * y3;
        let xinv_y3 = x_inv * y3;

        let block = |end: usize, len: usize| -> F {
            let w = y * x.pow_vartime([(4 * R::n() - 2 - end) as u64]);
            let v = y2 * x.pow_vartime([(2 * R::n() + 1 + end) as u64]);
            let u = y3 * x.pow_vartime([(2 * R::n() - 2 - end) as u64]);

            let plus = ragu_arithmetic::geosum::<F>(x_y3, len);
            let minus = ragu_arithmetic::geosum::<F>(xinv_y3, len);

            w * plus + v * minus + u * plus
        };

        // Handle the edge case where skip_multiplications is zero.
        let c1 = if self.skip_multiplications > 0 {
            block(self.skip_multiplications - 1, self.skip_multiplications)
        } else {
            F::ZERO
        };
        let c2 = block(R::n() - 2, reserved);

        y.pow_vartime([(3 * reserved) as u64]) * c1 + c2
    }

    fn sx(
        &self,
        x: F,
        _floor_plan: &[crate::floor_planner::ConstraintSegment],
    ) -> sparse::Polynomial<F, R> {
        // Bound is enforced in `StageMask::new`.
        assert!(self.skip_multiplications + self.num_multiplications < R::n());
        let reserved: usize = R::n() - self.skip_multiplications - self.num_multiplications - 1;

        if x == F::ZERO {
            return sparse::Polynomial::new();
        }

        let mut coeffs = Vec::with_capacity(R::num_coeffs());
        {
            let x_inv = x.invert().expect("x is not zero");
            let xn = x.pow_vartime([R::n() as u64]); // xn = x^n
            let xn2 = xn.square(); // xn2 = x^(2n)
            let mut u = xn2 * x_inv; // x^(2n - 1)
            let mut v = xn2; // x^(2n)
            let xn4 = xn2.square(); // x^(4n)
            let mut w = xn4 * x_inv; // x^(4n - 1)

            let mut alloc = || {
                let out = (u, v, w);
                u *= x_inv;
                v *= x;
                w *= x_inv;
                out
            };

            // Skip the ONE gate (gate 0) — its wires are consumed but not
            // constrained here. The registry key constraint is injected at the
            // registry level.
            alloc();

            let mut enforce_zero = |out: (F, F, F)| {
                coeffs.push(out.0);
                coeffs.push(out.1);
                coeffs.push(out.2);
            };

            for _ in 0..self.skip_multiplications {
                enforce_zero(alloc());
            }
            for _ in 0..self.num_multiplications {
                alloc();
            }
            for _ in 0..reserved {
                enforce_zero(alloc());
            }
        }

        coeffs.push(F::ZERO); // The constant term is always zero.
        coeffs.reverse();

        sparse::Polynomial::from_coeffs(coeffs)
    }

    fn sy(
        &self,
        y: F,
        _floor_plan: &[crate::floor_planner::ConstraintSegment],
    ) -> sparse::Polynomial<F, R> {
        // Bound is enforced in `StageMask::new`.
        assert!(self.skip_multiplications + self.num_multiplications < R::n());
        let reserved: usize = R::n() - self.skip_multiplications - self.num_multiplications - 1;

        if y == F::ZERO {
            return sparse::Polynomial::new();
        }

        let num_linear_from_gates = 3 * (reserved + self.skip_multiplications);
        // Start at y^{3*(reserved + skip)}: the highest Y-power used by gate
        // constraints. The registry key constraint (formerly counted here as +1)
        // now occupies Y^{4n-1} at the registry level and is excluded.
        let mut yq = y.pow_vartime([num_linear_from_gates as u64]);
        let y_inv = y.invert().expect("y is not zero");

        let mut view = sparse::View::backward();

        // Skip the ONE gate (gate 0). In the backward wire layout b[0] maps
        // to X^{2n} (the ONE wire). The registry key contribution at c[0] is
        // supplied by RegistryAt::y(), not here.
        view.a.push(F::ZERO);
        view.b.push(F::ZERO);
        view.c.push(F::ZERO);

        for _ in 0..self.skip_multiplications {
            view.a.push(yq);
            yq *= y_inv;
            view.b.push(yq);
            yq *= y_inv;
            view.c.push(yq);
            yq *= y_inv;
        }
        for _ in 0..self.num_multiplications {
            view.a.push(F::ZERO);
            view.b.push(F::ZERO);
            view.c.push(F::ZERO);
        }
        for _ in 0..reserved {
            view.a.push(yq);
            yq *= y_inv;
            view.b.push(yq);
            yq *= y_inv;
            view.c.push(yq);
            yq *= y_inv;
        }

        view.build()
    }

    fn constraint_counts(&self) -> (usize, usize) {
        let num_multiplication_constraints = R::n();
        // 3 constraints per non-multiplied gate + 1 for the ONE constraint.
        // The registry key constraint is handled at the registry level.
        let num_linear_constraints = 3 * (R::n() - self.num_multiplications - 1) + 1;
        (num_multiplication_constraints, num_linear_constraints)
    }

    fn segment_records(&self) -> &[crate::SegmentRecord] {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use ff::Field;
    use group::{Curve, prime::PrimeCurveAffine};
    use proptest::prelude::*;
    use ragu_arithmetic::{Coeff, CurveAffine, Cycle, FixedGenerators, Uendo};
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue, LinearExpression, emulator::Emulator},
        gadgets::{Bound, Gadget},
        maybe::Maybe,
        routines::{Prediction, Routine},
    };
    use ragu_pasta::{EpAffine, EqAffine, Fp, Fq, Pasta};
    use ragu_primitives::{Element, Endoscalar, Point, consistent::Consistent, io::Write};
    use rand::RngExt;

    use crate::{
        CircuitObject, WithAux, floor_planner, into_circuit_object, metrics,
        polynomials::{Rank, sparse},
        staging::StageBuilder,
        tests::SquareCircuit,
    };

    use super::{
        super::{Stage, StageExt},
        StageMask,
    };

    impl<F: Field, R: Rank> crate::Circuit<F> for StageMask<R> {
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            _: &mut D,
            _: DriverValue<D, Self::Instance<'source>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Ok(())
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            dr: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
        {
            let reserved = self.skip_multiplications + self.num_multiplications + 1;
            assert!(reserved <= R::n());

            for _ in 0..self.skip_multiplications {
                let (a, b, c) = dr.mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
                dr.enforce_zero(|lc| lc.add(&a))?;
                dr.enforce_zero(|lc| lc.add(&b))?;
                dr.enforce_zero(|lc| lc.add(&c))?;
            }

            for _ in 0..self.num_multiplications {
                dr.mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
            }

            for _ in 0..(R::n() - reserved) {
                let (a, b, c) = dr.mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
                dr.enforce_zero(|lc| lc.add(&a))?;
                dr.enforce_zero(|lc| lc.add(&b))?;
                dr.enforce_zero(|lc| lc.add(&c))?;
            }

            Ok(WithAux::new((), D::unit()))
        }
    }

    impl<R: Rank> StageMask<R> {
        /// Returns the generator point for the i-th A coefficient of this stage.
        ///
        /// This is useful for computing commitments to values placed in A positions
        /// of the witness polynomial, such as challenge coefficients for smuggling.
        fn generator_for_a_coefficient<C: CurveAffine>(
            &self,
            generators: &impl FixedGenerators<C>,
            coefficient_index: usize,
        ) -> C {
            assert!(
                coefficient_index < self.num_multiplications,
                "coefficient_index {} exceeds num_multiplications {}",
                coefficient_index,
                self.num_multiplications
            );

            let idx = 2 * R::n() + 1 + self.skip_multiplications + coefficient_index;
            generators.g()[idx]
        }
    }

    type R = crate::polynomials::ProductionRank;

    #[test]
    fn test_staging_valid() -> Result<()> {
        #[derive(Default)]
        struct MyStage1;
        #[derive(Default)]
        struct MyStage2;

        impl Stage<Fp, R> for MyStage1 {
            type Parent = ();

            fn values() -> usize {
                Uendo::BITS as usize
            }

            type Witness<'source> = Uendo;
            type OutputKind = Endoscalar<'static, core::marker::PhantomData<Fp>>;

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<Bound<'dr, D, Self::OutputKind>>
            where
                Self: 'dr,
            {
                Endoscalar::alloc(dr, witness)
            }
        }

        impl Stage<Fp, R> for MyStage2 {
            type Parent = MyStage1;

            fn values() -> usize {
                4
            }

            type Witness<'source> = (EpAffine, EpAffine);
            type OutputKind = (
                core::marker::PhantomData<Point<'static, core::marker::PhantomData<Fp>, EpAffine>>,
                core::marker::PhantomData<Point<'static, core::marker::PhantomData<Fp>, EpAffine>>,
            );

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<Bound<'dr, D, Self::OutputKind>>
            where
                Self: 'dr,
            {
                let a = Point::alloc(dr, witness.as_ref().map(|w| w.0))?;
                let b = Point::alloc(dr, witness.as_ref().map(|w| w.1))?;

                Ok((a, b))
            }
        }

        let endoscalar_a: Uendo = rand::rng().random();
        let endoscalar_b: Uendo = rand::rng().random();
        let p1 = (EpAffine::generator() * Fq::random(&mut rand::rng())).into();
        let p2 = (EpAffine::generator() * Fq::random(&mut rand::rng())).into();

        let rx1_a = MyStage1::rx(endoscalar_a)?;
        let rx1_b = MyStage1::rx(endoscalar_b)?;
        let rx2 = MyStage2::rx((p1, p2))?;

        let circ1 = MyStage1::mask()?.into_inner();
        let circ2 = MyStage2::mask()?.into_inner();

        let z = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        {
            let rhs = circ1.sy(y, &[]);
            assert_eq!(rx1_a.revdot(&rhs), Fp::ZERO);
            assert_eq!(rx1_b.revdot(&rhs), Fp::ZERO);

            // It is safe to combine an arbitrary number of these into a single
            // revdot claim (separating each stage polynomial by a power of z)
            // because the right hand side is the same for each, and the result
            // must be zero in both cases.
            let mut combined = rx1_a.clone();
            combined.scale(z);
            combined.add_assign(&rx1_b);
            assert_eq!(combined.revdot(&rhs), Fp::ZERO);
        }

        assert_eq!(rx1_a.revdot(&circ1.sy(y, &[])), Fp::ZERO);
        assert_eq!(rx2.revdot(&circ2.sy(y, &[])), Fp::ZERO);
        assert!(rx1_a.revdot(&circ2.sy(y, &[])) != Fp::ZERO);
        assert!(rx2.revdot(&circ1.sy(y, &[])) != Fp::ZERO);

        Ok(())
    }

    #[test]
    fn test_skip_multiplications_zero() {
        let stage_mask = StageMask::<R>::new(0, 5).unwrap();

        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        let sxy = stage_mask.sxy(x, y, &[]);
        let sx = stage_mask.sx(x, &[]);
        let sy = stage_mask.sy(y, &[]);

        assert_eq!(sxy, sx.eval(y));
        assert_eq!(sxy, sy.eval(x));
    }

    #[test]
    fn test_stage_mask_all_multiplications() {
        // Edge case: skip = 0, num = R::n() - 1, reserved = 0.
        let stage = StageMask::<R>::new(0, R::n() - 1).unwrap();
        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        let generic = into_circuit_object::<_, _, R>(stage.clone()).unwrap();
        let plan = floor_planner::floor_plan(generic.segment_records());
        let stripped = crate::staging::bonding::Stripped(generic);
        let comparison_sxy = stripped.sxy(x, y, &plan);

        assert_eq!(stage.sxy(x, y, &[]), comparison_sxy);
        assert_eq!(comparison_sxy, stripped.sx(x, &plan).eval(y));
        assert_eq!(comparison_sxy, stripped.sy(y, &plan).eval(x));
    }

    #[test]
    fn test_minimum_linear_constraints() {
        let circuit = into_circuit_object::<_, _, R>(SquareCircuit { times: 2 }).unwrap();
        let y = Fp::random(&mut rand::rng());

        let (_, num_linear_constraints) = circuit.constraint_counts();
        let plan = floor_planner::floor_plan(circuit.segment_records());
        let sy = circuit.sy(y, &plan);

        // The ONE wire (b-wire of gate 0) should have the y^0 coefficient.
        // In the backward view, b[0] maps to degree 2n.
        let sy_dense = sy.to_dense();
        let actual_one_coeff = sy_dense[2 * R::n()];

        // The ONE constraint is at Y^0, so its coefficient is y^0 = 1.
        assert_eq!(
            actual_one_coeff,
            Fp::ONE,
            "ONE wire coefficient should be 1 (y^0 from enforce_one)"
        );

        // The a-wire of gate 0 is not constrained at the circuit level —
        // the registry key constraint is injected at the registry level on
        // the c-wire only — so its coefficient should be zero.
        let actual_a0_coeff = sy_dense[2 * R::n() - 1];
        assert_eq!(
            actual_a0_coeff,
            Fp::ZERO,
            "a-wire of gate 0 should be zero (not constrained at circuit level)"
        );

        // Verify the expected number of constraints.
        assert!(num_linear_constraints >= 1);
    }

    #[test]
    fn test_root_routine_has_at_least_one_linear_constraint() {
        // The root segment always gets the ONE constraint from
        // metrics::eval(), so its num_linear_constraints must be at least 1.
        // This invariant prevents the `- 1` underflow in sy::eval's initial
        // y-power computation.
        let circuit = into_circuit_object::<_, _, R>(SquareCircuit { times: 0 }).unwrap();
        let floor_plan = floor_planner::floor_plan(circuit.segment_records());
        assert!(
            floor_plan[0].num_linear_constraints >= 1,
            "root segment must have at least 1 linear constraint (ONE), got {}",
            floor_plan[0].num_linear_constraints,
        );
    }

    #[test]
    fn test_stage_mask_exact_boundary() {
        let result = StageMask::<R>::new(R::n() - 2, 1);
        assert!(result.is_ok(), "Should accept skip + num + 1 == R::n()");

        let result = StageMask::<R>::new(R::n() - 1, 1);
        assert!(result.is_err(), "Should reject skip + num + 1 > R::n()");
    }

    #[test]
    fn test_stage_mask_reserved_zero() {
        // When reserved = 0, all gates except one are used.
        let stage = StageMask::<R>::new(0, R::n() - 1).expect("skip multiplications");

        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        let sxy = stage.sxy(x, y, &[]);
        let sx = stage.sx(x, &[]);
        let sy = stage.sy(y, &[]);

        assert_eq!(sxy, sx.eval(y));
        assert_eq!(sxy, sy.eval(x));
    }

    #[test]
    fn test_stage_mask_reserved_computation() {
        // Check we're computing reserved correctly.
        for skip in 0..10 {
            for num in 0..(R::n() - skip - 1) {
                let _ = StageMask::<R>::new(skip, num).expect("skip multiplications");
                let expected_reserved = R::n() - skip - num - 1;

                let num_linear_from_gates = 3 * (skip + expected_reserved);
                assert!(
                    num_linear_from_gates < R::num_coeffs(),
                    "Reserved computation should not cause overflow"
                );
            }
        }
    }

    proptest! {
        #[test]
        fn test_exy_proptest(skip in 0..R::n(), num in 0..R::n()) {
            prop_assume!(skip + 1 + num <= R::n());

            let stage_mask = StageMask::<R>::new(skip, num).unwrap();

            let generic = into_circuit_object::<_, _, R>(
                StageMask::<R>::new(skip, num).unwrap()
            ).unwrap();
            let plan = floor_planner::floor_plan(generic.segment_records());

            let stripped = crate::staging::bonding::Stripped(generic);

            let check = |x: Fp, y: Fp| {
                let sxy = stripped.sxy(x, y, &plan);
                let sx = stripped.sx(x, &plan);
                let sy = stripped.sy(y, &plan);

                prop_assert_eq!(sy.eval(x), sxy);
                prop_assert_eq!(sx.eval(y), sxy);
                prop_assert_eq!(stage_mask.sxy(x, y, &[]), sxy);
                prop_assert_eq!(stage_mask.sx(x, &[]).eval(y), sxy);
                prop_assert_eq!(stage_mask.sy(y, &[]).eval(x), sxy);

                Ok(())
            };

            let x = Fp::random(&mut rand::rng());
            let y = Fp::random(&mut rand::rng());
            check(x, y)?;
            check(Fp::ZERO, y)?;
            check(x, Fp::ZERO)?;
            check(Fp::ZERO, Fp::ZERO)?;

        }
    }

    #[derive(Default)]
    struct ConstrainedStage;

    #[derive(Gadget, Consistent, Write)]
    struct TwoElements<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        a: Element<'dr, D>,
        #[ragu(gadget)]
        b: Element<'dr, D>,
    }

    impl Stage<Fp, R> for ConstrainedStage {
        type Parent = ();
        type Witness<'source> = (Fp, Fp);
        type OutputKind =
            <TwoElements<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

        fn values() -> usize {
            2
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            let witness_a = witness.as_ref().map(|w| w.0);
            let witness_b = witness.as_ref().map(|w| w.1);

            let a = Element::alloc(dr, witness_a)?;
            let b = Element::alloc(dr, witness_b)?;

            dr.enforce_zero(|lc| lc.add(a.wire()).sub(b.wire()))?;

            Ok(TwoElements { a, b })
        }
    }

    #[test]
    fn test_enforce_stage_works() {
        let result =
            Emulator::emulate_wireless((Fp::from(42u64), Fp::from(42u64)), |dr, witness| {
                let builder = StageBuilder::<_, R, (), ConstrainedStage>::new(dr);
                let (guard, builder) = builder.add_stage::<ConstrainedStage>()?;
                let _gagdet = guard.enforced(builder.finish(), witness)?;
                Ok(())
            });

        assert!(result.is_ok(), "enforce_stage should succeed");
    }

    #[test]
    fn test_stage_well_formedness_with_valid_witness() {
        let valid_witness = (Fp::from(7u64), Fp::from(7u64));

        let rx = ConstrainedStage::rx(valid_witness).unwrap();

        let stage_mask = ConstrainedStage::mask::<'_>().unwrap().into_inner();

        // rx.revdot(&stage_mask) == 0 for well-formed stages
        let y = Fp::random(&mut rand::rng());
        let sy = stage_mask.sy(y, &[]);

        let check = rx.revdot(&sy);
        assert_eq!(
            check,
            Fp::ZERO,
            "valid witness should produce well-formed stage polynomial"
        );
    }

    #[test]
    fn test_constraint_counts_matches_metrics() {
        for skip in 0..10 {
            for num in 0..(R::n() - skip - 1) {
                let stage_mask = StageMask::<R>::new(skip, num).unwrap();
                let (mul_from_method, linear_from_method) =
                    <StageMask<R> as CircuitObject<Fp, R>>::constraint_counts(&stage_mask);

                let metrics = metrics::eval::<Fp, _>(&stage_mask).unwrap();

                assert_eq!(
                    mul_from_method, metrics.num_multiplication_constraints,
                    "multiplication constraints mismatch for skip={}, num={}",
                    skip, num
                );
                assert_eq!(
                    linear_from_method, metrics.num_linear_constraints,
                    "linear constraints mismatch for skip={}, num={}",
                    skip, num
                );
            }
        }
    }

    #[test]
    fn test_child_routine_zero_linear_constraints() {
        // A routine that only uses a multiplication gate and no linear
        // constraints.  This exercises the `.saturating_sub(1)` path in
        // sy::eval's sub-routine y-power initialisation.
        #[derive(Clone)]
        struct MulOnlyRoutine;

        impl Routine<Fp> for MulOnlyRoutine {
            type Input = ();
            type Output = ();
            type Aux<'dr> = ();

            fn execute<'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                _input: Bound<'dr, D, Self::Input>,
                _aux: DriverValue<D, Self::Aux<'dr>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                dr.mul(|| unreachable!())?;
                Ok(())
            }

            fn predict<'dr, D: Driver<'dr, F = Fp>>(
                &self,
                _dr: &mut D,
                _input: &Bound<'dr, D, Self::Input>,
            ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
            {
                Ok(Prediction::Unknown(D::unit()))
            }
        }

        struct TestCircuit;

        impl crate::Circuit<Fp> for TestCircuit {
            type Instance<'source> = ();
            type Witness<'source> = ();
            type Output = ();
            type Aux<'source> = ();

            fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                _dr: &mut D,
                _instance: DriverValue<D, Self::Instance<'source>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Ok(())
            }

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                _witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
            {
                dr.routine(MulOnlyRoutine, ())?;
                Ok(WithAux::new((), D::unit()))
            }
        }

        let circuit = into_circuit_object::<_, _, R>(TestCircuit).unwrap();
        let floor_plan = floor_planner::floor_plan(circuit.segment_records());

        // The child routine (index 1) should have zero linear constraints.
        assert_eq!(
            floor_plan[1].num_linear_constraints, 0,
            "MulOnlyRoutine should have 0 linear constraints"
        );

        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        // None of these must panic — previously sy would underflow on `- 1`.
        let sxy = circuit.sxy(x, y, &floor_plan);
        let sx = circuit.sx(x, &floor_plan);
        let sy = circuit.sy(y, &floor_plan);

        assert_eq!(sxy, sx.eval(y));
        assert_eq!(sxy, sy.eval(x));
    }

    /// A stage that allocates values only in a-positions (b = 0) for challenge smuggling.
    ///
    /// Each value is paired with a zero to ensure it lands in an a-coefficient position
    /// when the polynomial is built. This mimics the pattern used for smuggling challenges.
    #[derive(Default)]
    struct ParentAOnlyStage;

    #[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write)]
    struct ThreeAOnlyElements<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        a0: Element<'dr, D>,
        #[ragu(gadget)]
        b0: Element<'dr, D>,
        #[ragu(gadget)]
        a1: Element<'dr, D>,
        #[ragu(gadget)]
        b1: Element<'dr, D>,
        #[ragu(gadget)]
        a2: Element<'dr, D>,
        #[ragu(gadget)]
        b2: Element<'dr, D>,
    }

    impl Stage<Fp, R> for ParentAOnlyStage {
        type Parent = ();
        type Witness<'source> = [Fp; 3];
        type OutputKind = <ThreeAOnlyElements<'static, PhantomData<Fp>> as Gadget<
            'static,
            PhantomData<Fp>,
        >>::Kind;

        fn values() -> usize {
            6 // 3 multiplication gates
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            // Allocate each challenge value followed by zero, which
            // ensures challenges land in a-positions, zeros in b-positions.
            let a0 = Element::alloc(dr, witness.as_ref().map(|w| w[0]))?;
            let b0 = Element::zero(dr);
            let a1 = Element::alloc(dr, witness.as_ref().map(|w| w[1]))?;
            let b1 = Element::zero(dr);
            let a2 = Element::alloc(dr, witness.as_ref().map(|w| w[2]))?;
            let b2 = Element::zero(dr);

            Ok(ThreeAOnlyElements {
                a0,
                b0,
                a1,
                b1,
                a2,
                b2,
            })
        }
    }

    #[derive(Default)]
    struct ChildOfParentAOnlyStage;

    impl Stage<Fp, R> for ChildOfParentAOnlyStage {
        type Parent = ParentAOnlyStage;
        type Witness<'source> = [Fp; 3];
        type OutputKind = <ThreeAOnlyElements<'static, PhantomData<Fp>> as Gadget<
            'static,
            PhantomData<Fp>,
        >>::Kind;

        fn values() -> usize {
            6 // 3 multiplication gates
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            let a0 = Element::alloc(dr, witness.as_ref().map(|w| w[0]))?;
            let b0 = Element::zero(dr);
            let a1 = Element::alloc(dr, witness.as_ref().map(|w| w[1]))?;
            let b1 = Element::zero(dr);
            let a2 = Element::alloc(dr, witness.as_ref().map(|w| w[2]))?;
            let b2 = Element::zero(dr);

            Ok(ThreeAOnlyElements {
                a0,
                b0,
                a1,
                b1,
                a2,
                b2,
            })
        }
    }

    /// Tests that `StageMask::generator_for_a_coefficient` returns the generator
    /// at the index computed by `StageExt::generator_index_for_a`.
    #[test]
    fn test_generator_for_a_coefficient() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        // Test via StageMask directly
        let parent_mask = StageMask::<R>::new(
            ParentAOnlyStage::skip_multiplications(),
            ParentAOnlyStage::num_multiplications(),
        )
        .unwrap();

        for i in 0..3 {
            let gen_idx = <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(i);
            let expected_gen = generators.g()[gen_idx];
            let actual_gen = parent_mask.generator_for_a_coefficient(generators, i);
            assert_eq!(actual_gen, expected_gen);
        }

        let child_mask = StageMask::<R>::new(
            ChildOfParentAOnlyStage::skip_multiplications(),
            ChildOfParentAOnlyStage::num_multiplications(),
        )
        .unwrap();

        for i in 0..3 {
            let gen_idx = <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(i);
            let expected_gen = generators.g()[gen_idx];
            let actual_gen = child_mask.generator_for_a_coefficient(generators, i);
            assert_eq!(actual_gen, expected_gen);
        }
    }

    /// Tests the generator index formula `2n + 1 + skip + i` for both a root
    /// stage and a child stage with non-zero skip.
    #[test]
    fn test_generator_index_edge_cases() {
        assert_eq!(
            <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(0),
            2 * R::n() + 1
        );
        assert_eq!(
            <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(2),
            2 * R::n() + 3
        );
        assert_eq!(
            <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(0),
            2 * R::n() + 4
        );
        assert_eq!(
            <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(2),
            2 * R::n() + 6
        );
    }

    /// Tests that committing to an rx polynomial with values only in a-positions
    /// matches a manual MSM using generators from `generator_index_for_a`.
    #[test]
    fn test_a_only_commitment_for_challenge_smuggling() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        let challenges = [Fp::from(42u64), Fp::from(123u64), Fp::from(456u64)];
        let blind = Fp::ZERO;

        let rx: sparse::Polynomial<Fp, R> = ChildOfParentAOnlyStage::rx(challenges).unwrap();
        let poly_commitment: EqAffine = rx.commit_to_affine(generators, blind);

        let mut manual_commitment = EqAffine::identity();
        for (i, &challenge) in challenges.iter().enumerate() {
            let idx = <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(i);
            let a_gen = generators.g()[idx];
            let contrib = a_gen * challenge;
            manual_commitment = (manual_commitment.to_curve() + contrib).to_affine();
        }

        assert_eq!(
            poly_commitment, manual_commitment,
            "A-only commitment should match manual computation"
        );
    }

    /// Same as above but for a root stage (no parent, zero skip).
    #[test]
    fn test_a_only_commitment_via_staging_mechanism() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        let challenges = [Fp::from(42u64), Fp::from(123u64), Fp::from(456u64)];
        let blind = Fp::ZERO;

        let rx: sparse::Polynomial<Fp, R> = ParentAOnlyStage::rx(challenges).unwrap();
        let poly_commitment: EqAffine = rx.commit_to_affine(generators, blind);

        // Manually compute expected commitment using StageExt::generator_index_for_a.
        let mut manual_commitment = EqAffine::identity();
        for (i, &challenge) in challenges.iter().enumerate() {
            let idx = <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(i);
            let a_gen = generators.g()[idx];
            manual_commitment = (manual_commitment.to_curve() + a_gen * challenge).to_affine();
        }

        assert_eq!(
            poly_commitment, manual_commitment,
            "Commitment via staging mechanism should match manual computation"
        );
    }
}
