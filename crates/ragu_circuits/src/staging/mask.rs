use ff::Field;
use ragu_arithmetic::geosum;
use ragu_core::Result;

use crate::{
    CircuitObject,
    polynomials::{Rank, sparse},
};

#[derive(Clone)]
pub struct StageMask<R: Rank> {
    skip_gates: usize,
    num_gates: usize,
    _marker: core::marker::PhantomData<R>,
}

impl<R: Rank> StageMask<R> {
    /// Creates a new staging wiring polynomial with the given
    /// `skip_gates` and `num_gates` values. `skip_gates` includes
    /// the SYSTEM gate (gate 0) and must be at least 1. Gate wires are
    /// enforced to zero for gates `1..skip_gates` and
    /// `(skip_gates + num_gates)..n`. The SYSTEM gate is not constrained
    /// here because `d[0]` carries the alpha blinding factor and
    /// `b[0]` may or may not be set to 1; `a[0]` and `c[0]` are
    /// zero in all cases.
    pub fn new(skip_gates: usize, num_gates: usize) -> Result<Self> {
        assert!(skip_gates > 0, "skip_gates must include the SYSTEM gate");
        if skip_gates + num_gates > R::n() {
            return Err(ragu_core::Error::GateBoundExceeded { limit: R::n() });
        }
        Ok(Self {
            skip_gates,
            num_gates,
            _marker: core::marker::PhantomData,
        })
    }

    /// Creates the final staging wiring polynomial with the given
    /// `skip_gates` and maximum possible gates. `skip_gates` must
    /// be at least 1 (it includes the SYSTEM gate). The number
    /// of gates will be `R::n() - skip_gates`, which is the maximum
    /// before bounds are reached.
    pub fn new_final(skip_gates: usize) -> Result<Self> {
        assert!(skip_gates > 0, "skip_gates must include the SYSTEM gate");
        if skip_gates > R::n() {
            return Err(ragu_core::Error::GateBoundExceeded { limit: R::n() });
        }

        let num_gates = R::n() - skip_gates;

        Ok(Self {
            skip_gates,
            num_gates,
            _marker: core::marker::PhantomData,
        })
    }

    /// Projects the bivariate mask polynomial onto a univariate sparse
    /// polynomial by evaluating one variable at `p`. Used by both
    /// `sx` ($S(x, Y)$) and `sy` ($S(X, y)$). Unconstrained wires
    /// (the SYSTEM gate and active-stage gates) are zeroed out.
    fn project<F: Field>(&self, p: F) -> sparse::Polynomial<F, R> {
        let n = R::n();
        let mut view = sparse::View::<F, R, _>::wiring();
        view.d.resize(n, F::ZERO);
        view.a.resize(n, F::ZERO);
        view.b.resize(n, F::ZERO);
        view.c.resize(n, F::ZERO);

        let mut cur = F::ONE;
        for j in 0..n {
            view.d[j] = cur;
            cur *= p;
        }
        for j in (0..n).rev() {
            view.a[j] = cur;
            cur *= p;
        }
        for j in 0..n {
            view.b[j] = cur;
            cur *= p;
        }
        for j in (0..n).rev() {
            view.c[j] = cur;
            cur *= p;
        }

        // The wires in the SYSTEM gate are unconstrained.
        view.a[0] = F::ZERO;
        view.b[0] = F::ZERO;
        view.c[0] = F::ZERO;
        view.d[0] = F::ZERO;

        // The wires active in the stage are not constrained.
        for i in 0..self.num_gates {
            let j = self.skip_gates + i;
            view.a[j] = F::ZERO;
            view.b[j] = F::ZERO;
            view.c[j] = F::ZERO;
            view.d[j] = F::ZERO;
        }

        view.build()
    }
}

impl<F: Field, R: Rank> CircuitObject<F, R> for StageMask<R> {
    fn sxy(&self, x: F, y: F, _floor_plan: &[crate::floor_planner::ConstraintSegment]) -> F {
        if x == F::ZERO || y == F::ZERO {
            // If either x or y is zero, the polynomial evaluates to zero
            // (the constant term of a bonding polynomial is always zero).
            return F::ZERO;
        }

        // Precomputed (ideally):
        let xy = x * y;
        let xy_2n = xy.pow_vartime([2 * R::n() as u64]);
        let xy_inv = xy.invert().expect("xy is not zero");

        /// Full wiring polynomial $S(xy)$ over all $4n$ wire slots,
        /// minus the SYSTEM gate's four unconstrained wires.
        fn global<F: Field>(xy: F, xy_2n: F, xy_inv: F, n: usize) -> F {
            geosum(xy, n << 2) - (xy_2n + F::ONE) * (xy_2n * xy_inv + F::ONE)
        }

        /// Contribution of the `m` active-stage gates starting at gate `g`.
        /// Subtracted from [`global`] to zero out unconstrained wires.
        fn notch<F: Field>(xy: F, xy_2n: F, xy_inv: F, g: usize, m: usize) -> F {
            let gsum = geosum(xy, m);
            let xy_g = xy.pow_vartime([g as u64]);
            let xy_h = xy_2n * xy_inv.pow_vartime([(g + m) as u64]);

            (F::ONE + xy_2n) * (xy_g + xy_h) * gsum
        }

        global(xy, xy_2n, xy_inv, R::n())
            - notch(xy, xy_2n, xy_inv, self.skip_gates, self.num_gates)
    }

    fn sx(
        &self,
        x: F,
        _floor_plan: &[crate::floor_planner::ConstraintSegment],
    ) -> sparse::Polynomial<F, R> {
        self.project(x)
    }

    fn sy(
        &self,
        y: F,
        _floor_plan: &[crate::floor_planner::ConstraintSegment],
    ) -> sparse::Polynomial<F, R> {
        self.project(y)
    }

    fn constraint_counts(&self) -> (usize, usize) {
        let num_gates = R::n();
        // 4n-2 enforce_zero (all degrees from 4n-2 to 1, with dummies for
        // active gates and the SYSTEM gate's inaccessible wires) + 1 enforce_one.
        let num_constraints = 4 * R::n() - 1;
        (num_gates, num_constraints)
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
    use ragu_arithmetic::{CurveAffine, Cycle, FixedGenerators, Uendo};
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
        CircuitObject, WithAux, floor_planner, into_circuit_object, into_raw_circuit_object,
        metrics,
        polynomials::{Rank, sparse},
        staging::StageBuilder,
        tests::SquareCircuit,
    };

    use super::{
        super::{Stage, StageExt},
        StageMask,
    };

    use crate::raw::GateWires;

    impl<F: Field, R: Rank> crate::raw::RawCircuit<F> for StageMask<R> {
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            dr: &mut D,
            system_gate: GateWires<D::Wire>,
            _: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
        where
            Self: 'dr,
        {
            assert!(self.skip_gates + self.num_gates <= R::n());

            // Collect all n gates. The SYSTEM gate comes from the
            // orchestration function; gates 1..n are allocated here.
            let mut gates = alloc::vec::Vec::with_capacity(R::n());
            gates.push(system_gate);
            for _ in 1..R::n() {
                gates.push(GateWires::from(dr.gate(|| unimplemented!())?));
            }

            let is_active =
                |j: usize| j == 0 || (j >= self.skip_gates && j < self.skip_gates + self.num_gates);

            // Issue 4n-2 enforce_zero in decreasing degree order so that the
            // driver assigns y^k to the constraint at degree k. Dummy (empty
            // LC) constraints fill gaps for active gates. SYSTEM gate wires
            // are directly accessible via gates[0].
            //
            // c[j] at degree 4n-1-j (j=1..n-1), b[j] at degree 2n+j (j=n-1..0),
            // a[j] at degree 2n-1-j (j=0..n-1), d[j] at degree j (j=n-1..1).
            // d[0] at degree 0 is not issued (unconstrained blinding factor).
            // c[0] is the registry key slot at degree 4n-1 — not emitted here.
            let wires = gates
                .iter()
                .enumerate()
                .skip(1)
                .map(|(j, g)| (!is_active(j)).then_some(&g.c))
                .chain(
                    gates
                        .iter()
                        .enumerate()
                        .rev()
                        .map(|(j, g)| (!is_active(j)).then_some(&g.b)),
                )
                .chain(
                    gates
                        .iter()
                        .enumerate()
                        .map(|(j, g)| (!is_active(j)).then_some(&g.a)),
                )
                .chain(
                    gates
                        .iter()
                        .enumerate()
                        .skip(1)
                        .rev()
                        .map(|(j, g)| (!is_active(j)).then_some(&g.d)),
                );

            for wire in wires {
                match wire {
                    Some(w) => dr.enforce_zero(|lc| lc.add(w))?,
                    None => dr.enforce_zero(|lc| lc)?,
                }
            }

            Ok(WithAux::new((), D::unit()))
        }
    }

    /// Creates a [`CircuitObject`] from a [`StageMask`] via its [`RawCircuit`]
    /// impl.
    fn mask_circuit_object(
        mask: StageMask<R>,
    ) -> alloc::boxed::Box<dyn CircuitObject<Fp, R> + 'static> {
        let metrics = metrics::eval_raw::<Fp, _>(&mask).unwrap();
        into_raw_circuit_object::<Fp, _, R>(mask, metrics).unwrap()
    }

    impl<R: Rank> StageMask<R> {
        /// Returns the generator point for the `coefficient_index`-th $b$-wire
        /// coefficient of this stage.
        ///
        /// The $b$-wire at gate $j$ occupies degree $2n - 1 - j$ in the
        /// witness polynomial. The SYSTEM gate is included in `skip_gates`, so the
        /// first active gate is at index `skip_gates` and the formula
        /// becomes $2n - 1 - \text{skip\_gates} - \text{coefficient\_index}$.
        fn generator_for_b_coefficient<C: CurveAffine>(
            &self,
            generators: &impl FixedGenerators<C>,
            coefficient_index: usize,
        ) -> C {
            assert!(
                coefficient_index < self.num_gates,
                "coefficient_index {} exceeds num_gates {}",
                coefficient_index,
                self.num_gates
            );

            let idx = 2 * R::n() - 1 - self.skip_gates - coefficient_index;
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

        let rx1_a = MyStage1::rx(Fp::ZERO, endoscalar_a)?;
        let rx1_b = MyStage1::rx(Fp::ZERO, endoscalar_b)?;
        let rx2 = MyStage2::rx(Fp::ZERO, (p1, p2))?;

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
    fn test_skip_gates_one() {
        let stage_mask = StageMask::<R>::new(1, 5).unwrap();

        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        let sxy = stage_mask.sxy(x, y, &[]);
        let sx = stage_mask.sx(x, &[]);
        let sy = stage_mask.sy(y, &[]);

        assert_eq!(sxy, sx.eval(y));
        assert_eq!(sxy, sy.eval(x));
    }

    #[test]
    fn test_stage_mask_all_gates() {
        // Edge case: skip = 1, num = R::n() - 1, reserved = 0.
        let stage = StageMask::<R>::new(1, R::n() - 1).unwrap();
        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        let generic = mask_circuit_object(stage.clone());
        let plan = floor_planner::floor_plan(generic.segment_records());
        let stripped = crate::staging::bonding::Stripped::new(generic);
        let corrected_sxy = stripped.sxy(x, y, &plan);

        assert_eq!(stage.sxy(x, y, &[]), corrected_sxy);
        assert_eq!(corrected_sxy, stripped.sx(x, &plan).eval(y));
        assert_eq!(corrected_sxy, stripped.sy(y, &plan).eval(x));
    }

    #[test]
    fn test_root_routine_has_at_least_one_constraint() {
        // The root segment always gets the ONE constraint from
        // metrics::eval(), so its num_constraints must be at least 1.
        // This invariant prevents the `- 1` underflow in sy::eval's initial
        // y-power computation.
        let circuit = into_circuit_object::<_, _, R>(SquareCircuit { times: 0 }).unwrap();
        let floor_plan = floor_planner::floor_plan(circuit.segment_records());
        assert!(
            floor_plan[0].num_constraints >= 1,
            "root segment must have at least 1 constraint (ONE), got {}",
            floor_plan[0].num_constraints,
        );
    }

    #[test]
    fn test_stage_mask_exact_boundary() {
        let result = StageMask::<R>::new(R::n() - 1, 1);
        assert!(result.is_ok(), "Should accept skip + num == R::n()");

        let result = StageMask::<R>::new(R::n(), 1);
        assert!(result.is_err(), "Should reject skip + num > R::n()");
    }

    #[test]
    fn test_stage_mask_reserved_zero() {
        // When reserved = 0, all gates except the SYSTEM gate are active.
        let stage = StageMask::<R>::new(1, R::n() - 1).expect("valid stage mask");

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
        for skip in 1..10 {
            for num in 0..(R::n() - skip) {
                let _ = StageMask::<R>::new(skip, num).expect("valid stage mask");

                // The Circuit impl always issues 4n-2 enforce_zero
                // (with dummies for active gates and the SYSTEM gate).
                let num_constraints_from_gates = 4 * R::n() - 2;
                assert!(
                    num_constraints_from_gates < R::num_coeffs(),
                    "Reserved computation should not cause overflow"
                );
            }
        }
    }

    proptest! {
        #[test]
        fn test_exy_proptest(skip in 1..R::n(), num in 0..R::n()) {
            prop_assume!(skip + num <= R::n());

            let stage_mask = StageMask::<R>::new(skip, num).unwrap();

            let generic = mask_circuit_object(
                StageMask::<R>::new(skip, num).unwrap()
            );
            let plan = floor_planner::floor_plan(generic.segment_records());

            let stripped = crate::staging::bonding::Stripped::new(generic);

            let check = |x: Fp, y: Fp| {
                let sxy = stripped.sxy(x, y, &plan);
                let sx_eval = stripped.sx(x, &plan).eval(y);
                let sy_eval = stripped.sy(y, &plan).eval(x);

                // Internal consistency of the RawCircuit impl (with correction)
                prop_assert_eq!(sy_eval, sxy);
                prop_assert_eq!(sx_eval, sxy);
                // Match against the hand-written CircuitObject
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

        let rx = ConstrainedStage::rx(Fp::ZERO, valid_witness).unwrap();

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
        for skip in 1..10 {
            for num in 0..(R::n() - skip) {
                let stage_mask = StageMask::<R>::new(skip, num).unwrap();
                let (mul_from_method, linear_from_method) =
                    <StageMask<R> as CircuitObject<Fp, R>>::constraint_counts(&stage_mask);

                let metrics = metrics::eval_raw::<Fp, _>(&stage_mask).unwrap();

                assert_eq!(
                    mul_from_method, metrics.num_gates,
                    "gate count mismatch for skip={}, num={}",
                    skip, num
                );
                assert_eq!(
                    linear_from_method, metrics.num_constraints,
                    "constraint count mismatch for skip={}, num={}",
                    skip, num
                );
            }
        }
    }

    #[test]
    fn test_child_routine_zero_constraints() {
        // A routine that only uses a gate and no constraints.
        // This exercises the `.saturating_sub(1)` path in
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

        // The child routine (index 1) should have zero constraints.
        assert_eq!(
            floor_plan[1].num_constraints, 0,
            "MulOnlyRoutine should have 0 constraints"
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

    /// A stage that allocates values only in b-positions (d = 0) for challenge smuggling.
    ///
    /// Each value is paired with a zero to ensure it lands in a b-coefficient position
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
            // ensures challenges land in b-positions, zeros in d-positions.
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

    /// Tests that `StageMask::generator_for_b_coefficient` returns the generator
    /// at the index computed by `StageExt::generator_index_for_b`.
    #[test]
    fn test_generator_for_b_coefficient() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        // Test via StageMask directly
        let parent_mask = StageMask::<R>::new(
            ParentAOnlyStage::skip_gates(),
            ParentAOnlyStage::num_gates(),
        )
        .unwrap();

        for i in 0..3 {
            let gen_idx = <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_b(i);
            let expected_gen = generators.g()[gen_idx];
            let actual_gen = parent_mask.generator_for_b_coefficient(generators, i);
            assert_eq!(actual_gen, expected_gen);
        }

        let child_mask = StageMask::<R>::new(
            ChildOfParentAOnlyStage::skip_gates(),
            ChildOfParentAOnlyStage::num_gates(),
        )
        .unwrap();

        for i in 0..3 {
            let gen_idx = <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_b(i);
            let expected_gen = generators.g()[gen_idx];
            let actual_gen = child_mask.generator_for_b_coefficient(generators, i);
            assert_eq!(actual_gen, expected_gen);
        }
    }

    /// Tests the generator index formula `2n - 1 - skip - i` for both a root
    /// stage and a child stage with non-zero skip.
    #[test]
    fn test_generator_index_edge_cases() {
        assert_eq!(
            <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_b(0),
            2 * R::n() - 2
        );
        assert_eq!(
            <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_b(2),
            2 * R::n() - 4
        );
        assert_eq!(
            <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_b(0),
            2 * R::n() - 5
        );
        assert_eq!(
            <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_b(2),
            2 * R::n() - 7
        );
    }

    /// Tests that committing to an rx polynomial with values only in b-positions
    /// matches a manual MSM using generators from `generator_index_for_b`.
    #[test]
    fn test_b_wire_commitment_for_challenge_smuggling() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        let challenges = [Fp::from(42u64), Fp::from(123u64), Fp::from(456u64)];

        let rx: sparse::Polynomial<Fp, R> =
            ChildOfParentAOnlyStage::rx(Fp::ZERO, challenges).unwrap();
        let poly_commitment: EqAffine = rx.commit_to_affine(generators);

        let mut manual_commitment = EqAffine::identity();
        for (i, &challenge) in challenges.iter().enumerate() {
            let idx = <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_b(i);
            let b_gen = generators.g()[idx];
            let contrib = b_gen * challenge;
            manual_commitment = (manual_commitment.to_curve() + contrib).to_affine();
        }

        assert_eq!(
            poly_commitment, manual_commitment,
            "B-wire commitment should match manual computation"
        );
    }

    /// Same as above but for a root stage (no parent, zero skip).
    #[test]
    fn test_b_wire_commitment_via_staging_mechanism() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        let challenges = [Fp::from(42u64), Fp::from(123u64), Fp::from(456u64)];

        let rx: sparse::Polynomial<Fp, R> = ParentAOnlyStage::rx(Fp::ZERO, challenges).unwrap();
        let poly_commitment: EqAffine = rx.commit_to_affine(generators);

        // Manually compute expected commitment using StageExt::generator_index_for_b.
        let mut manual_commitment = EqAffine::identity();
        for (i, &challenge) in challenges.iter().enumerate() {
            let idx = <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_b(i);
            let b_gen = generators.g()[idx];
            manual_commitment = (manual_commitment.to_curve() + b_gen * challenge).to_affine();
        }

        assert_eq!(
            poly_commitment, manual_commitment,
            "Commitment via staging mechanism should match manual computation"
        );
    }
}
