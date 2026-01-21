use arithmetic::{CurveAffine, FixedGenerators};
use ff::Field;
use ragu_core::Result;

use alloc::vec::Vec;

use crate::{
    CircuitObject,
    polynomials::{Rank, structured, unstructured},
};

/// Represents a stage's polynomial structure.
#[derive(Clone)]
pub struct StageObject<R: Rank> {
    skip_multiplications: usize,
    num_multiplications: usize,
    _marker: core::marker::PhantomData<R>,
}

impl<R: Rank> StageObject<R> {
    /// Creates a new staging circuit polynomial with the given
    /// `skip_multiplications` and `num_multiplications` values. Witnesses that
    /// satisfy this circuit will have all non-`ONE` multiplication gate wires
    /// enforced to equal zero except for the
    /// `skip_multiplications..(skip_multiplications + num_multiplications)`
    /// multiplication gates.
    pub fn new(skip_multiplications: usize, num_multiplications: usize) -> Result<Self> {
        if skip_multiplications + num_multiplications + 1 > R::n() {
            return Err(ragu_core::Error::MultiplicationBoundExceeded(R::n()));
        }
        assert!(skip_multiplications + num_multiplications < R::n()); // Technically a redundant assertion.

        Ok(Self {
            skip_multiplications,
            num_multiplications,
            _marker: core::marker::PhantomData,
        })
    }

    /// Creates a new staging circuit polynomial with the given
    /// `skip_multiplications` and maximum possible multiplications.
    /// The number of multiplications will be `R::n() - skip_multiplications - 1`,
    /// which is the maximum before bounds are reached.
    pub fn new_max(skip_multiplications: usize) -> Result<Self> {
        if skip_multiplications + 1 > R::n() {
            return Err(ragu_core::Error::MultiplicationBoundExceeded(R::n()));
        }

        let num_multiplications = R::n() - skip_multiplications - 1;
        assert!(skip_multiplications + num_multiplications < R::n()); // Technically a redundant assertion.

        Ok(Self {
            skip_multiplications,
            num_multiplications,
            _marker: core::marker::PhantomData,
        })
    }

    /// Returns the number of skipped multiplications for this stage.
    pub fn skip_multiplications(&self) -> usize {
        self.skip_multiplications
    }

    /// Returns the number of active multiplications for this stage.
    pub fn num_multiplications(&self) -> usize {
        self.num_multiplications
    }

    /// Returns the generator index for the i-th A coefficient of this stage.
    pub fn generator_index_for_a(&self, coefficient_index: usize) -> usize {
        assert!(
            coefficient_index < self.num_multiplications,
            "coefficient_index {} exceeds num_multiplications {}",
            coefficient_index,
            self.num_multiplications
        );

        2 * R::n() + 1 + self.skip_multiplications + coefficient_index
    }

    /// Returns the generator point for the i-th A coefficient of this stage.
    pub fn generator_for_a_coefficient<C: CurveAffine>(
        &self,
        generators: &impl FixedGenerators<C>,
        coefficient_index: usize,
    ) -> C {
        let idx = self.generator_index_for_a(coefficient_index);
        generators.g()[idx]
    }
}

impl<F: Field, R: Rank> CircuitObject<F, R> for StageObject<R> {
    fn sxy(&self, x: F, y: F, key: F) -> F {
        // Bound is enforced in `StageObject::new`.
        assert!(self.skip_multiplications + self.num_multiplications < R::n());
        let reserved: usize = R::n() - self.skip_multiplications - self.num_multiplications - 1;

        if x == F::ZERO || y == F::ZERO {
            // If either x or y is zero, the polynomial evaluates to zero. This
            // is unlike standard circuits because the constant term is not used
            // to constrain the `ONE` wire.
            return F::ZERO;
        }

        let x_inv = x.invert().expect("x is not zero");
        let y2 = y.square();
        let y3 = y * y2;
        let x_y3 = x * y3;
        let xinv_y3 = x_inv * y3;

        // Placeholder contribution: Y^(q+1) * (X^(2n-1) - K *X^(4n-1)).
        let num_linear_from_gates = 3 * (self.skip_multiplications + reserved);
        let y_power = y.pow_vartime([(num_linear_from_gates + 1) as u64]);
        let x_2n_minus_1 = x.pow_vartime([(2 * R::n() - 1) as u64]);
        let x_4n_minus_1 = x.pow_vartime([(4 * R::n() - 1) as u64]);
        let placeholder = y_power * (x_2n_minus_1 - key * x_4n_minus_1);

        let block = |end: usize, len: usize| -> F {
            let w = y * x.pow_vartime([(4 * R::n() - 2 - end) as u64]);
            let v = y2 * x.pow_vartime([(2 * R::n() + 1 + end) as u64]);
            let u = y3 * x.pow_vartime([(2 * R::n() - 2 - end) as u64]);

            let plus = arithmetic::geosum::<F>(x_y3, len);
            let minus = arithmetic::geosum::<F>(xinv_y3, len);

            w * plus + v * minus + u * plus
        };

        // Handle the edge case where skip_multiplications is zero.
        let c1 = if self.skip_multiplications > 0 {
            block(self.skip_multiplications - 1, self.skip_multiplications)
        } else {
            F::ZERO
        };
        let c2 = block(R::n() - 2, reserved);

        placeholder + y.pow_vartime([(3 * reserved) as u64]) * c1 + c2
    }

    fn sx(&self, x: F, key: F) -> unstructured::Polynomial<F, R> {
        // Bound is enforced in `StageObject::new`.
        assert!(self.skip_multiplications + self.num_multiplications < R::n());
        let reserved: usize = R::n() - self.skip_multiplications - self.num_multiplications - 1;

        if x == F::ZERO {
            return unstructured::Polynomial::new();
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

            // Placeholder contribution: x^(2n-1) - k * x^(4n-1).
            let (key_wire, _, one) = alloc();
            coeffs.push(key_wire - key * one);

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

        unstructured::Polynomial::from_coeffs(coeffs)
    }

    fn sy(&self, y: F, key: F) -> structured::Polynomial<F, R> {
        // Bound is enforced in `StageObject::new`.
        assert!(self.skip_multiplications + self.num_multiplications < R::n());
        let reserved: usize = R::n() - self.skip_multiplications - self.num_multiplications - 1;

        let mut poly = structured::Polynomial::new();
        if y == F::ZERO {
            return poly;
        }

        let num_linear_from_gates = 3 * (reserved + self.skip_multiplications);
        let mut yq = y.pow_vartime([(num_linear_from_gates + 1) as u64]);
        let y_inv = y.invert().expect("y is not zero");

        {
            let poly = poly.backward();

            // Placeholder contribution: Y^q - k * Y^q.
            poly.a.push(yq);
            poly.b.push(F::ZERO);
            poly.c.push(-key * yq);
            yq *= y_inv;

            for _ in 0..self.skip_multiplications {
                poly.a.push(yq);
                yq *= y_inv;
                poly.b.push(yq);
                yq *= y_inv;
                poly.c.push(yq);
                yq *= y_inv;
            }
            for _ in 0..self.num_multiplications {
                poly.a.push(F::ZERO);
                poly.b.push(F::ZERO);
                poly.c.push(F::ZERO);
            }
            for _ in 0..reserved {
                poly.a.push(yq);
                yq *= y_inv;
                poly.b.push(yq);
                yq *= y_inv;
                poly.c.push(yq);
                yq *= y_inv;
            }
        }

        poly
    }

    fn constraint_counts(&self) -> (usize, usize) {
        let num_multiplication_constraints = R::n();
        let num_linear_constraints = 3 * (R::n() - self.num_multiplications - 1) + 2;
        (num_multiplication_constraints, num_linear_constraints)
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use arithmetic::{Coeff, Cycle, FixedGenerators, Uendo};
    use ff::Field;
    use group::{Curve, prime::PrimeCurveAffine};
    use proptest::prelude::*;
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue, LinearExpression, emulator::Emulator},
        gadgets::{Gadget, GadgetKind},
        maybe::Maybe,
    };
    use ragu_pasta::{EpAffine, EqAffine, Fp, Fq, Pasta};
    use ragu_primitives::{Element, Endoscalar, Point};
    use rand::{Rng, thread_rng};

    use crate::{
        CircuitExt, CircuitObject, metrics,
        polynomials::{Rank, structured},
        s::sy,
        staging::StageBuilder,
        tests::SquareCircuit,
    };

    use super::{
        super::{Stage, StageExt},
        StageObject,
    };

    impl<F: Field, R: Rank> crate::Circuit<F> for StageObject<R> {
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            _: &mut D,
            _: DriverValue<D, Self::Instance<'source>>,
        ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
            Ok(())
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            dr: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<(
            <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
            DriverValue<D, Self::Aux<'source>>,
        )> {
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

            Ok(((), D::just(|| ())))
        }
    }

    type R = crate::polynomials::R<13>;

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
            ) -> Result<<Self::OutputKind as GadgetKind<Fp>>::Rebind<'dr, D>>
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
            ) -> Result<<Self::OutputKind as GadgetKind<Fp>>::Rebind<'dr, D>>
            where
                Self: 'dr,
            {
                let a = Point::alloc(dr, witness.view().map(|w| w.0))?;
                let b = Point::alloc(dr, witness.view().map(|w| w.1))?;

                Ok((a, b))
            }
        }

        let endoscalar_a: Uendo = thread_rng().r#gen();
        let endoscalar_b: Uendo = thread_rng().r#gen();
        let p1 = (EpAffine::generator() * Fq::random(thread_rng())).into();
        let p2 = (EpAffine::generator() * Fq::random(thread_rng())).into();

        let rx1_a = MyStage1::rx(endoscalar_a)?;
        let rx1_b = MyStage1::rx(endoscalar_b)?;
        let rx2 = MyStage2::rx((p1, p2))?;

        let circ1 = MyStage1::into_object()?;
        let circ2 = MyStage2::into_object()?;

        let z = Fp::random(thread_rng());
        let y = Fp::random(thread_rng());
        let k = Fp::random(thread_rng());

        {
            let rhs = circ1.sy(y, k);
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

        assert_eq!(rx1_a.revdot(&circ1.sy(y, k)), Fp::ZERO);
        assert_eq!(rx2.revdot(&circ2.sy(y, k)), Fp::ZERO);
        assert!(rx1_a.revdot(&circ2.sy(y, k)) != Fp::ZERO);
        assert!(rx2.revdot(&circ1.sy(y, k)) != Fp::ZERO);

        Ok(())
    }

    #[test]
    fn test_skip_multiplications_zero() {
        let stage_object = StageObject::<R>::new(0, 5).unwrap();

        let x = Fp::random(thread_rng());
        let y = Fp::random(thread_rng());
        let k = Fp::random(thread_rng());

        let sxy = stage_object.sxy(x, y, k);
        let sx = stage_object.sx(x, k);
        let sy = stage_object.sy(y, k);

        assert_eq!(sxy, sx.eval(y));
        assert_eq!(sxy, sy.eval(x));
    }

    #[test]
    fn test_stage_object_all_multiplications() {
        // Edge case: skip = 0, num = R::n() - 1, reserved = 0.
        let stage = StageObject::<R>::new(0, R::n() - 1).unwrap();
        let x = Fp::random(thread_rng());
        let y = Fp::random(thread_rng());
        let k = Fp::random(thread_rng());

        let comparison = stage.clone().into_object::<R>().unwrap();

        let xn_minus_1 = x.pow_vartime([(4 * R::n() - 1) as u64]);
        let comparison_sxy = comparison.sxy(x, y, k) - xn_minus_1;

        assert_eq!(stage.sxy(x, y, k), comparison_sxy);
    }

    #[test]
    fn test_placeholder_constraint_with_zero_k() {
        // We should verify the polynomial evaluations are consistent even when k = 0
        // (which would make the circuit unsatisfiable), but we gauard against this
        // during mesh finalization.
        let circuit = SquareCircuit { times: 2 };
        let y = Fp::random(thread_rng());
        let k = Fp::ZERO;

        let circuit_obj = circuit.into_object::<R>().unwrap();
        let x = Fp::random(thread_rng());
        let sxy_result = circuit_obj.sy(y, k).eval(x);
        let sxy_direct = circuit_obj.sxy(x, y, k);
        assert_eq!(
            sxy_result, sxy_direct,
            "sy.eval(x) should match sxy(x, y, k) even with k = 0"
        );
    }

    #[test]
    fn test_minimum_linear_constraints() {
        let circuit = SquareCircuit { times: 2 };
        let y = Fp::random(thread_rng());
        let k = Fp::random(thread_rng());

        let metrics = metrics::eval(&circuit).expect("metrics should succeed");
        let mut sy = sy::eval::<_, _, R>(&circuit, y, k, metrics.num_linear_constraints)
            .expect("sy() evaluation should succeed");

        // The first gate (ONE gate) should have the highest y-power.
        let expected_y_power = metrics.num_linear_constraints - 1;
        let actual_first_coeff = sy.backward().a[0];
        let expected_first_coeff = y.pow_vartime([expected_y_power as u64]);

        // This verifies the y-power calculation is correct
        assert_eq!(
            actual_first_coeff, expected_first_coeff,
            "First coefficient should have correct y-power"
        );
    }

    #[test]
    fn test_stage_object_exact_boundary() {
        let result = StageObject::<R>::new(R::n() - 2, 1);
        assert!(result.is_ok(), "Should accept skip + num + 1 == R::n()");

        let result = StageObject::<R>::new(R::n() - 1, 1);
        assert!(result.is_err(), "Should reject skip + num + 1 > R::n()");
    }

    #[test]
    fn test_stage_object_reserved_zero() {
        // When reserved = 0, all gates except one are used.
        let stage = StageObject::<R>::new(0, R::n() - 1).expect("skip multiplications");

        let x = Fp::random(thread_rng());
        let y = Fp::random(thread_rng());
        let k = Fp::random(thread_rng());

        let sxy = stage.sxy(x, y, k);
        let sx = stage.sx(x, k);
        let sy = stage.sy(y, k);

        assert_eq!(sxy, sx.eval(y));
        assert_eq!(sxy, sy.eval(x));
    }

    #[test]
    fn test_stage_object_reserved_computation() {
        // Check we're computing reserved correctly.
        for skip in 0..10 {
            for num in 0..(R::n() - skip - 1) {
                let _ = StageObject::<R>::new(skip, num).expect("skip multiplications");
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

            let stage_object = StageObject::<R>::new(skip, num).unwrap();
            let comparison_object = stage_object.clone().into_object::<R>().unwrap();

            let k = Fp::random(thread_rng());

            let check = |x: Fp, y: Fp| {
                let xn_minus_1 = x.pow_vartime([(4 * R::n() - 1) as u64]);

                // This adjusts for the single "ONE" constraint which is always skipped
                // in staging witnesses.
                let sxy = comparison_object.sxy(x, y, k) - xn_minus_1;
                let mut sx = comparison_object.sx(x, k);
                {
                    sx[0] -= xn_minus_1;
                }
                let mut sy = comparison_object.sy(y, k);
                {
                    let sy = sy.backward();
                    sy.c[0] -= Fp::ONE;
                }

                prop_assert_eq!(sy.eval(x), sxy);
                prop_assert_eq!(sx.eval(y), sxy);
                prop_assert_eq!(stage_object.sxy(x, y, k), sxy);
                prop_assert_eq!(stage_object.sx(x, k).eval(y), sxy);
                prop_assert_eq!(stage_object.sy(y, k).eval(x), sxy);

                Ok(())
            };

            let x = Fp::random(thread_rng());
            let y = Fp::random(thread_rng());
            check(x, y)?;
            check(Fp::ZERO, y)?;
            check(x, Fp::ZERO)?;
            check(Fp::ZERO, Fp::ZERO)?;

        }
    }

    #[derive(Default)]
    struct ConstrainedStage;

    #[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write)]
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
        ) -> Result<<Self::OutputKind as GadgetKind<Fp>>::Rebind<'dr, D>>
        where
            Self: 'dr,
        {
            let witness_a = witness.view().map(|w| w.0);
            let witness_b = witness.view().map(|w| w.1);

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

        let stage_obj = ConstrainedStage::into_object::<'_>().unwrap();

        // rx.revdot(&stage_object) == 0 for well-formed stages
        let y = Fp::random(thread_rng());
        let k = Fp::ONE;
        let sy = stage_obj.sy(y, k);

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
                let stage_object = StageObject::<R>::new(skip, num).unwrap();
                let (mul_from_method, linear_from_method) =
                    <StageObject<R> as CircuitObject<Fp, R>>::constraint_counts(&stage_object);

                let metrics = metrics::eval::<Fp, _>(&stage_object).unwrap();

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
    fn test_generator_for_a_coefficient() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        let stage = StageObject::<R>::new(2, 4).unwrap();

        for i in 0..4 {
            let gen_idx = stage.generator_index_for_a(i);
            let expected_gen = generators.g()[gen_idx];
            let actual_gen = stage.generator_for_a_coefficient(generators, i);
            assert_eq!(actual_gen, expected_gen);
        }
    }

    #[test]
    fn test_a_only_commitment_for_challenge_smuggling() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        let stage = StageObject::<R>::new(1, 3).unwrap();
        let blind = Fp::ZERO;

        let challenges = [Fp::from(42u64), Fp::from(123u64), Fp::from(456u64)];
        let mut rx: structured::Polynomial<Fp, R> = structured::Polynomial::new();
        {
            let rx = rx.forward();

            rx.a.push(Fp::ZERO);
            rx.b.push(Fp::ZERO);
            rx.c.push(Fp::ZERO);

            rx.a.push(Fp::ZERO);
            rx.b.push(Fp::ZERO);
            rx.c.push(Fp::ZERO);

            for &challenge in &challenges {
                rx.a.push(challenge);
                rx.b.push(Fp::ZERO);
                rx.c.push(Fp::ZERO);
            }
        }

        let poly_commitment: EqAffine = rx.commit(generators, blind);

        let mut manual_commitment = EqAffine::identity();
        for (i, &challenge) in challenges.iter().enumerate() {
            let a_gen = stage.generator_for_a_coefficient(generators, i);
            let contrib = a_gen * challenge;
            manual_commitment = (manual_commitment.to_curve() + contrib).to_affine();
        }

        assert_eq!(
            poly_commitment, manual_commitment,
            "A-only commitment should match for challenge smuggling"
        );
    }

    /// A stage that allocates values only in a-positions (b = 0) for challenge smuggling.
    ///
    /// Each value is paired with a zero to ensure it lands in an a-coefficient position
    /// when the polynomial is built. This mimics the pattern used for smuggling challenges.
    #[derive(Default)]
    struct AOnlyStage;

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

    impl Stage<Fp, R> for AOnlyStage {
        type Parent = ();
        type Witness<'source> = [Fp; 3];
        type OutputKind = <ThreeAOnlyElements<'static, PhantomData<Fp>> as Gadget<
            'static,
            PhantomData<Fp>,
        >>::Kind;

        fn values() -> usize {
            6 // 3 values + 3 zeros = 6 values = 3 multiplication gates
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<<Self::OutputKind as GadgetKind<Fp>>::Rebind<'dr, D>>
        where
            Self: 'dr,
        {
            // Allocate each challenge value followed by zero, which
            // ensures challenges land in a-positions, zeros in b-positions.
            let a0 = Element::alloc(dr, witness.view().map(|w| w[0]))?;
            let b0 = Element::zero(dr);
            let a1 = Element::alloc(dr, witness.view().map(|w| w[1]))?;
            let b1 = Element::zero(dr);
            let a2 = Element::alloc(dr, witness.view().map(|w| w[2]))?;
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

    #[test]
    fn test_a_only_commitment_via_staging_mechanism() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        let challenges = [Fp::from(42u64), Fp::from(123u64), Fp::from(456u64)];
        let blind = Fp::ZERO;

        // Use the actual staging mechanism to build rx.
        let rx: structured::Polynomial<Fp, R> = AOnlyStage::rx(challenges).unwrap();
        let poly_commitment: EqAffine = rx.commit(generators, blind);

        // Build `StageObject` with matching parameters.
        let skip = AOnlyStage::skip_multiplications(); // 0 for root stage
        let num = <AOnlyStage as StageExt<Fp, R>>::num_multiplications(); // ceil(6/2) = 3
        let stage_obj = StageObject::<R>::new(skip, num).unwrap();

        // Manually compute expected commitment using generator_for_a_coefficient.
        let mut manual_commitment = EqAffine::identity();
        for (i, &challenge) in challenges.iter().enumerate() {
            let a_gen = stage_obj.generator_for_a_coefficient(generators, i);
            manual_commitment = (manual_commitment.to_curve() + a_gen * challenge).to_affine();
        }

        assert_eq!(
            poly_commitment, manual_commitment,
            "Commitment via staging mechanism should match manual computation"
        );
    }
}
