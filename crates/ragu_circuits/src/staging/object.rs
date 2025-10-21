use ff::Field;
use ragu_core::Result;

use alloc::vec::Vec;

use crate::{
    CircuitObject,
    polynomials::{Rank, structured, unstructured},
};

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
}

impl<F: Field, R: Rank> CircuitObject<F, R> for StageObject<R> {
    fn sxy(&self, x: F, y: F) -> F {
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

        y.pow_vartime([(3 * reserved) as u64]) * c1 + c2
    }

    fn sx(&self, x: F) -> unstructured::Polynomial<F, R> {
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

            let mut enforce_zero = |out: (F, F, F)| {
                coeffs.push(out.0);
                coeffs.push(out.1);
                coeffs.push(out.2);
            };

            alloc(); // ONE

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

    fn sy(&self, y: F) -> structured::Polynomial<F, R> {
        // Bound is enforced in `StageObject::new`.
        assert!(self.skip_multiplications + self.num_multiplications < R::n());
        let reserved: usize = R::n() - self.skip_multiplications - self.num_multiplications - 1;

        let mut poly = structured::Polynomial::new();
        if y == F::ZERO {
            return poly;
        }

        let mut yq = y.pow_vartime([(3 * (reserved + self.skip_multiplications)) as u64]);
        let y_inv = y.invert().expect("y is not zero");

        {
            let poly = poly.backward();

            // ONE
            poly.a.push(F::ZERO);
            poly.b.push(F::ZERO);
            poly.c.push(F::ZERO);

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
}

#[cfg(test)]
mod tests {
    use arithmetic::{Coeff, Uendo};
    use ff::Field;
    use group::prime::PrimeCurveAffine;
    use proptest::prelude::*;
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue, LinearExpression},
        gadgets::GadgetKind,
        maybe::Maybe,
    };
    use ragu_pasta::{EpAffine, Fp, Fq};
    use ragu_primitives::{Endoscalar, Point};
    use rand::{Rng, thread_rng};

    use crate::{CircuitExt, CircuitObject, polynomials::Rank};

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
        struct MyStage1;
        struct MyStage2;

        impl Stage<Fp, R> for MyStage1 {
            type Parent = ();

            fn values() -> usize {
                Uendo::BITS as usize
            }

            type Witness<'source> = Uendo;
            type OutputKind = Endoscalar<'static, core::marker::PhantomData<Fp>>;

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
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

        let endoscalar: Uendo = thread_rng().r#gen();
        let p1 = (EpAffine::generator() * Fq::random(thread_rng())).into();
        let p2 = (EpAffine::generator() * Fq::random(thread_rng())).into();

        let rx1 = MyStage1::rx(endoscalar)?;
        let rx2 = MyStage2::rx((p1, p2))?;

        let circ1 = MyStage1::into_object()?;
        let circ2 = MyStage2::into_object()?;

        let z = Fp::random(thread_rng());
        let y = Fp::random(thread_rng());

        {
            let mut rhs = rx1.clone();
            rhs.dilate(z);
            rhs.add_assign(&circ1.sy(y));
            rhs.add_assign(&R::tz(z));
            assert_eq!(rx1.revdot(&rhs), Fp::ZERO);
        }

        assert_eq!(rx1.revdot(&circ1.sy(y)), Fp::ZERO);
        assert_eq!(rx2.revdot(&circ2.sy(y)), Fp::ZERO);
        assert!(rx1.revdot(&circ2.sy(y)) != Fp::ZERO);
        assert!(rx2.revdot(&circ1.sy(y)) != Fp::ZERO);

        Ok(())
    }

    #[test]
    fn test_skip_multiplications_zero() {
        let stage_object = StageObject::<R>::new(0, 5).unwrap();

        let x = Fp::random(thread_rng());
        let y = Fp::random(thread_rng());

        let sxy = stage_object.sxy(x, y);
        let sx = stage_object.sx(x);
        let sy = stage_object.sy(y);

        assert_eq!(sxy, sx.eval(y));
        assert_eq!(sxy, sy.eval(x));
    }

    proptest! {
        #[test]
        fn test_exy_proptest(skip in 0..R::n(), num in 0..R::n()) {
            prop_assume!(skip + 1 + num <= R::n());

            let stage_object = StageObject::<R>::new(skip, num).unwrap();
            let comparison_object = stage_object.clone().into_object::<R>().unwrap();

            let check = |x: Fp, y: Fp| {
                let xn_minus_1 = x.pow_vartime([(4 * R::n() - 1) as u64]);

                // This adjusts for the single "ONE" constraint which is always skipped
                // in staging witnesses.
                let sxy = comparison_object.sxy(x, y) - xn_minus_1;
                let mut sx = comparison_object.sx(x);
                {
                    sx[0] -= xn_minus_1;
                }
                let mut sy = comparison_object.sy(y);
                {
                    let sy = sy.backward();
                    sy.c[0] -= Fp::ONE;
                }

                prop_assert_eq!(sy.eval(x), sxy);
                prop_assert_eq!(sx.eval(y), sxy);
                prop_assert_eq!(stage_object.sxy(x, y), sxy);
                prop_assert_eq!(stage_object.sx(x).eval(y), sxy);
                prop_assert_eq!(stage_object.sy(y).eval(x), sxy);

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
}
