use arithmetic::{Coeff, CurveAffine};
use ff::{Field, WithSmallOrderMulGroup};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::Gadget,
    maybe::Maybe,
};

use core::marker::PhantomData;

use crate::{Boolean, Element, io::Write};

/// Represents an affine point on a curve defined over the circuit's field.
#[derive(Gadget, Write)]
pub struct Point<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    x: Element<'dr, D>,
    #[ragu(gadget)]
    y: Element<'dr, D>,
    #[ragu(phantom)]
    _marker: PhantomData<C>,
}

impl<'dr, D: Driver<'dr, F = C::Base>, C: CurveAffine> Point<'dr, D, C> {
    /// Creates a new `Point` from the given coordinates without checking
    /// that the provided $x, y$ are on the curve.
    fn new_unchecked(x: Element<'dr, D>, y: Element<'dr, D>) -> Self {
        Point {
            x,
            y,
            _marker: PhantomData,
        }
    }

    /// Allocate a point on the curve. This will return an error if the provided
    /// point is at infinity.
    pub fn alloc(dr: &mut D, p: DriverValue<D, C>) -> Result<Self> {
        let coordinates = D::with(|| {
            let coordinates = p.take().coordinates().into_option();
            coordinates.ok_or_else(|| {
                Error::InvalidWitness("point at infinity cannot be witnessed".into())
            })
        })?;

        let (x, x2) = Element::alloc_square(dr, coordinates.view().map(|p| *p.x()))?;
        let x3 = x.mul(dr, &x2)?;
        let (y, y2) = Element::alloc_square(dr, coordinates.view().map(|p| *p.y()))?;

        // x^3 + b - y^2 = 0
        dr.enforce_zero(|lc| {
            lc.add(x3.wire())
                .add_term(&D::ONE, Coeff::Arbitrary(C::b()))
                .sub(y2.wire())
        })?;

        Ok(Point::new_unchecked(x, y))
    }

    /// Obtain a constant point in the circuit. Fails if the point is the
    /// identity.
    pub fn constant(dr: &mut D, p: C) -> Result<Self> {
        if let Some(coordinates) = p.coordinates().into_option() {
            let x = Element::constant(dr, *coordinates.x());
            let y = Element::constant(dr, *coordinates.y());

            Ok(Point::new_unchecked(x, y))
        } else {
            Err(Error::InvalidWitness(
                "point at infinity cannot be witnessed".into(),
            ))
        }
    }

    /// Returns the point represented by this gadget.
    pub fn value(&self) -> DriverValue<D, C> {
        D::just(|| {
            let x = *self.x.value().take();
            let y = *self.y.value().take();
            C::from_xy(x, y).expect("must be valid affine point on curve")
        })
    }

    /// Applies the endomorphism to this point.
    pub fn endo(&self, dr: &mut D) -> Result<Self> {
        let x = self.x.scale(dr, Coeff::Arbitrary(C::Base::ZETA));
        Ok(Point::new_unchecked(x, self.y.clone()))
    }

    /// Negates this point.
    pub fn negate(&self, dr: &mut D) -> Self {
        Point {
            x: self.x.clone(),
            y: self.y.negate(dr),
            _marker: PhantomData,
        }
    }

    /// Apply the endomorphism iff the provided condition is true.
    pub fn conditional_endo(&self, dr: &mut D, condition: &Boolean<'dr, D>) -> Result<Self> {
        // x' = x + (x(ZETA - 1)) * condition
        let tmp = self
            .x
            .scale(dr, Coeff::Arbitrary(D::F::ZETA - D::F::ONE))
            .mul(dr, &condition.element())?;
        Ok(Point::new_unchecked(self.x.add(dr, &tmp), self.y.clone()))
    }

    /// Apply the negation map iff the provided condition is true.
    pub fn conditional_negate(&self, dr: &mut D, condition: &Boolean<'dr, D>) -> Result<Self> {
        // y' = y + (y(-2)) * condition
        let tmp = self
            .y
            .scale(dr, Coeff::Arbitrary(-D::F::from(2)))
            .mul(dr, &condition.element())?;
        Ok(Point::new_unchecked(self.x.clone(), self.y.add(dr, &tmp)))
    }

    /// Doubles this point. Ragu does not support curves with points of order
    /// two, and thus all affine points have affine doubles.
    pub fn double(&self, dr: &mut D) -> Result<Self> {
        // delta = 3x^2 / 2y
        let double_y = self.y.double(dr);
        let delta = self
            .x
            .square(dr)?
            .scale(dr, Coeff::Arbitrary(D::F::from(3)))
            .div_nonzero(dr, &double_y)?;

        // x3 = delta^2 - 2x
        let double_x = self.x.double(dr);
        let x3 = delta.square(dr)?.sub(dr, &double_x);

        // y3 = delta * (x - x3) - y
        let x_sub_x3 = self.x.sub(dr, &x3);
        let y3 = delta.mul(dr, &x_sub_x3)?.sub(dr, &self.y);

        Ok(Point::new_unchecked(x3, y3))
    }

    /// Adds two points with different x-coordinates.
    ///
    /// If you cannot guarantee `x_0 != x_1` up front, pass `Some(acc)` via
    /// `nonzero`. On each call, `*acc` is multiplied by `x_1 - x_0`. After
    /// processing a batch of additions, [invert](Element::invert) `*acc` once;
    /// inversion succeeds iff every `x_1 - x_0 != 0`, thereby certifying that
    /// all pairs had distinct x-coordinates.
    pub fn add_incomplete(
        &self,
        dr: &mut D,
        other: &Self,
        nonzero: Option<&mut Element<'dr, D>>,
    ) -> Result<Self> {
        // delta = (y1 - y0) / (x1 - x0)
        let tmp = other.x.sub(dr, &self.x);
        if let Some(nonzero) = nonzero {
            *nonzero = nonzero.mul(dr, &tmp)?;
        }
        let delta = other.y.sub(dr, &self.y).div_nonzero(dr, &tmp)?;

        // x3 = delta^2 - x0 - x1
        let x3 = delta.square(dr)?.sub(dr, &self.x).sub(dr, &other.x);

        // y3 = delta * (x0 - x3) - y0
        let tmp = self.x.sub(dr, &x3);
        let y3 = delta.mul(dr, &tmp)?.sub(dr, &self.y);

        Ok(Point {
            x: x3,
            y: y3,
            _marker: PhantomData,
        })
    }

    /// Computes $\[2\] Q + P$. **The caller must ensure that $P$ and $Q$ do not
    /// have the same x-coordinate and that the result is not the identity.**
    pub fn double_and_add_incomplete(&self, dr: &mut D, other: &Self) -> Result<Self> {
        // See <https://github.com/zcash/zcash/issues/3924> for an explanation.

        // lambda_1 = (y_q - y_p)/(x_q - x_p)
        let tmp = other.x.sub(dr, &self.x);
        let lambda_1 = other.y.sub(dr, &self.y).div_nonzero(dr, &tmp)?;

        // x_r = lambda_1^2 - x_p - x_q
        let x_r = lambda_1.square(dr)?.sub(dr, &self.x).sub(dr, &other.x);

        // lambda_2 = 2 y_p /(x_p - x_r) - lambda_1
        let tmp = self.x.sub(dr, &x_r);
        let lambda_2 = self.y.double(dr).div_nonzero(dr, &tmp)?.sub(dr, &lambda_1);

        // x_s = lambda_2^2 - x_r - x_p
        let x_s = lambda_2.square(dr)?.sub(dr, &x_r).sub(dr, &self.x);

        // y_s = lambda_2 (x_p - x_s) - y_p
        let tmp = self.x.sub(dr, &x_s);
        let y_s = lambda_2.mul(dr, &tmp)?.sub(dr, &self.y);

        Ok(Point {
            x: x_s,
            y: y_s,
            _marker: PhantomData,
        })
    }
}

#[test]
fn test_point_alloc() -> Result<()> {
    use group::prime::PrimeCurveAffine;

    type F = ragu_pasta::Fp;
    type C = ragu_pasta::EpAffine;
    type Simulator = crate::Simulator<F>;

    let alloc = |point: C| {
        Simulator::simulate(point, |dr, point| {
            Point::alloc(dr, point.clone())?;

            Ok(())
        })
    };

    alloc(C::generator())?;
    assert!(alloc(C::identity()).is_err());

    Ok(())
}

#[test]
fn test_point_double() -> Result<()> {
    use group::{Group, prime::PrimeCurveAffine};

    type F = ragu_pasta::Fp;
    type C = ragu_pasta::EpAffine;
    type Simulator = crate::Simulator<F>;

    let double = |point: C| {
        let sim = Simulator::simulate(point, |dr, point| {
            let p = Point::alloc(dr, point.clone())?;
            dr.reset();
            let q = p.double(dr)?;
            assert_eq!(
                point.take().to_curve().double(),
                C::from_xy(*q.x.value().take(), *q.y.value().take())
                    .unwrap()
                    .into()
            );

            Ok(())
        })?;

        assert_eq!(sim.num_allocations(), 0);
        assert_eq!(sim.num_multiplications(), 4);
        assert_eq!(sim.num_linear_constraints(), 8);
        Ok(())
    };

    double(C::generator())?;

    Ok(())
}

#[test]
fn test_add_incomplete() -> Result<()> {
    use alloc::vec;
    use arithmetic::CurveExt;
    use group::{Group, prime::PrimeCurveAffine};

    type F = ragu_pasta::Fp;
    type C = ragu_pasta::EpAffine;
    type Simulator = crate::Simulator<F>;

    let generator = C::generator();

    let points = vec![
        generator,
        -generator,
        generator.to_curve().endo().into(),
        (-generator.to_curve().endo()).into(),
        generator.to_curve().double().into(),
        (-generator.to_curve().double()).into(),
        generator.to_curve().double().endo().into(),
    ];

    for p in &points {
        for q in &points {
            let sim = Simulator::simulate((*p, *q), |dr, witness| {
                let (p, q) = witness.cast();
                let p_gadget = Point::alloc(dr, p.clone())?;
                let q_gadget = Point::alloc(dr, q.clone())?;
                dr.reset();
                let r_gadget = p_gadget.add_incomplete(dr, &q_gadget, None)?;
                let expected = p.take().to_curve() + q.take().to_curve();
                let expected_affine =
                    C::from_xy(*r_gadget.x.value().take(), *r_gadget.y.value().take()).unwrap();
                assert_eq!(expected_affine, expected.into());
                Ok(())
            });

            if p.coordinates().unwrap().x() == q.coordinates().unwrap().x() {
                assert!(sim.is_err());
            } else {
                let sim = sim?;
                assert_eq!(sim.num_allocations(), 0);
                assert_eq!(sim.num_multiplications(), 3);
                assert_eq!(sim.num_linear_constraints(), 6);
            }
        }
    }

    Ok(())
}

#[test]
fn test_double_and_add_incomplete() -> Result<()> {
    use alloc::vec;
    use alloc::vec::Vec;
    use arithmetic::CurveExt;
    use group::{Group, prime::PrimeCurveAffine};

    type F = ragu_pasta::Fp;
    type C = ragu_pasta::EpAffine;
    type Simulator = crate::Simulator<F>;

    let generator = C::generator();

    let points: Vec<C> = vec![
        generator,
        generator.to_curve().double().into(),
        -generator,
        (-generator.to_curve().double()).into(),
        (-generator.to_curve().double().double()).into(),
        generator,
        generator.to_curve().endo().into(),
        (-generator.to_curve().endo()).into(),
    ];

    for p in &points {
        for q in &points {
            let sim = Simulator::simulate((*p, *q), |dr, witness| {
                let (p, q) = witness.cast();
                let p_gadget = Point::alloc(dr, p.clone())?;
                let q_gadget = Point::alloc(dr, q.clone())?;
                dr.reset();
                let r_gadget = p_gadget.double_and_add_incomplete(dr, &q_gadget)?;
                let expected = p.take().to_curve().double() + q.take().to_curve();
                let expected_affine =
                    C::from_xy(*r_gadget.x.value().take(), *r_gadget.y.value().take()).unwrap();
                assert_eq!(expected_affine, expected.into());
                Ok(())
            });

            if p.coordinates().unwrap().x() == q.coordinates().unwrap().x()
                || (p.to_curve().double() + q.to_curve()).is_identity().into()
            {
                assert!(sim.is_err());
            } else {
                let sim = sim?;
                assert_eq!(sim.num_allocations(), 0);
                assert_eq!(sim.num_multiplications(), 5);
                assert_eq!(sim.num_linear_constraints(), 10);
            }
        }
    }
    Ok(())
}
