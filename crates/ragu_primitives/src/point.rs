//! Elliptic curve point gadget for in-circuit curve operations.
//!
//! Provides the [`Point`] type representing an affine curve point with
//! constrained coordinates for in-circuit elliptic curve arithmetic. See
//! [`Point`] for the full list of supported curve assumptions.

use alloc::boxed::Box;
use core::marker::PhantomData;

use ragu_arithmetic::{Coeff, CurveAffine, ff::WithSmallOrderMulGroup};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::Gadget,
    maybe::Maybe,
};

use crate::{
    Boolean, Element, Nonzero, NonzeroBank, comparison::GadgetEquals, consistent::Consistent,
    io::Write,
};

/// An error indicating that a point is the identity (the point at infinity).
///
/// [`Point::alloc`] and [`Point::constant`] box this type as the source of
/// [`Error::InvalidWitness`] when the input point is the identity, which has
/// no affine coordinates and so cannot be represented. Callers can detect the
/// condition with [`Error::invalid_witness_source`].
///
/// # Examples
///
/// ```
/// use ragu_core::Error;
/// use ragu_primitives::PointAtInfinityError;
///
/// let err = Error::InvalidWitness(Box::new(PointAtInfinityError));
/// assert!(err.invalid_witness_source::<PointAtInfinityError>().is_some());
/// ```
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
#[error("point at infinity cannot be witnessed")]
pub struct PointAtInfinityError;

/// Represents an affine point on a curve defined over the circuit's field.
///
/// ## Supported Curves
///
/// This implementation assumes that the points are on a short Weierstrass curve
/// $y^2 = x^3 + b$ where $b$ is a non-square in $\mathbb{F}$, and there are no
/// points of order $2$. Furthermore, the field $\mathbb{F}$ must have a
/// nontrivial cube root of unity $\zeta$ used for an endomorphism optimization.
/// These assumptions are satisfied by the Pasta curves.
///
/// As a result, the $x$ and $y$ coordinates are nonzero for every affine point.
#[derive(Gadget, Write, GadgetEquals)]
pub struct Point<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    x: Nonzero<'dr, D>,
    #[ragu(gadget)]
    y: Nonzero<'dr, D>,
    #[ragu(phantom)]
    _marker: PhantomData<C>,
}

impl<'dr, D: Driver<'dr, F = C::Base>, C: CurveAffine> Point<'dr, D, C> {
    /// Creates a new `Point` from the given coordinates without enforcing that
    /// the provided $x, y$ satisfy the curve equation.
    ///
    /// # Preconditions
    ///
    /// The caller must enforce or derive the curve equation before using the
    /// result as an ordinary [`Point`].
    fn new_unchecked(x: Nonzero<'dr, D>, y: Nonzero<'dr, D>) -> Self {
        Point {
            x,
            y,
            _marker: PhantomData,
        }
    }

    /// Allocates a point on the curve from witness input.
    ///
    /// This method uses [`Element::alloc_square`] to allocate coordinates and
    /// then enforces the curve equation.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned point represent an affine
    /// point on the curve with nonzero coordinates.
    ///
    /// # Completeness
    ///
    /// Witness generation succeeds when witness input is not the identity.
    ///
    /// # Errors
    ///
    /// Witness generation fails with [`Error::InvalidWitness`] when witness
    /// input is the identity. The boxed source is a [`PointAtInfinityError`]
    /// value, which callers can detect with
    /// [`Error::invalid_witness_source`].
    pub fn alloc(dr: &mut D, p: DriverValue<D, C>) -> Result<Self> {
        let coordinates = D::try_just(|| {
            let coordinates = p.take().coordinates().into_option();
            coordinates.ok_or_else(|| Error::InvalidWitness(Box::new(PointAtInfinityError)))
        })?;

        let (x, x2) = Element::alloc_square(dr, coordinates.as_ref().map(|p| *p.x()))?;
        let x3 = x.mul(dr, &x2)?;
        let (y, y2) = Element::alloc_square(dr, coordinates.as_ref().map(|p| *p.y()))?;

        // Enforce x³ + b - y² = 0
        dr.enforce_zero(|lc| {
            lc.add(x3.wire())
                .add_term(&D::ONE, Coeff::Arbitrary(C::b()))
                .sub(y2.wire())
        })?;

        Ok(Point::new_unchecked(
            Nonzero::new_unchecked(x),
            Nonzero::new_unchecked(y),
        ))
    }

    /// Embeds a constant point.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::InvalidWitness`] when `p` is the identity. The
    /// boxed source is a [`PointAtInfinityError`] value, which callers can
    /// detect with [`Error::invalid_witness_source`].
    pub fn constant(dr: &mut D, p: C) -> Result<Self> {
        if let Some(coordinates) = p.coordinates().into_option() {
            let x = Element::constant(dr, *coordinates.x());
            let y = Element::constant(dr, *coordinates.y());

            Ok(Point::new_unchecked(
                Nonzero::new_unchecked(x),
                Nonzero::new_unchecked(y),
            ))
        } else {
            Err(Error::InvalidWitness(Box::new(PointAtInfinityError)))
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
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned point represent the
    /// endomorphism of `self`.
    pub fn endo(&self, dr: &mut D) -> Self {
        let endo_x = self.x.scale(dr, Coeff::Arbitrary(C::Base::ZETA));
        Point::new_unchecked(Nonzero::new_unchecked(endo_x), self.y.clone())
    }

    /// Negates this point.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned point represent `-self`.
    pub fn negate(&self, dr: &mut D) -> Self {
        Point {
            x: self.x.clone(),
            y: self.y.negate(dr),
            _marker: PhantomData,
        }
    }

    /// Applies the endomorphism iff the provided condition is true.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned point represent `self`
    /// when `condition` is false and the endomorphism of `self` when
    /// `condition` is true.
    pub fn conditional_endo(&self, dr: &mut D, condition: &Boolean<'dr, D>) -> Result<Self> {
        let endo_x = self.x.scale(dr, Coeff::Arbitrary(D::F::ZETA));
        let x = condition.conditional_select(dr, &self.x, &endo_x)?;
        Ok(Point::new_unchecked(
            Nonzero::new_unchecked(x),
            self.y.clone(),
        ))
    }

    /// Applies the negation map iff the provided condition is true.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned point represent `self`
    /// when `condition` is false and `-self` when `condition` is true.
    pub fn conditional_negate(&self, dr: &mut D, condition: &Boolean<'dr, D>) -> Result<Self> {
        let neg_y = self.y.negate(dr);
        let y = condition.conditional_select(dr, &self.y, &neg_y)?;
        Ok(Point::new_unchecked(
            self.x.clone(),
            Nonzero::new_unchecked(y),
        ))
    }

    /// Doubles this point. Ragu does not support curves with points of order
    /// two, and thus all affine points have affine doubles.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment makes the returned point represent
    /// `self + self`.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if the slope assignment cannot be
    /// computed from witness input.
    pub fn double(&self, dr: &mut D) -> Result<Self> {
        // delta = 3x^2 / 2y
        let double_y = self.y.double(dr);
        let delta = self
            .x
            .square(dr)?
            .scale(dr, Coeff::Arbitrary(D::F::from(3)))
            .divide(dr, &double_y)?;

        // x3 = delta^2 - 2x
        let double_x = self.x.double(dr);
        let x3 = delta.square(dr)?.sub(dr, &double_x);

        // y3 = delta * (x - x3) - y
        let x_sub_x3 = self.x.sub(dr, &x3);
        let y3 = delta.mul(dr, &x_sub_x3)?.sub(dr, &self.y);

        Ok(Point::new_unchecked(
            Nonzero::new_unchecked(x3),
            Nonzero::new_unchecked(y3),
        ))
    }

    /// Computes `self + other` via incomplete affine addition.
    ///
    /// # Exceptional Cases
    ///
    /// This method requires `self.x != other.x`. The provided `bank` is used to
    /// discharge this requirement on behalf of the caller.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment for the enclosing bank scope makes the
    /// returned point represent `self + other`.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if witness input falls into the
    /// exceptional case.
    pub fn add_incomplete(
        &self,
        dr: &mut D,
        other: &Self,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Self> {
        // delta = (y1 - y0) / (x1 - x0)
        let tmp = other.x.sub(dr, &self.x);
        let tmp = bank.fold(dr, tmp)?;
        let delta = other.y.sub(dr, &self.y).divide(dr, &tmp)?;

        // x3 = delta^2 - x0 - x1
        let x3 = delta.square(dr)?.sub(dr, &self.x).sub(dr, &other.x);

        // y3 = delta * (x0 - x3) - y0
        let tmp = self.x.sub(dr, &x3);
        let y3 = delta.mul(dr, &tmp)?.sub(dr, &self.y);

        Ok(Point::new_unchecked(
            Nonzero::new_unchecked(x3),
            Nonzero::new_unchecked(y3),
        ))
    }

    /// Computes $\[2\] Q + P$ using the standard $(Q + P) + Q$
    /// [trick](https://github.com/zcash/zcash/issues/3924).
    ///
    /// # Exceptional Cases
    ///
    /// This method requires `self.x != other.x` and requires the intermediate
    /// incomplete additions to avoid the identity. The provided `bank` is used
    /// to discharge these requirements on behalf of the caller.
    ///
    /// # Soundness
    ///
    /// Any satisfying assignment for the enclosing bank scope makes the
    /// returned point represent the documented `[2] Q + P` relation.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if witness input falls into an
    /// exceptional case.
    pub fn double_and_add_incomplete(
        &self,
        dr: &mut D,
        other: &Self,
        bank: &mut NonzeroBank<'dr, D>,
    ) -> Result<Self> {
        // See <https://github.com/zcash/zcash/issues/3924> for an explanation.

        // lambda_1 = (y_q - y_p)/(x_q - x_p)
        let tmp = other.x.sub(dr, &self.x);
        let tmp = bank.fold(dr, tmp)?;
        let lambda_1 = other.y.sub(dr, &self.y).divide(dr, &tmp)?;

        // x_r = lambda_1^2 - x_p - x_q
        let x_r = lambda_1.square(dr)?.sub(dr, &self.x).sub(dr, &other.x);

        // lambda_2 = 2 y_p /(x_p - x_r) - lambda_1
        let tmp = self.x.sub(dr, &x_r);
        let tmp = bank.fold(dr, tmp)?;
        let lambda_2 = self.y.double(dr).divide(dr, &tmp)?.sub(dr, &lambda_1);

        // x_s = lambda_2^2 - x_r - x_p
        let x_s = lambda_2.square(dr)?.sub(dr, &x_r).sub(dr, &self.x);

        // y_s = lambda_2 (x_p - x_s) - y_p
        let tmp = self.x.sub(dr, &x_s);
        let y_s = lambda_2.mul(dr, &tmp)?.sub(dr, &self.y);

        Ok(Point::new_unchecked(
            Nonzero::new_unchecked(x_s),
            Nonzero::new_unchecked(y_s),
        ))
    }
}

impl<'dr, D: Driver<'dr, F = C::Base>, C: CurveAffine> Consistent<'dr, D> for Point<'dr, D, C> {
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        Self::alloc(dr, self.value())?.enforce_conservative_equal(dr, self)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use ragu_arithmetic::{
        CurveExt,
        group::{CurveAffine as _, Group},
    };

    use super::*;

    type F = ragu_pasta::Fp;
    type C = ragu_pasta::EpAffine;
    type Simulator = crate::Simulator<F>;

    #[test]
    fn test_point_alloc() -> Result<()> {
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

    /// The identity is rejected with the typed [`PointAtInfinityError`]
    /// source on both the witnessed and constant paths.
    #[test]
    fn test_identity_reports_typed_source() {
        let result = Simulator::simulate(C::identity(), |dr, point| {
            Point::alloc(dr, point.clone())?;
            Ok(())
        });
        let Err(err) = result else {
            panic!("identity point must be rejected");
        };
        assert_eq!(
            err.invalid_witness_source::<PointAtInfinityError>(),
            Some(&PointAtInfinityError)
        );

        let result = Simulator::simulate(C::identity(), |dr, _| {
            Point::constant(dr, C::identity())?;
            Ok(())
        });
        let Err(err) = result else {
            panic!("identity constant must be rejected");
        };
        assert_eq!(
            err.invalid_witness_source::<PointAtInfinityError>(),
            Some(&PointAtInfinityError)
        );
    }

    #[test]
    fn test_point_double() -> Result<()> {
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
            assert_eq!(sim.num_gates(), 4);
            assert_eq!(sim.num_constraints(), 8);
            Ok(())
        };

        double(C::generator())?;

        Ok(())
    }

    #[test]
    fn test_add_incomplete() -> Result<()> {
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
                    let mut bank = NonzeroBank::new_unchecked();
                    let r_gadget = p_gadget.add_incomplete(dr, &q_gadget, &mut bank)?;
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
                    assert_eq!(sim.num_gates(), 3);
                    assert_eq!(sim.num_constraints(), 6);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_double_and_add_incomplete() -> Result<()> {
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
                    let mut bank = NonzeroBank::new_unchecked();
                    let r_gadget = p_gadget.double_and_add_incomplete(dr, &q_gadget, &mut bank)?;
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
                    assert_eq!(sim.num_gates(), 5);
                    assert_eq!(sim.num_constraints(), 10);
                }
            }
        }
        Ok(())
    }
}
