//! Affine coordinates including the identity, encoded canonically as `(0, 0)`.

use core::marker::PhantomData;

use ragu_core::{
    Coeff, Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use crate::{
    Boolean, Element, GadgetExt, HoistedEndoscalar, Nonzero, Point, comparison::GadgetEquals,
    consistent::Consistent, io::Write,
};

/// A curve point whose coordinates can also represent the identity.
///
/// This uses the same curve assumptions as [`Point`]: finite points have
/// nonzero coordinates. The identity is exactly `(0, 0)`, so the encoding
/// occupies two wires and has no unconstrained activation flag.
#[derive(Gadget, Write, GadgetEquals)]
pub struct CompletePoint<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    #[ragu(gadget)]
    x: Element<'dr, D>,
    #[ragu(gadget)]
    y: Element<'dr, D>,
    #[ragu(phantom)]
    marker: PhantomData<C>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> CompletePoint<'dr, D, C> {
    /// Allocates a finite point or the identity, enforcing its encoding.
    ///
    /// # Soundness
    ///
    /// The coordinates satisfy the curve equation, or both equal zero.
    pub fn alloc(dr: &mut D, value: DriverValue<D, C>) -> Result<Self> {
        let coordinates = value.map(|p| p.coordinates().unwrap_or((D::F::ZERO, D::F::ZERO)));
        let point = Self {
            x: Element::alloc(dr, &mut (), coordinates.as_ref().map(|p| p.0))?,
            y: Element::alloc(dr, &mut (), coordinates.as_ref().map(|p| p.1))?,
            marker: PhantomData,
        };
        point.enforce_curve(dr)?;
        Ok(point)
    }

    /// Embeds a constant point, including the identity.
    pub fn constant(dr: &mut D, point: C) -> Self {
        let (x, y) = point.coordinates().unwrap_or((D::F::ZERO, D::F::ZERO));
        Self {
            x: Element::constant(dr, x),
            y: Element::constant(dr, y),
            marker: PhantomData,
        }
    }

    /// Converts an already constrained finite point without adding gates.
    pub fn from_affine(point: Point<'dr, D, C>) -> Self {
        Self {
            x: point.x.into_inner(),
            y: point.y.into_inner(),
            marker: PhantomData,
        }
    }

    /// Converts to a finite point, rejecting the identity.
    ///
    /// Nonzero `x` excludes the identity; the curve assumptions then imply
    /// nonzero `y`. This is the checked boundary to incomplete arithmetic.
    pub fn to_affine(&self, dr: &mut D) -> Result<Point<'dr, D, C>> {
        Ok(Point::new_unchecked(
            self.x.clone().enforce_nonzero(dr)?,
            Nonzero::new_unchecked(self.y.clone()),
        ))
    }

    /// Returns the represented group element.
    pub fn value(&self) -> DriverValue<D, C> {
        D::just(|| {
            let x = *self.x.value().take();
            let y = *self.y.value().take();
            if x == D::F::ZERO {
                C::identity()
            } else {
                C::from_xy(x, y).expect("constrained curve point")
            }
        })
    }

    /// Returns the canonical coordinates; the identity has two zeroes.
    pub fn coordinates(&self) -> (&Element<'dr, D>, &Element<'dr, D>) {
        (&self.x, &self.y)
    }

    /// Enforces the complete affine encoding on existing coordinate wires.
    fn enforce_curve(&self, dr: &mut D) -> Result<()> {
        let identity = self.x.is_zero(dr, &mut ())?;
        identity.element().mul(dr, &self.y)?.enforce_zero(dr)?;
        let x2 = self.x.square(dr)?;
        let x3 = x2.mul(dr, &self.x)?;
        let b = identity.not(dr).element().scale(dr, Coeff::Arbitrary(C::B));
        let y2 = self.y.square(dr)?;
        x3.add(dr, &b).enforce_equal(dr, &y2)
    }

    /// Selects `other` when `condition` is true, otherwise `self`.
    pub fn select(&self, dr: &mut D, condition: &Boolean<'dr, D>, other: &Self) -> Result<Self> {
        Ok(Self {
            x: condition.conditional_select(dr, &self.x, &other.x)?,
            y: condition.conditional_select(dr, &self.y, &other.y)?,
            marker: PhantomData,
        })
    }

    /// Adds points, including doubling, inverse pairs and the identity.
    ///
    /// # Soundness
    ///
    /// For constrained inputs the result represents their group sum.
    pub fn add(&self, dr: &mut D, other: &Self) -> Result<Self> {
        let left_identity = self.x.is_zero(dr, &mut ())?;
        let right_identity = other.x.is_zero(dr, &mut ())?;
        let dx = other.x.sub(dr, &self.x);
        let same_x = dx.is_zero(dr, &mut ())?;
        let dy = other.y.sub(dr, &self.y);
        let double_y = self.y.double(dr);
        let numerator_double = self
            .x
            .square(dr)?
            .scale(dr, Coeff::Arbitrary(D::F::from(3)));
        let numerator = same_x.conditional_select(dr, &dy, &numerator_double)?;
        let denominator = same_x.conditional_select(dr, &dx, &double_y)?;
        let zero_denominator = denominator.is_zero(dr, &mut ())?;
        let one = Element::one();
        let denominator = zero_denominator.conditional_select(dr, &denominator, &one)?;
        let inverse = denominator.invert(dr)?;
        let slope = numerator.mul(dr, &inverse)?;
        let x = slope.square(dr)?.sub(dr, &self.x).sub(dr, &other.x);
        let delta = self.x.sub(dr, &x);
        let y = slope.mul(dr, &delta)?.sub(dr, &self.y);
        let candidate = Self {
            x,
            y,
            marker: PhantomData,
        };

        let opposite_y = self.y.add(dr, &other.y).is_zero(dr, &mut ())?;
        let inverse_pair = same_x.and(dr, &opposite_y)?;
        let identity = Self::constant(dr, C::identity());
        let sum = candidate.select(dr, &inverse_pair, &identity)?;
        let sum = sum.select(dr, &left_identity, other)?;
        sum.select(dr, &right_identity, self)
    }

    /// Multiplies by the hoisted endoscalar, preserving the identity.
    ///
    /// The finite multiplication uses [`HoistedEndoscalar::group_scale`];
    /// its scalar and curve assumptions also apply here.
    pub fn group_scale(&self, dr: &mut D, scalar: &HoistedEndoscalar<'dr, D>) -> Result<Self> {
        let identity = self.x.is_zero(dr, &mut ())?;
        let generator = Self::constant(dr, C::generator());
        let finite = self.select(dr, &identity, &generator)?;
        // The selection is finite: a nonidentity input, or the generator.
        let finite = Point::new_unchecked(
            Nonzero::new_unchecked(finite.x),
            Nonzero::new_unchecked(finite.y),
        );
        let scaled = Self::from_affine(scalar.group_scale(dr, &finite)?);
        let zero = Self::constant(dr, C::identity());
        scaled.select(dr, &identity, &zero)
    }
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Consistent<'dr, D> for CompletePoint<'dr, D, C> {
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        self.enforce_curve(dr)
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::{EpAffine, EqAffine, Fp, Fq};
    use udon::curve::{Affine, Projective};

    use super::*;
    use crate::{Simulator, Uendo, lift_endoscalar};

    #[test]
    fn complete_addition_covers_exceptional_pairs() -> Result<()> {
        check_addition::<EpAffine>()?;
        check_addition::<EqAffine>()
    }

    fn check_addition<C: udon::curve::EndomorphismAffine>() -> Result<()> {
        let g = C::generator();
        let points = [C::identity(), g, -g, g.to_projective().double().to_affine()];
        let mut shape = None;
        for left in points {
            for right in points {
                let simulation = Simulator::<C::Base>::simulate((left, right), |dr, witness| {
                    let left = CompletePoint::<_, C>::alloc(dr, witness.as_ref().map(|p| p.0))?;
                    let right = CompletePoint::alloc(dr, witness.as_ref().map(|p| p.1))?;
                    let sum = left.add(dr, &right)?;
                    assert_eq!(
                        sum.value().take(),
                        (left.value().take().to_projective()
                            + right.value().take().to_projective())
                        .to_affine()
                    );
                    Ok(())
                })?;
                let counts = (simulation.num_gates(), simulation.num_constraints());
                assert_eq!(*shape.get_or_insert(counts), counts);
            }
        }
        Ok(())
    }

    #[test]
    fn identity_encoding_rejects_nonzero_y_and_off_curve_points() {
        for (x, y) in [(Fp::ZERO, Fp::ONE), (Fp::ONE, Fp::ZERO)] {
            assert!(
                Simulator::<Fp>::simulate((x, y), |dr, witness| {
                    let point = CompletePoint::<_, EpAffine> {
                        x: Element::alloc(dr, &mut (), witness.as_ref().map(|p| p.0))?,
                        y: Element::alloc(dr, &mut (), witness.as_ref().map(|p| p.1))?,
                        marker: PhantomData,
                    };
                    point.enforce_consistent(dr)
                })
                .is_err()
            );
        }
    }

    #[test]
    fn scaling_preserves_zero_commitments() -> Result<()> {
        for point in [EpAffine::identity(), EpAffine::generator()] {
            let scalar_value = Uendo::from(42u128);
            Simulator::<Fp>::simulate((point, scalar_value), |dr, witness| {
                let value = witness.as_ref().map(|w| w.0);
                let point = CompletePoint::<_, EpAffine>::alloc(dr, value.clone())?;
                let scalar = HoistedEndoscalar::alloc(dr, witness.as_ref().map(|w| w.1))?;
                let scaled = point.group_scale(dr, &scalar)?;
                assert_eq!(
                    scaled.value().take(),
                    (value.take().to_projective() * lift_endoscalar::<Fq>(scalar_value))
                        .to_affine()
                );
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn finite_conversion_rejects_identity() -> Result<()> {
        for point in [EpAffine::identity(), EpAffine::generator()] {
            let result = Simulator::<Fp>::simulate(point, |dr, value| {
                let point = CompletePoint::<_, EpAffine>::alloc(dr, value.clone())?;
                assert_eq!(point.to_affine(dr)?.value().take(), value.take());
                Ok(())
            });
            assert_eq!(result.is_ok(), !point.is_identity());
        }
        Ok(())
    }
}
