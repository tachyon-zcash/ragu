//! Field element gadget for arithmetic circuit wires.
//!
//! Provides the [`Element`] type representing a wire and its field element
//! assignment, the fundamental building block for circuit construction.

use arithmetic::Coeff;
use arithmetic::PrimeFieldExt;
use ff::{Field, PrimeField};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Consistent, Gadget, Kind},
    maybe::Maybe,
};

use alloc::vec::Vec;
use core::borrow::Borrow;

use crate::{
    Boolean,
    io::{Buffer, Write},
};

/// Represents a wire and its corresponding field element value, but generally
/// does not guarantee any particular constraint has been imposed on the wire.
/// Also represents the fundamental code unit of serialization using the
/// [`Write`] trait.
///
/// ## Usage
///
/// Elements can be allocated ([`Element::alloc`], [`Element::alloc_square`])
/// with a provided witness assignment. Any constant field element can be turned
/// into an [`Element`] without an allocation using [`Element::constant`] (or
/// [`Element::one`] for the unitary case).
///
/// It is not possible to distinguish an [`Element`] that represents an
/// allocated wire from a virtual wire such as a constant or the result of
/// adding elements together. The ability to represent both is provided for
/// convenience and to ensure that [`Element`] can implement the [`Gadget`]
/// trait, but more efficient abstractions can avoid unnecessary constraints by
/// preserving this distinction.
///
/// Elements can be added, multiplied and scaled in various ways.
///
/// ## Promotion
///
/// As with all gadgets, an [`Element`] can be [demoted](crate::promotion) but
/// because it only represents a wire it is preferable to demote by extracting
/// the wire using [`Element::wire`]. Promotion via [`Element::promote`] takes a
/// bare wire instead of a demoted gadget to encourage this.
#[derive(Gadget, Consistent)]
pub struct Element<'dr, D: Driver<'dr>> {
    /// A wire created by the driver
    #[ragu(wire)]
    wire: D::Wire,

    /// The witness value for the assignment of this wire
    #[ragu(value)]
    value: DriverValue<D, D::F>,
}

impl<'dr, D: Driver<'dr>> Element<'dr, D> {
    /// Allocates an element with the provided witness assignment.
    ///
    /// This costs one allocation.
    pub fn alloc(dr: &mut D, assignment: DriverValue<D, D::F>) -> Result<Self> {
        let wire = dr.alloc(|| Ok(Coeff::Arbitrary(*assignment.snag())))?;

        Ok(Element {
            value: assignment,
            wire,
        })
    }

    /// Allocates an element $a$ with the provided witness assignment and
    /// squares it in a single step. Returns $(a, a^2)$.
    ///
    /// This costs one multiplication constraint.
    pub fn alloc_square(dr: &mut D, assignment: DriverValue<D, D::F>) -> Result<(Self, Self)> {
        let square = D::just(|| assignment.snag().square());
        let (a, b, c) = dr.mul(|| {
            let value = *assignment.view().take();
            Ok((
                Coeff::Arbitrary(value),
                Coeff::Arbitrary(value),
                Coeff::Arbitrary(*square.snag()),
            ))
        })?;
        dr.enforce_equal(&a, &b)?;

        Ok((
            Element {
                value: assignment,
                wire: a,
            },
            Element {
                value: square,
                wire: c,
            },
        ))
    }

    /// Creates an element for the unitary constant value.
    pub fn one() -> Self {
        Element {
            value: D::just(|| D::F::ONE),
            wire: D::ONE,
        }
    }

    /// Creates an element for the zero constant value.
    pub fn zero(dr: &mut D) -> Self {
        let wire = dr.constant(Coeff::Zero);
        let value = D::just(|| D::F::ZERO);

        Element { value, wire }
    }

    /// Creates an element with a non-trivial constant for use as a stub.
    ///
    /// See [`PrimeFieldExt::todo`] for the equivalent on bare field elements.
    pub fn todo(dr: &mut D) -> Self
    where
        D::F: PrimeField,
    {
        Self::constant(dr, D::F::todo())
    }

    /// Creates an element for the provided constant value.
    pub fn constant(dr: &mut D, value: D::F) -> Self {
        let wire = dr.constant(Coeff::Arbitrary(value));
        let value = D::just(|| value);

        Element { value, wire }
    }

    /// Constructs a new element from a wire and a witness value. **It is the
    /// caller's responsibility to ensure that the provided witness value is
    /// consistent with the provided wire's value.**
    pub fn promote(wire: D::Wire, value: DriverValue<D, D::F>) -> Self {
        Element { wire, value }
    }

    /// Returns the value of this element. The caller can rely on this being
    /// consistent with the underlying wire's value.
    pub fn value(&self) -> DriverValue<D, &D::F> {
        self.value.view()
    }

    /// Returns the wire associated with this element.
    pub fn wire(&self) -> &D::Wire {
        &self.wire
    }

    /// Multiply two elements together.
    pub fn mul(&self, dr: &mut D, other: &Self) -> Result<Self> {
        let product = D::just(|| {
            let a = *self.value.snag();
            let b = *other.value.snag();
            a * b
        });

        let (a, b, c) = dr.mul(|| {
            Ok((
                Coeff::Arbitrary(*self.value.snag()),
                Coeff::Arbitrary(*other.value.snag()),
                Coeff::Arbitrary(*product.snag()),
            ))
        })?;
        dr.enforce_equal(&a, self.wire())?;
        dr.enforce_equal(&b, other.wire())?;

        Ok(Element {
            value: product,
            wire: c,
        })
    }

    /// Squares an element.
    pub fn square(&self, dr: &mut D) -> Result<Self> {
        self.mul(dr, self)
    }

    /// Enforces that this element equals zero.
    pub fn enforce_zero(&self, dr: &mut D) -> Result<()> {
        dr.enforce_zero(|lc| lc.add(&self.wire))
    }

    /// Negates this element.
    pub fn negate(&self, dr: &mut D) -> Self {
        self.scale(dr, Coeff::NegativeOne)
    }

    /// Add two elements together.
    pub fn add(&self, dr: &mut D, other: &Self) -> Self {
        let value = D::just(|| {
            let a = *self.value.snag();
            let b = *other.value.snag();
            a + b
        });

        let wire = dr.add(|lc| lc.add(&self.wire).add(&other.wire));

        Element { value, wire }
    }

    /// Subtracts another element from this one.
    pub fn sub(&self, dr: &mut D, other: &Self) -> Self {
        let value = D::just(|| {
            let a = *self.value.snag();
            let b = *other.value.snag();
            a - b
        });

        let wire = dr.add(|lc| lc.add(&self.wire).sub(&other.wire));

        Element { value, wire }
    }

    /// Add another element scaled by a constant: `self` + `other` * `coeff`.
    pub fn add_coeff(&self, dr: &mut D, other: &Self, coeff: Coeff<D::F>) -> Self {
        let value = D::just(|| {
            *self.value.snag() + (Coeff::Arbitrary(*other.value.snag()) * coeff).value()
        });
        let wire = dr.add(|lc| lc.add(&self.wire).add_term(&other.wire, coeff));
        Element { value, wire }
    }

    /// Scale this element by a constant.
    pub fn scale(&self, dr: &mut D, coeff: Coeff<D::F>) -> Self {
        let value = D::just(|| (Coeff::Arbitrary(*self.value.snag()) * coeff).value());
        let wire = dr.add(|lc| lc.add_term(&self.wire, coeff));
        Element { value, wire }
    }

    /// Double this element.
    pub fn double(&self, dr: &mut D) -> Self {
        self.add(dr, self)
    }

    /// Invert this element if it is nonzero.
    ///
    /// This will fail to synthesize if the element is zero.
    pub fn invert(&self, dr: &mut D) -> Result<Self> {
        let inverse = D::with(|| {
            self.value
                .snag()
                .invert()
                .into_option()
                .ok_or_else(|| Error::InvalidWitness("division by zero".into()))
        })?;

        self.invert_with(dr, inverse)
    }

    /// Enforce that this element times the provided `inverse` (unallocated value) equals one.
    /// Returns the allocated `inverse` element.
    pub fn invert_with(&self, dr: &mut D, inverse: DriverValue<D, D::F>) -> Result<Self> {
        let (a, b, c) = dr.mul(|| {
            Ok((
                Coeff::Arbitrary(*self.value.snag()),
                Coeff::Arbitrary(*inverse.snag()),
                Coeff::One,
            ))
        })?;
        dr.enforce_equal(&a, self.wire())?;
        dr.enforce_equal(&c, &D::ONE)?;

        Ok(Element {
            value: inverse,
            wire: b,
        })
    }

    /// Divides this element by the provided element `by` and returns the
    /// quotient. If `by` is zero, the result may be unconstrained.
    ///
    /// Essentially, the prover witnesses `quotient` such that
    ///
    /// `quotient * by = self`
    ///
    /// which enforces that `quotient` is equal to `self / by` if and only if
    /// `by` is nonzero.
    pub fn div_nonzero(&self, dr: &mut D, by: &Self) -> Result<Self> {
        let quotient_value = D::with(|| {
            Ok(*self.value().take()
                * by.value()
                    .take()
                    .invert()
                    .into_option()
                    .ok_or_else(|| Error::InvalidWitness("division by zero".into()))?)
        })?;

        let (quotient, denominator, numerator) = dr.mul(|| {
            let c = *self.value().take();
            let b = *by.value().take();
            let a = *quotient_value.snag();

            Ok((
                Coeff::Arbitrary(a),
                Coeff::Arbitrary(b),
                Coeff::Arbitrary(c),
            ))
        })?;
        dr.enforce_equal(self.wire(), &numerator)?;
        dr.enforce_equal(by.wire(), &denominator)?;

        Ok(Element {
            value: quotient_value,
            wire: quotient,
        })
    }

    /// Returns a boolean indicating whether this element is zero.
    pub fn is_zero(&self, dr: &mut D) -> Result<Boolean<'dr, D>> {
        crate::boolean::is_zero(dr, self)
    }

    /// Returns a boolean indicating whether this element equals another.
    pub fn is_equal(&self, dr: &mut D, other: &Self) -> Result<Boolean<'dr, D>> {
        let diff = self.sub(dr, other);
        diff.is_zero(dr)
    }

    /// Computes a weighted sum of the elements yielded by an iterator by the
    /// powers of the provided `scale_factor`.
    ///
    /// Horner's method is used to evaluate the weighted sum, effectively
    /// scaling the first element by the highest power of `scale_factor` and the
    /// last element by nothing at all.
    pub fn fold<E: Borrow<Element<'dr, D>>>(
        dr: &mut D,
        elements: impl IntoIterator<Item = E>,
        scale_factor: &Element<'dr, D>,
    ) -> Result<Self> {
        let mut iter = elements.into_iter();
        let Some(first) = iter.next() else {
            return Ok(Element::zero(dr));
        };
        iter.try_fold(first.borrow().clone(), |acc, elem| {
            acc.mul(dr, scale_factor)
                .map(|scaled| scaled.add(dr, elem.borrow()))
        })
    }

    /// Sums an iterator of elements.
    ///
    /// This is more efficient than [`Element::fold`] with scale=1 because it
    /// avoids multiplication constraints.
    pub fn sum<E: Borrow<Element<'dr, D>>>(
        dr: &mut D,
        elements: impl IntoIterator<Item = E>,
    ) -> Self {
        elements
            .into_iter()
            .fold(Element::zero(dr), |acc, elem| acc.add(dr, elem.borrow()))
    }
}

impl<F: Field> Write<F> for Kind![F; @Element<'_, _>] {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Element<'dr, D>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        buf.write(dr, this)
    }
}

/// Simple buffer that collects pushed values into a vector.
impl<'dr, D: Driver<'dr>> Buffer<'dr, D> for Vec<Element<'dr, D>> {
    fn write(&mut self, _: &mut D, value: &Element<'dr, D>) -> Result<()> {
        Vec::push(self, value.clone());
        Ok(())
    }
}

/// Simple buffer that does nothing.
impl<'dr, D: Driver<'dr>> Buffer<'dr, D> for () {
    fn write(&mut self, _: &mut D, _: &Element<'dr, D>) -> Result<()> {
        Ok(())
    }
}

/// Simple buffer that counts the number of pushes.
impl<'dr, D: Driver<'dr>> Buffer<'dr, D> for usize {
    fn write(&mut self, _: &mut D, _: &Element<'dr, D>) -> Result<()> {
        *self += 1;
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, B: Buffer<'dr, D>> Buffer<'dr, D> for &mut B {
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        B::write(self, dr, value)
    }
}

/// Computes a fixed linear combination of some allocated values.
pub fn multiadd<'dr, D: Driver<'dr>>(
    dr: &mut D,
    values: &[Element<'dr, D>],
    coeffs: &[D::F],
) -> Result<Element<'dr, D>> {
    assert_eq!(values.len(), coeffs.len());
    let value = D::just(|| {
        let mut sum = D::F::ZERO;
        for (value, coeff) in values.iter().zip(coeffs) {
            sum += *value.value().take() * *coeff;
        }
        sum
    });
    let wire = dr.add(|mut lc| {
        for (value, coeff) in values.iter().zip(coeffs) {
            lc = lc.add_term(value.wire(), Coeff::Arbitrary(*coeff));
        }
        lc
    });

    Ok(Element::promote(wire, value))
}

#[test]
fn test_div_nonzero() -> Result<()> {
    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    let alloc = |a: F, b: F| {
        let sim = Simulator::simulate((a, b), |dr, witness| {
            let (a, b) = witness.cast();
            let a = Element::alloc(dr, a.clone())?;
            let b = Element::alloc(dr, b.clone())?;

            let quotient = a.div_nonzero(dr, &b)?;

            assert_eq!(
                *quotient.value().take(),
                *a.value().take() * b.value().take().invert().unwrap()
            );

            Ok(())
        })?;

        assert_eq!(sim.num_allocations(), 2);
        assert_eq!(sim.num_multiplications(), 1);
        assert_eq!(sim.num_linear_constraints(), 2);
        Ok(())
    };

    alloc(F::from(4578u64), F::from(372u64))?;
    alloc(F::ZERO, F::from(372u64))?;
    assert!(alloc(F::from(4578u64), F::ZERO).is_err());

    Ok(())
}

#[test]
fn test_invert() -> Result<()> {
    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    let inv = |a: F| {
        let sim = Simulator::simulate(a, |dr, witness| {
            let a = Element::alloc(dr, witness.clone())?;
            dr.reset();
            let ainv = a.invert(dr)?;

            assert_eq!(*ainv.value().take(), a.value().take().invert().unwrap());

            Ok(())
        })?;

        assert_eq!(sim.num_allocations(), 0);
        assert_eq!(sim.num_multiplications(), 1);
        assert_eq!(sim.num_linear_constraints(), 2);
        Ok(())
    };

    inv(F::from(4578u64))?;
    assert!(inv(F::ZERO).is_err());

    Ok(())
}
