//! Boolean gadget for constrained binary values.
//!
//! Provides the [`Boolean`] type representing a wire constrained to be zero or
//! one, with logical operations implemented as circuit constraints.

use core::marker::PhantomData;
use ff::{Field, PrimeField};
use ragu_arithmetic::Coeff;

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, FromDriver, LinearExpression},
    gadgets::{Consistent, Gadget, GadgetKind, Kind},
    maybe::Maybe,
};

use crate::vec::{CollectFixed, FixedVec, Len};

use alloc::{vec, vec::Vec};

use crate::{
    Element, GadgetExt,
    io::{Buffer, Write},
    promotion::{Demoted, Promotion},
    util::InternalMaybe,
};

/// Represents a wire that is constrained to be zero or one, along with its
/// corresponding [`bool`] value.
#[derive(Gadget)]
pub struct Boolean<'dr, D: Driver<'dr>> {
    /// The wire constrained to hold either `0` or `1` in the scalar field.
    #[ragu(wire)]
    wire: D::Wire,

    /// The witness value of this boolean.
    #[ragu(value)]
    value: DriverValue<D, bool>,
}

impl<'dr, D: Driver<'dr>> Boolean<'dr, D> {
    /// Allocates a boolean with the provided witness value.
    ///
    /// This costs one multiplication constraint and two linear constraints.
    pub fn alloc(dr: &mut D, value: DriverValue<D, bool>) -> Result<Self> {
        let (a, b, c) = dr.mul(|| {
            let value = value.coeff().take();
            Ok((value, value, value))
        })?;

        // Enforce a = b => c = a²
        dr.enforce_equal(&a, &b)?;

        // Enforce a = c => a = a²
        //                => (a - 0)(a - 1) = 0
        //                => (a = 0) OR (a = 1)
        dr.enforce_equal(&a, &c)?;

        Ok(Boolean { value, wire: c })
    }

    /// Computes the NOT of this boolean. This is "free" in the circuit model.
    pub fn not(&self, dr: &mut D) -> Self {
        // The wire w is transformed into 1 - w, its logical NOT.
        let wire = dr.add(|lc| lc.add(&D::ONE).sub(self.wire()));
        let value = self.value().not();
        Boolean { wire, value }
    }

    /// Computes the AND of two booleans. This costs one multiplication
    /// constraint and two linear constraints.
    pub fn and(&self, dr: &mut D, other: &Self) -> Result<Self> {
        let result = D::just(|| self.value.snag() & other.value.snag());
        let (a, b, c) = dr.mul(|| {
            let a = self.value.coeff().take();
            let b = other.value.coeff().take();
            let c = result.coeff().take();
            Ok((a, b, c))
        })?;

        dr.enforce_equal(&a, self.wire())?;
        dr.enforce_equal(&b, other.wire())?;

        Ok(Boolean {
            value: result,
            wire: c,
        })
    }

    /// Selects between two elements based on this boolean's value.
    /// Returns `a` when false, `b` when true.
    ///
    /// This costs one multiplication constraint and two linear constraints.
    pub fn conditional_select(
        &self,
        dr: &mut D,
        a: &Element<'dr, D>,
        b: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        // Result = a + cond * (b - a)
        let diff = b.sub(dr, a);
        let cond_times_diff = self.element().mul(dr, &diff)?;
        Ok(a.add(dr, &cond_times_diff))
    }

    /// Conditionally enforces that two elements are equal.
    /// When this boolean is true, enforces `a == b`; when false, no constraint.
    ///
    /// This costs one multiplication constraint and three linear constraints.
    pub fn conditional_enforce_equal(
        &self,
        dr: &mut D,
        a: &Element<'dr, D>,
        b: &Element<'dr, D>,
    ) -> Result<()> {
        // Enforce: condition → (a == b)
        // Equivalent to: condition * (a - b) == 0
        // - When condition = 1: a - b = 0
        // - When condition = 0: 0 = 0 (trivially satisfied)
        let diff = a.sub(dr, b);
        let product = self.element().mul(dr, &diff)?;
        product.enforce_zero(dr)
    }

    /// Returns the witness value of this boolean.
    pub fn value(&self) -> DriverValue<D, bool> {
        self.value.clone()
    }

    /// Returns the wire associated with this boolean.
    pub fn wire(&self) -> &D::Wire {
        &self.wire
    }

    /// Converts this boolean into an [`Element`].
    pub fn element(&self) -> Element<'dr, D> {
        Element::promote(self.wire.clone(), self.value().fe())
    }
}

/// Returns a boolean indicating whether the element is zero.
///
/// Uses the standard inverse trick for zero checking in arithmetic circuits.
pub(crate) fn is_zero<'dr, D: Driver<'dr>>(
    dr: &mut D,
    x: &Element<'dr, D>,
) -> Result<Boolean<'dr, D>> {
    // We enforce the constraints:
    //
    // - x * is_zero = 0
    // - x * inv = 1 - is_zero
    //
    // Given `x != 0`, the first constraint guarantees `is_zero = 0` as desired.
    // Given `x == 0`, the first constraint leaves `is_zero` unconstrained, but
    // the second constraint reduces to `0 = 1 - is_zero`, which reduces to
    // `is_zero = 1`, as desired. `inv` always has a solution, meaning it is
    // complete. By construction, `is_zero` is boolean constrained for all
    // satisfying assignments of these two constraints.

    let is_zero = x.value().map(|v| *v == D::F::ZERO);

    // Constraint 1: x * is_zero = 0.
    let (x_wire, is_zero_wire, zero_product) = dr.mul(|| {
        Ok((
            x.value().arbitrary().take(),
            is_zero.coeff().take(),
            Coeff::Zero,
        ))
    })?;
    dr.enforce_equal(&x_wire, x.wire())?;
    dr.enforce_zero(|lc| lc.add(&zero_product))?;

    // Constraint 2: x * inv = 1 - is_zero.
    let (x_wire, _, is_not_zero) = dr.mul(|| {
        Ok((
            x.value().arbitrary().take(),
            x.value()
                .map(|x| x.invert().unwrap_or(D::F::ZERO))
                .arbitrary()
                .take(),
            is_zero.not().coeff().take(),
        ))
    })?;
    dr.enforce_equal(&x_wire, x.wire())?;
    dr.enforce_zero(|lc| lc.add(&is_not_zero).sub(&D::ONE).add(&is_zero_wire))?;

    Ok(Boolean {
        wire: is_zero_wire,
        value: is_zero,
    })
}

impl<F: Field> Write<F> for Kind![F; @Boolean<'_, _>] {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Boolean<'dr, D>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        this.element().write(dr, buf)
    }
}

impl<F: Field> Promotion<F> for Kind![F; @Boolean<'_, _>] {
    type Value = bool;

    fn promote<'dr, D: Driver<'dr, F = F>>(
        demoted: &Demoted<'dr, D, Boolean<'dr, D>>,
        witness: DriverValue<D, bool>,
    ) -> Boolean<'dr, D> {
        Boolean {
            wire: demoted.wire.clone(),
            value: witness,
        }
    }
}

/// Packs boolean slices into field elements using little-endian bit order.
///
/// The first bit in each chunk is the least significant bit.
pub fn multipack<'dr, D: Driver<'dr, F: ff::PrimeField>>(
    dr: &mut D,
    bits: &[Boolean<'dr, D>],
) -> Result<Vec<Element<'dr, D>>> {
    let mut v = vec![];
    for chunk in bits.chunks(D::F::CAPACITY as usize) {
        let value = D::just(|| {
            let mut value = D::F::ZERO;
            let mut gain = D::F::ONE;
            for bit in chunk.iter() {
                if bit.value().take() {
                    value += gain;
                }
                gain = gain.double();
            }
            value
        });

        let wire = dr.add(|mut lc| {
            for bit in chunk.iter() {
                lc = lc.add(bit.wire());
                lc = lc.gain(Coeff::Two);
            }
            lc
        });

        v.push(Element::promote(wire, value));
    }

    Ok(v)
}

impl<'dr, D: Driver<'dr>> Consistent<'dr, D> for Boolean<'dr, D> {
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        Self::alloc(dr, self.value())?.enforce_equal(dr, self)
    }
}

/// A fixed-length boolean vector with single-constraint equality checking,
/// using a fixed-linear combination technique.
pub struct BooleanVec<'dr, D: Driver<'dr>, L: Len> {
    inner: FixedVec<Boolean<'dr, D>, L>,
}

impl<'dr, D: Driver<'dr>, L: Len> BooleanVec<'dr, D, L> {
    /// Creates a new `BooleanVec` from a `FixedVec` of booleans.
    pub fn new(inner: FixedVec<Boolean<'dr, D>, L>) -> Self {
        Self { inner }
    }

    /// Consumes this `BooleanVec` and returns the inner `FixedVec`.
    pub fn into_inner(self) -> FixedVec<Boolean<'dr, D>, L> {
        self.inner
    }

    /// Allocates a `BooleanVec` from witness values.
    pub fn alloc(dr: &mut D, values: FixedVec<DriverValue<D, bool>, L>) -> Result<Self> {
        let inner = values
            .into_iter()
            .map(|v| Boolean::alloc(dr, v))
            .try_collect_fixed()?;
        Ok(Self { inner })
    }
}

impl<'dr, D: Driver<'dr>, L: Len> core::ops::Deref for BooleanVec<'dr, D, L> {
    type Target = [Boolean<'dr, D>];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'dr, D: Driver<'dr>, L: Len> Clone for BooleanVec<'dr, D, L> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<'dr, D: Driver<'dr>, L: Len> Gadget<'dr, D> for BooleanVec<'dr, D, L>
where
    D::F: PrimeField,
{
    type Kind = BooleanVecKind<L>;
}

/// The [`GadgetKind`] for [`BooleanVec`].
pub struct BooleanVecKind<L: Len> {
    _marker: PhantomData<L>,
}

// Safety: `BooleanVec` contains only `Boolean` gadgets which satisfy the `Send`
// requirement when `D::Wire` is `Send`.
unsafe impl<F: PrimeField, L: Len> GadgetKind<F> for BooleanVecKind<L> {
    type Rebind<'dr, D: Driver<'dr, F = F>> = BooleanVec<'dr, D, L>;

    fn map_gadget<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
        this: &Self::Rebind<'dr, D>,
        ndr: &mut ND,
    ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
        assert_eq!(this.inner.len(), L::len());
        let inner = this.inner.iter().map(|b| b.map(ndr)).try_collect_fixed()?;
        Ok(BooleanVec { inner })
    }

    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Self::Rebind<'dr, D2>,
        b: &Self::Rebind<'dr, D2>,
    ) -> Result<()> {
        // Chunk by F::CAPACITY to avoid field overflow, one constraint per chunk.
        let pairs: Vec<_> = a.iter().zip(b.iter()).collect();
        for chunk in pairs.chunks(F::CAPACITY as usize) {
            dr.enforce_zero(|mut lc| {
                for (a_bit, b_bit) in chunk {
                    lc = lc.add(a_bit.wire()).sub(b_bit.wire());
                    lc = lc.gain(Coeff::Two);
                }
                lc
            })?;
        }
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, L: Len> Consistent<'dr, D> for BooleanVec<'dr, D, L>
where
    D::F: PrimeField,
{
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        for b in self.iter() {
            b.enforce_consistent(dr)?;
        }
        Ok(())
    }
}

#[test]
fn test_boolean_alloc() -> Result<()> {
    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    let alloc = |bit: bool| {
        let sim = Simulator::simulate(bit, |dr, bit| {
            let allocated_bit = Boolean::alloc(dr, bit.clone())?;

            assert_eq!(allocated_bit.value().take(), bit.clone().take());
            assert_eq!(*allocated_bit.wire(), bit.fe().take());

            Ok(())
        })?;

        assert_eq!(sim.num_allocations(), 0);
        assert_eq!(sim.num_multiplications(), 1);
        assert_eq!(sim.num_linear_constraints(), 2);
        Ok(())
    };

    alloc(false)?;
    alloc(true)?;

    Ok(())
}

#[test]
fn test_conditional_select() -> Result<()> {
    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    // condition = true (returns b)
    Simulator::simulate((true, F::from(1u64), F::from(2u64)), |dr, witness| {
        let (cond, a, b) = witness.cast();
        let cond = Boolean::alloc(dr, cond)?;
        let a = Element::alloc(dr, a)?;
        let b = Element::alloc(dr, b)?;

        let result = cond.conditional_select(dr, &a, &b)?;
        assert_eq!(*result.value().take(), F::from(2u64));

        Ok(())
    })?;

    // condition = false (returns a)
    Simulator::simulate((false, F::from(1u64), F::from(2u64)), |dr, witness| {
        let (cond, a, b) = witness.cast();
        let cond = Boolean::alloc(dr, cond)?;
        let a = Element::alloc(dr, a)?;
        let b = Element::alloc(dr, b)?;

        let result = cond.conditional_select(dr, &a, &b)?;
        assert_eq!(*result.value().take(), F::from(1u64));

        Ok(())
    })?;

    Ok(())
}

#[test]
fn test_conditional_enforce_equal() -> Result<()> {
    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    // When condition is true, a == b should be enforced (and satisfied)
    let sim = Simulator::simulate((true, F::from(42u64), F::from(42u64)), |dr, witness| {
        let (cond, a, b) = witness.cast();
        let cond = Boolean::alloc(dr, cond)?;
        let a = Element::alloc(dr, a)?;
        let b = Element::alloc(dr, b)?;

        dr.reset();
        cond.conditional_enforce_equal(dr, &a, &b)?;
        Ok(())
    })?;

    assert_eq!(sim.num_multiplications(), 1);
    assert_eq!(sim.num_linear_constraints(), 3);

    // When condition is false, constraint is trivially satisfied even if a != b
    Simulator::simulate((false, F::from(1u64), F::from(2u64)), |dr, witness| {
        let (cond, a, b) = witness.cast();
        let cond = Boolean::alloc(dr, cond)?;
        let a = Element::alloc(dr, a)?;
        let b = Element::alloc(dr, b)?;

        cond.conditional_enforce_equal(dr, &a, &b)?;
        Ok(())
    })?;

    Ok(())
}

#[test]
fn test_multipack() -> Result<()> {
    use alloc::vec::Vec;

    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    let bits = (0..1000).map(|i| i % 2 == 0).collect::<Vec<_>>();

    Simulator::simulate(bits, |dr, bits| {
        let bits = (0..1000)
            .map(|i| Boolean::alloc(dr, bits.view().map(|b| b[i])))
            .collect::<Result<Vec<_>>>()?;

        let vals = multipack(dr, &bits)?;
        assert_eq!(vals.len(), 4);

        for val in vals {
            assert_eq!(val.value().take(), val.wire());
        }

        Ok(())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragu_core::maybe::Maybe;

    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    #[test]
    fn test_is_equal_same() -> Result<()> {
        let sim = Simulator::simulate((F::from(123u64), F::from(123u64)), |dr, witness| {
            let (a_val, b_val) = witness.cast();
            let a = Element::alloc(dr, a_val)?;
            let b = Element::alloc(dr, b_val)?;

            dr.reset();
            let eq = a.is_equal(dr, &b)?;

            assert!(eq.value().take(), "Expected a == b");
            Ok(())
        })?;

        assert_eq!(sim.num_multiplications(), 2);
        assert_eq!(sim.num_linear_constraints(), 4);

        Ok(())
    }

    #[test]
    fn test_is_not_equal() -> Result<()> {
        Simulator::simulate((F::from(1u64), F::from(123u64)), |dr, witness| {
            let (a_val, b_val) = witness.cast();
            let a = Element::alloc(dr, a_val)?;
            let b = Element::alloc(dr, b_val)?;

            dr.reset();
            let eq = a.is_equal(dr, &b)?;

            assert!(!eq.value().take(), "Expected a != b");
            Ok(())
        })?;

        Ok(())
    }
}

#[test]
fn test_multipack_vector() -> Result<()> {
    use alloc::vec::Vec;

    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    let bits = vec![false, true, true, false, true]; // 0b10110 = 22
    Simulator::simulate(bits, |dr, bits| {
        let bits = (0..5)
            .map(|i| Boolean::alloc(dr, bits.view().map(|b| b[i])))
            .collect::<Result<Vec<_>>>()?;

        let vals = multipack(dr, &bits)?;
        assert_eq!(vals.len(), 1);
        assert_eq!(*vals[0].value().take(), F::from(22));
        assert_eq!(*vals[0].wire(), F::from(22));

        Ok(())
    })?;

    Ok(())
}

#[test]
fn test_boolean_vec_equality() -> Result<()> {
    use crate::vec::ConstLen;
    use ragu_core::gadgets::Gadget;
    type F = ragu_pasta::Fp;
    type Simulator = crate::Simulator<F>;

    let bits = vec![true, false, true, true, false, false, true, true];
    let sim = Simulator::simulate((bits.clone(), bits), |dr, witness| {
        let (a_bits, b_bits) = witness.cast();
        let a: BooleanVec<_, ConstLen<8>> = BooleanVec::new(
            (0..8)
                .map(|i| Boolean::alloc(dr, a_bits.view().map(|b| b[i])))
                .try_collect_fixed()?,
        );
        let b: BooleanVec<_, ConstLen<8>> = BooleanVec::new(
            (0..8)
                .map(|i| Boolean::alloc(dr, b_bits.view().map(|b| b[i])))
                .try_collect_fixed()?,
        );
        dr.reset();
        a.enforce_equal(dr, &b)?;

        Ok(())
    })?;

    assert_eq!(sim.num_linear_constraints(), 1);

    Ok(())
}
