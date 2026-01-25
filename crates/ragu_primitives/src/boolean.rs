use arithmetic::Coeff;
use ff::{Field, PrimeField};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Consistent, Gadget, Kind},
    maybe::Maybe,
};

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
    /// The wire that has a value of either `0` or `1`.
    #[ragu(wire)]
    wire: D::Wire,

    /// The witness value for the value of this boolean.
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

        // enforces a = b  =>  c = a^2
        dr.enforce_equal(&a, &b)?;

        // enforces a = c  =>  a = a^2
        //                 =>  (a - 0) * (a - 1) = 0
        //                 =>  (a = 0) OR (a = 1)
        dr.enforce_equal(&a, &c)?;

        // NB: We can take any of the three wires we want.
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

/// Returns a boolean indicating whether the element is zero, using the standard
/// "inverse trick" for zero checking in arithmetic circuits.
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

/// Packs boolean slices into values depending on the capacity of the prime
/// field to store data.
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
        // Enforce the bit constraint
        let (a, b, c) = dr.mul(|| {
            let v = self.value.coeff().take();
            Ok((v, v, v))
        })?;
        dr.enforce_equal(&a, self.wire())?;
        dr.enforce_equal(&b, self.wire())?;
        dr.enforce_equal(&c, self.wire())?;
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
