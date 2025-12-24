//! Comparison gadget for field elements.

use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, LinearExpression},
    maybe::Maybe,
};

use crate::{Boolean, Element};

/// Compares two elements and returns a boolean indicating whether they are equal.
/// Uses the standard "inverse trick" for equality checking in arithmetic circuits.
pub fn is_equal<'dr, D: Driver<'dr>>(
    dr: &mut D,
    a: &Element<'dr, D>,
    b: &Element<'dr, D>,
) -> Result<Boolean<'dr, D>> {
    let diff = a.sub(dr, b);

    let is_equal_witness = D::just(|| *diff.value().take() == D::F::ZERO);
    let diff_inv = D::just(|| diff.value().take().invert().unwrap_or(D::F::ZERO));

    let is_equal_fe = || {
        if *is_equal_witness.snag() {
            D::F::ONE
        } else {
            D::F::ZERO
        }
    };
    let diff_coeff = || Coeff::Arbitrary(*diff.value().take());

    // Constraint: diff * inv = 1 - is_eq.
    let (diff_wire, _, one_minus_is_equal) = dr.mul(|| {
        Ok((
            diff_coeff(),
            Coeff::Arbitrary(*diff_inv.snag()),
            Coeff::Arbitrary(D::F::ONE - is_equal_fe()),
        ))
    })?;
    dr.enforce_equal(&diff_wire, diff.wire())?;
    let is_equal_wire = dr.add(|lc| lc.add(&D::ONE).sub(&one_minus_is_equal));

    // Constraint: diff * is_eq = 0.
    let (diff_wire, is_equal_wire_2, zero_product) =
        dr.mul(|| Ok((diff_coeff(), Coeff::Arbitrary(is_equal_fe()), Coeff::Zero)))?;
    dr.enforce_equal(&diff_wire, diff.wire())?;
    dr.enforce_equal(&is_equal_wire_2, &is_equal_wire)?;
    dr.enforce_zero(|lc| lc.add(&zero_product))?;

    Ok(Boolean::promote(is_equal_wire, is_equal_witness))
}

/// Convience method that compares an element against the constant ONE
/// and returns a boolean gadget.
pub fn is_one<'dr, D: Driver<'dr>>(dr: &mut D, a: &Element<'dr, D>) -> Result<Boolean<'dr, D>> {
    is_equal(dr, a, &Element::one())
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
            let eq = is_equal(dr, &a, &b)?;

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
            let eq = is_equal(dr, &a, &b)?;

            assert!(!eq.value().take(), "Expected a != b");
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_is_equal_one() -> Result<()> {
        Simulator::simulate(F::ONE, |dr, witness| {
            let a = Element::alloc(dr, witness)?;

            dr.reset();
            let eq = is_one(dr, &a)?;

            assert!(eq.value().take(), "Expected a == ONE");
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_is_equal_zero() -> Result<()> {
        Simulator::simulate((F::ZERO, F::ZERO), |dr, witness| {
            let (a_val, b_val) = witness.cast();
            let a = Element::alloc(dr, a_val)?;
            let b = Element::alloc(dr, b_val)?;

            dr.reset();
            let eq = is_equal(dr, &a, &b)?;

            assert!(eq.value().take(), "Expected 0 == 0");
            Ok(())
        })?;

        Ok(())
    }
}
