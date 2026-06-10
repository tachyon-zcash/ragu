use ragu_arithmetic::{
    Coeff,
    ff::{Field, PrimeField},
};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, Kind},
    maybe::Maybe,
};

use crate::{
    Element, GadgetExt,
    comparison::GadgetEquals,
    consistent::Consistent,
    io::{Buffer, Write},
};

/// An [`Element`] that has been constrained nonzero in the constraint system.
///
/// See [`Element::enforce_nonzero`].
///
/// [`Nonzero`] dereferences to the underlying [`Element`], so all of
/// [`Element`]'s methods are available directly on a [`Nonzero`].
#[derive(Gadget, Write, GadgetEquals)]
pub struct Nonzero<'dr, D: Driver<'dr>> {
    element: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> Nonzero<'dr, D> {
    /// Wraps `element` without checking the nonzero invariant.
    ///
    /// The caller is responsible for having emitted constraints that prove
    /// `element` is nonzero.
    pub(crate) fn new_unchecked(element: Element<'dr, D>) -> Self {
        Self { element }
    }

    /// Consumes `self` and returns the underlying [`Element`].
    pub fn into_inner(self) -> Element<'dr, D> {
        self.element
    }

    /// Negates this element. The result is nonzero since
    /// $-a = 0 \implies a = 0$.
    pub fn negate(&self, dr: &mut D) -> Self {
        Self::new_unchecked(self.element.negate(dr))
    }

    /// Squares this element. The result is nonzero since `F` is an integral
    /// domain.
    ///
    /// This costs one gate and two constraints.
    pub fn square(&self, dr: &mut D) -> Result<Self> {
        Ok(Self::new_unchecked(self.element.square(dr)?))
    }

    /// Multiplies this element by another nonzero element. The result is
    /// nonzero since `F` is an integral domain.
    ///
    /// This costs one gate and two constraints.
    pub fn mul(&self, dr: &mut D, other: &Self) -> Result<Self> {
        Ok(Self::new_unchecked(self.element.mul(dr, &other.element)?))
    }

    /// Divides this element by `divisor` and returns the quotient. The result
    /// is nonzero since `F` is an integral domain.
    ///
    /// This costs one gate and two constraints.
    pub fn divide(&self, dr: &mut D, divisor: &Self) -> Result<Self> {
        Ok(Self::new_unchecked(self.element.divide(dr, divisor)?))
    }
}

impl<'dr, D: Driver<'dr, F: PrimeField>> Nonzero<'dr, D> {
    /// Monomorphization-time guard that `D::F` has odd characteristic, which
    /// is what makes [`double`](Self::double) preserve nonzeroness: $2x = 0$
    /// has no nonzero solution iff $\mathrm{char}(F) \neq 2$.
    ///
    /// $S$ is the 2-adicity of $p - 1$ where $p = \mathrm{char}(D::F)$. For
    /// any odd prime $p$, $p - 1$ is even, so $S \geq 1$. The only prime
    /// field where $S = 0$ is $\mathbb{F}_2$; bounding on [`PrimeField`]
    /// already rules out extension fields, so together this excludes every
    /// char-2 field.
    pub const ASSERT_ODD_CHAR: () = assert!(
        <D::F as PrimeField>::S >= 1,
        "Nonzero::double requires a field of odd characteristic",
    );

    /// Doubles this element. The result is nonzero since `char(F) > 2`.
    pub fn double(&self, dr: &mut D) -> Self {
        let () = Self::ASSERT_ODD_CHAR;
        Self::new_unchecked(self.element.double(dr))
    }
}

impl<'dr, D: Driver<'dr>> core::ops::Deref for Nonzero<'dr, D> {
    type Target = Element<'dr, D>;

    fn deref(&self) -> &Element<'dr, D> {
        &self.element
    }
}

impl<'dr, D: Driver<'dr>> Consistent<'dr, D> for Nonzero<'dr, D> {
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        self.enforce_invertible(dr)?;
        Ok(())
    }
}

/// An invertible [`Element`].
///
/// This gadget represents a nonzero [`Element`] with a known multiplicative
/// inverse, accessible via [`element`](Self::element) and
/// [`inverse`](Self::inverse).
///
/// Inversion is free, since the inverse is located within the gadget.
#[derive(Gadget)]
pub struct Invertible<'dr, D: Driver<'dr>> {
    element: Nonzero<'dr, D>,
    inverse: Nonzero<'dr, D>,
}

impl<'dr, D: Driver<'dr>> Invertible<'dr, D> {
    /// Allocate an [`Invertible`] field element.
    ///
    /// This will be unsatisfied (and fail to synthesize) if `value` is zero.
    ///
    /// Computing the inverse witness costs a field inversion. If the inverse is
    /// already known, prefer
    /// [`alloc_with_advice`](Invertible::alloc_with_advice).
    ///
    /// This costs one gate and one constraint.
    pub fn alloc(dr: &mut D, value: DriverValue<D, D::F>) -> Result<Self> {
        let inverse_value = D::try_just(|| {
            value
                .snag()
                .invert()
                .into_option()
                .ok_or_else(|| Error::InvalidWitness("division by zero".into()))
        })?;
        Self::alloc_with_advice(dr, value, inverse_value)
    }

    /// Allocate an [`Invertible`] field element given its inverse as advice.
    ///
    /// This will be unsatisfied if `value` is zero or if `inverse_value` is not
    /// really its multiplicative inverse.
    ///
    /// This costs one gate and one constraint.
    pub fn alloc_with_advice(
        dr: &mut D,
        value: DriverValue<D, D::F>,
        inverse_value: DriverValue<D, D::F>,
    ) -> Result<Self> {
        let (a, b, c) = dr.mul(|| {
            Ok((
                Coeff::Arbitrary(*value.snag()),
                Coeff::Arbitrary(*inverse_value.snag()),
                Coeff::One,
            ))
        })?;
        dr.enforce_equal(&c, &D::ONE)?;

        Ok(Self {
            element: Nonzero::new_unchecked(Element::promote(a, value)),
            inverse: Nonzero::new_unchecked(Element::promote(b, inverse_value)),
        })
    }

    /// Returns the multiplicative inverse of `self`. This is free.
    pub fn invert(&self) -> Self {
        Self {
            element: self.inverse.clone(),
            inverse: self.element.clone(),
        }
    }

    /// Returns the underlying [`Nonzero`] element.
    pub fn element(&self) -> &Nonzero<'dr, D> {
        &self.element
    }

    /// Returns the inverse of the underlying element, also as a [`Nonzero`].
    pub fn inverse(&self) -> &Nonzero<'dr, D> {
        &self.inverse
    }

    /// Consumes `self` and returns the underlying [`Nonzero`] element.
    pub fn into_element(self) -> Nonzero<'dr, D> {
        self.element
    }

    /// Consumes `self` and returns the inverse as a [`Nonzero`].
    pub fn into_inverse(self) -> Nonzero<'dr, D> {
        self.inverse
    }
}

impl<'dr, D: Driver<'dr>> Consistent<'dr, D> for Invertible<'dr, D> {
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        let value = D::just(|| *self.element.value().take());
        let inverse_value = D::just(|| *self.inverse.value().take());
        Self::alloc_with_advice(dr, value, inverse_value)?.enforce_conservative_equal(dr, self)
    }
}

impl<F: Field> GadgetEquals<F> for Kind![F; @Invertible<'_, _>] {
    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Invertible<'dr, D2>,
        b: &Invertible<'dr, D2>,
    ) -> Result<()> {
        // Soundness: comparing only the element suffices because
        // `alloc_with_advice` enforces `element * inverse = 1`, so equal
        // elements have equal inverses in any satisfied assignment.
        a.element.enforce_equal(dr, &b.element)
    }
}

/// Encodes only the element; the inverse is derivable and is omitted.
impl<F: Field> Write<F> for Kind![F; @Invertible<'_, _>] {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Invertible<'dr, D>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        this.element().write(dr, buf)
    }
}

/// Batches deferred nonzero proofs so several factors can share one final
/// nonzero check.
///
/// Folding an element into the bank multiplies it into a running product and
/// trusts it nonzero; when the scope closes, the product is constrained
/// nonzero, retroactively validating every factor.
///
/// [`NonzeroBank`] is only constructible by [`NonzeroBank::scope`] or by
/// internal callers that assert every fold is nonzero by structural argument.
pub struct NonzeroBank<'dr, D: Driver<'dr>> {
    // `None` is unchecked mode: `fold` emits no constraint and `enforce` is a
    // no-op. `Some(p)` is discharging mode: `fold` multiplies the new factor
    // into `p` and the closing scope constrains `p != 0`.
    product: Option<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> NonzeroBank<'dr, D> {
    /// Constructs a discharging bank. Only callable inside the crate; users
    /// reach this via [`scope`](Self::scope).
    pub(crate) fn new() -> Self {
        Self {
            product: Some(Element::one()),
        }
    }

    /// Constructs a bank that asserts every fold is nonzero by external
    /// argument. No constraints are emitted by `fold` or by dropping the
    /// bank. Internal use only.
    pub(crate) fn new_unchecked() -> Self {
        Self { product: None }
    }

    /// Folds `elem` into the running product and returns it typed as [`Nonzero`].
    ///
    /// In discharging mode, the nonzero proof is deferred until the enclosing
    /// [`scope`](Self::scope) succeeds. Errors from that scope must be
    /// propagated.
    ///
    /// This costs one gate and two constraints in discharging mode, and zero
    /// gates and zero constraints in unchecked mode.
    pub fn fold(&mut self, dr: &mut D, elem: Element<'dr, D>) -> Result<Nonzero<'dr, D>> {
        if let Some(product) = &mut self.product {
            *product = product.mul(dr, &elem)?;
        }
        Ok(Nonzero::new_unchecked(elem))
    }

    /// Discharges a discharging bank by constraining its product nonzero.
    /// In unchecked mode this is a no-op. Only callable inside the crate;
    /// users reach this via [`scope`](Self::scope).
    pub(crate) fn enforce(self, dr: &mut D) -> Result<()> {
        if let Some(product) = self.product {
            product.enforce_nonzero(dr)?;
        }
        Ok(())
    }

    /// Opens a scope in which nonzero proofs can be batched.
    ///
    /// On success, the bank is discharged before returning. On error, the bank
    /// is not discharged.
    ///
    /// Callers must propagate errors from this function. Swallowing an error
    /// can skip deferred nonzero checks and lead to unsound circuit code.
    ///
    /// This costs one gate and two constraints for the final discharge, plus
    /// one gate and two constraints per [`fold`](Self::fold) in discharging
    /// mode, on top of whatever the body itself emits.
    pub fn scope<T>(
        dr: &mut D,
        body: impl FnOnce(&mut D, &mut NonzeroBank<'dr, D>) -> Result<T>,
    ) -> Result<T> {
        let mut bank = Self::new();
        let result = body(dr, &mut bank)?;
        bank.enforce(dr)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::ff::Field;

    use super::*;
    use crate::{Simulator, allocator::Standard};

    type F = ragu_pasta::Fp;
    type Sim = Simulator<F>;

    #[test]
    fn test_alloc_nonzero() -> Result<()> {
        let alloc = |a: F| {
            let sim = Sim::simulate(a, |dr, witness| {
                let inv = Invertible::alloc(dr, witness.clone())?;
                assert_eq!(*inv.element().value().take(), *witness.snag());
                assert_eq!(
                    *inv.element().value().take() * inv.inverse().value().take(),
                    F::ONE
                );
                Ok(())
            })?;
            assert_eq!(sim.num_gates(), 1);
            assert_eq!(sim.num_constraints(), 1);
            Ok(())
        };

        alloc(F::from(4578u64))?;
        alloc(F::from(1u64))?;
        Ok(())
    }

    #[test]
    fn test_alloc_zero_fails() {
        let result = Sim::simulate(F::ZERO, |dr, witness| {
            Invertible::alloc(dr, witness.clone())?;
            Ok(())
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_invert_swaps_for_free() -> Result<()> {
        Sim::simulate(F::from(7u64), |dr, witness| {
            let inv = Invertible::alloc(dr, witness.clone())?;
            let a_wire = *inv.element().wire();
            let b_wire = *inv.inverse().wire();

            dr.reset();
            let swapped = inv.invert();

            assert_eq!(*swapped.element().wire(), b_wire);
            assert_eq!(*swapped.inverse().wire(), a_wire);
            Ok(())
        })?;

        let sim = Sim::simulate(F::from(7u64), |dr, witness| {
            let inv = Invertible::alloc(dr, witness.clone())?;
            dr.reset();
            let _ = inv.invert();
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 0);
        assert_eq!(sim.num_constraints(), 0);

        Ok(())
    }

    #[test]
    fn test_enforce_consistent() -> Result<()> {
        let sim = Sim::simulate(F::from(5u64), |dr, witness| {
            let inv = Invertible::alloc(dr, witness.clone())?;
            dr.reset();
            inv.enforce_consistent(dr)?;
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 1);
        assert_eq!(sim.num_constraints(), 3);
        Ok(())
    }

    #[test]
    fn test_gadget_ext_enforce_equal_uses_gadget_equals() -> Result<()> {
        let sim = Sim::simulate(F::from(5u64), |dr, witness| {
            let a = Invertible::alloc(dr, witness.clone())?;
            let b = Invertible::alloc(dr, witness.clone())?;
            dr.reset();
            a.enforce_equal(dr, &b)?;
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 0);
        assert_eq!(sim.num_constraints(), 1);
        Ok(())
    }

    #[test]
    fn test_invertible_gadget_equals_uses_represented_value() -> Result<()> {
        let sim = Sim::simulate(F::from(5u64), |dr, witness| {
            let value = *witness.snag();
            let valid = Invertible::alloc(dr, witness.clone())?;
            let malformed = Invertible {
                element: Nonzero::new_unchecked(Element::constant(dr, value)),
                inverse: Nonzero::new_unchecked(Element::constant(dr, F::from(9u64))),
            };

            dr.reset();
            malformed.enforce_equal(dr, &valid)?;
            assert_eq!(dr.num_gates(), 0);
            assert_eq!(dr.num_constraints(), 1);

            dr.reset();
            assert!(malformed.enforce_conservative_equal(dr, &valid).is_err());
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 0);
        Ok(())
    }

    #[test]
    fn test_enforce_nonzero_succeeds() -> Result<()> {
        let sim = Sim::simulate(F::from(7u64), |dr, witness| {
            let allocator = &mut Standard::new();
            let element = Element::alloc(dr, allocator, witness.clone())?;
            dr.reset();
            let nonzero = element.enforce_nonzero(dr)?;
            assert_eq!(*nonzero.value().take(), *witness.snag());
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 1);
        assert_eq!(sim.num_constraints(), 2);
        Ok(())
    }

    #[test]
    fn test_enforce_nonzero_fails_for_zero() {
        let result = Sim::simulate(F::ZERO, |dr, witness| {
            let allocator = &mut Standard::new();
            let element = Element::alloc(dr, allocator, witness.clone())?;
            element.enforce_nonzero(dr)?;
            Ok(())
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_nonzero_square_cost() -> Result<()> {
        let sim = Sim::simulate(F::from(7u64), |dr, witness| {
            let allocator = &mut Standard::new();
            let element = Element::alloc(dr, allocator, witness.clone())?.enforce_nonzero(dr)?;

            dr.reset();
            let _ = element.square(dr)?;
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 1);
        assert_eq!(sim.num_constraints(), 2);
        Ok(())
    }

    #[test]
    fn test_nonzero_mul_cost() -> Result<()> {
        let sim = Sim::simulate((F::from(7u64), F::from(11u64)), |dr, witness| {
            let (a, b) = witness.cast();
            let allocator = &mut Standard::new();
            let a = Element::alloc(dr, allocator, a.clone())?.enforce_nonzero(dr)?;
            let b = Element::alloc(dr, allocator, b.clone())?.enforce_nonzero(dr)?;

            dr.reset();
            let _ = a.mul(dr, &b)?;
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 1);
        assert_eq!(sim.num_constraints(), 2);
        Ok(())
    }

    #[test]
    fn test_nonzero_divide_cost() -> Result<()> {
        let sim = Sim::simulate((F::from(7u64), F::from(11u64)), |dr, witness| {
            let (a, b) = witness.cast();
            let allocator = &mut Standard::new();
            let a = Element::alloc(dr, allocator, a.clone())?.enforce_nonzero(dr)?;
            let b = Element::alloc(dr, allocator, b.clone())?.enforce_nonzero(dr)?;

            dr.reset();
            let _ = a.divide(dr, &b)?;
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 1);
        assert_eq!(sim.num_constraints(), 2);
        Ok(())
    }

    #[test]
    fn test_nonzero_bank_scope_discharges() -> Result<()> {
        let sim = Sim::simulate(F::from(7u64), |dr, witness| {
            let allocator = &mut Standard::new();
            let element = Element::alloc(dr, allocator, witness.clone())?;
            dr.reset();
            NonzeroBank::scope(dr, |dr, bank| {
                let _ = bank.fold(dr, element.clone())?;
                Ok(())
            })
        })?;
        assert_eq!(sim.num_gates(), 2);
        assert_eq!(sim.num_constraints(), 4);
        Ok(())
    }

    #[test]
    fn test_nonzero_bank_fold_costs_in_discharging_mode() -> Result<()> {
        let sim = Sim::simulate(F::from(7u64), |dr, witness| {
            let allocator = &mut Standard::new();
            let element = Element::alloc(dr, allocator, witness.clone())?;
            let mut bank = NonzeroBank::new();

            dr.reset();
            let _ = bank.fold(dr, element)?;
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 1);
        assert_eq!(sim.num_constraints(), 2);
        Ok(())
    }

    #[test]
    fn test_nonzero_bank_fold_costs_in_unchecked_mode() -> Result<()> {
        let sim = Sim::simulate(F::from(7u64), |dr, witness| {
            let allocator = &mut Standard::new();
            let element = Element::alloc(dr, allocator, witness.clone())?;
            let mut bank = NonzeroBank::new_unchecked();

            dr.reset();
            let _ = bank.fold(dr, element)?;
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 0);
        assert_eq!(sim.num_constraints(), 0);
        Ok(())
    }

    #[test]
    fn test_nonzero_bank_scope_rejects_zero_fold() {
        let result = Sim::simulate(F::ZERO, |dr, witness| {
            let allocator = &mut Standard::new();
            let element = Element::alloc(dr, allocator, witness.clone())?;
            NonzeroBank::scope(dr, |dr, bank| {
                let _ = bank.fold(dr, element.clone())?;
                Ok(())
            })
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_nonzero_enforce_consistent() -> Result<()> {
        let sim = Sim::simulate(F::from(5u64), |dr, witness| {
            let allocator = &mut Standard::new();
            let element = Element::alloc(dr, allocator, witness.clone())?;
            let nonzero = element.enforce_nonzero(dr)?;
            dr.reset();
            nonzero.enforce_consistent(dr)?;
            Ok(())
        })?;
        assert_eq!(sim.num_gates(), 1);
        assert_eq!(sim.num_constraints(), 2);
        Ok(())
    }
}
