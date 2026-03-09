//! Zero-cost dummy [`Driver`] implementation for
//! [`PhantomData<F>`](core::marker::PhantomData).
//!
//! `PhantomData<F>` implements [`Driver`] with `Wire = ()` and `MaybeKind =
//! Empty`. All constraint methods are no-ops, and witness closures are never
//! called — the compiler dead-code eliminates them entirely.
//!
//! This exists for three reasons:
//!
//! 1. **Type-level [`GadgetKind`] extraction.** The `Kind!` macro uses
//!    `PhantomData<F>` as a universal dummy driver to satisfy the type system
//!    when extracting a gadget's driver-agnostic kind (e.g. `Kind![F;
//!    Boolean<'_, _>]` expands to `<Boolean<'static, PhantomData<F>> as
//!    Gadget<…>>::Kind`).
//!
//! 2. **Wire counting and stripping.** [`Gadget::num_wires()`] and
//!    [`Emulator::wires()`] use `PhantomData<F>` as a [`WireMap`] destination
//!    to count or extract wires without materializing a real driver.
//!
//! 3. **Testing.** Used as a lightweight [`WireMap`] destination in unit tests
//!    where no actual constraint system is needed.
//!
//! [`GadgetKind`]: crate::gadgets::GadgetKind
//! [`Gadget::num_wires()`]: crate::gadgets::Gadget::num_wires
//! [`Emulator::wires()`]: super::emulator::Emulator::wires
//! [`WireMap`]: crate::convert::WireMap

use super::{Coeff, Driver, DriverTypes, Field, Result};

/// Dummy driver that does absolutely nothing. All gates and constraints are
/// no-ops, and witness closures are dead-code eliminated via `MaybeKind =
/// Empty`.
impl<F: Field> Driver<'_> for core::marker::PhantomData<F> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        Ok(())
    }
}

impl<F: Field> DriverTypes for core::marker::PhantomData<F> {
    type ImplField = F;
    type ImplWire = ();
    type MaybeKind = crate::maybe::Empty;
    type LCadd = ();
    type LCenforce = ();
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::marker::PhantomData;

    use crate::Result;
    use crate::drivers::{Coeff, Driver};
    use crate::maybe::Empty;
    use ragu_pasta::Fp;

    type F = Fp;

    #[test]
    fn phantom_closures_never_invoked() -> Result<()> {
        let mut dr = PhantomData::<F>;
        let called = Cell::new(0u32);

        dr.mul(|| {
            called.set(called.get() + 1);
            Ok((Coeff::One, Coeff::One, Coeff::One))
        })?;

        dr.add(|lc| {
            called.set(called.get() + 1);
            lc
        });

        dr.enforce_zero(|lc| {
            called.set(called.get() + 1);
            lc
        })?;

        dr.alloc(|| {
            called.set(called.get() + 1);
            Ok(Coeff::One)
        })?;

        dr.constant(Coeff::One);

        assert_eq!(called.get(), 0);
        Ok(())
    }

    #[test]
    fn phantom_mul_returns_unit_triple() -> Result<()> {
        let mut dr = PhantomData::<F>;
        let (_a, _b, _c): ((), (), ()) = dr.mul(|| panic!("must not be called"))?;
        Ok(())
    }

    #[test]
    fn phantom_add_returns_unit() {
        let mut dr = PhantomData::<F>;
        let _: () = dr.add(|_lc| panic!("must not be called"));
    }

    #[test]
    fn phantom_enforce_zero_succeeds() -> Result<()> {
        let mut dr = PhantomData::<F>;
        dr.enforce_zero(|_lc| panic!("must not be called"))?;
        Ok(())
    }

    #[test]
    fn phantom_alloc_returns_unit() -> Result<()> {
        let mut dr = PhantomData::<F>;
        let _: () = dr.alloc(|| panic!("must not be called"))?;
        Ok(())
    }

    #[test]
    fn phantom_constant_returns_unit() {
        let mut dr = PhantomData::<F>;
        let _: () = dr.constant(Coeff::Arbitrary(F::from(42)));
    }

    #[test]
    fn phantom_enforce_equal_succeeds() -> Result<()> {
        let mut dr = PhantomData::<F>;
        dr.enforce_equal(&(), &())?;
        Ok(())
    }

    #[test]
    fn phantom_one_is_unit() {
        let _: () = PhantomData::<F>::ONE;
    }

    #[test]
    fn phantom_just_and_try_just_skip_closures() -> Result<()> {
        let _: Empty = PhantomData::<F>::just(|| panic!("must not be called"));
        let _: Empty =
            PhantomData::<F>::try_just(|| -> Result<()> { panic!("must not be called") })?;
        Ok(())
    }
}
