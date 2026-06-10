//! [`Write`] and [`GadgetEquals`] implementations for foreign standard library
//! types.
//!
//! Enables types like `()`, arrays, tuples, and `Box<T>` to participate in
//! circuit I/O and equality checking.

use alloc::boxed::Box;
use core::marker::PhantomData;

use ragu_arithmetic::ff::Field;
use ragu_core::{Result, drivers::Driver, gadgets::Bound};

use crate::{
    comparison::GadgetEquals,
    io::{Buffer, Write},
};

impl<F: Field> Write<F> for () {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        _: &(),
        _: &mut D,
        _: &mut B,
    ) -> Result<()> {
        Ok(())
    }
}

impl<F: Field> GadgetEquals<F> for () {
    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        _: &mut D1,
        _: &Bound<'dr, D2, Self>,
        _: &Bound<'dr, D2, Self>,
    ) -> Result<()> {
        Ok(())
    }
}

impl<F: Field, G: Write<F>, const N: usize> Write<F> for [PhantomData<G>; N] {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &[Bound<'dr, D, G>; N],
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        for item in this {
            G::write_gadget(item, dr, buf)?;
        }
        Ok(())
    }
}

impl<F: Field, G: GadgetEquals<F>, const N: usize> GadgetEquals<F> for [PhantomData<G>; N] {
    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Bound<'dr, D2, Self>,
        b: &Bound<'dr, D2, Self>,
    ) -> Result<()> {
        for (a, b) in a.iter().zip(b.iter()) {
            G::enforce_equal_gadget(dr, a, b)?;
        }
        Ok(())
    }
}

impl<F: Field, G1: Write<F>, G2: Write<F>> Write<F> for (PhantomData<G1>, PhantomData<G2>) {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &(Bound<'dr, D, G1>, Bound<'dr, D, G2>),
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        G1::write_gadget(&this.0, dr, buf)?;
        G2::write_gadget(&this.1, dr, buf)?;
        Ok(())
    }
}

impl<F: Field, G1: GadgetEquals<F>, G2: GadgetEquals<F>> GadgetEquals<F>
    for (PhantomData<G1>, PhantomData<G2>)
{
    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Bound<'dr, D2, Self>,
        b: &Bound<'dr, D2, Self>,
    ) -> Result<()> {
        G1::enforce_equal_gadget(dr, &a.0, &b.0)?;
        G2::enforce_equal_gadget(dr, &a.1, &b.1)
    }
}

impl<F: Field, G: Write<F>> Write<F> for PhantomData<Box<G>> {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Box<Bound<'dr, D, G>>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        G::write_gadget(this, dr, buf)
    }
}

impl<F: Field, G: GadgetEquals<F>> GadgetEquals<F> for PhantomData<Box<G>> {
    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Bound<'dr, D2, Self>,
        b: &Bound<'dr, D2, Self>,
    ) -> Result<()> {
        G::enforce_equal_gadget(dr, a, b)
    }
}
