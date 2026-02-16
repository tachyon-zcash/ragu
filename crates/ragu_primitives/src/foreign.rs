//! [`Write`] implementations for foreign standard library types.
//!
//! Enables types like `()`, arrays, tuples, and `Box<T>` to participate in
//! the circuit IO system by implementing the [`Write`] trait.

use ff::Field;
use ragu_core::{Result, drivers::Driver, gadgets::Bound};

use alloc::boxed::Box;

use crate::io::{Buffer, Write};

impl<F: Field> Write<F> for () {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        _: &(),
        _: &mut D,
        _: &mut B,
    ) -> Result<()> {
        Ok(())
    }
}

impl<F: Field, G: Write<F>, const N: usize> Write<F> for [::core::marker::PhantomData<G>; N] {
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

impl<F: Field, G1: Write<F>, G2: Write<F>> Write<F>
    for (
        ::core::marker::PhantomData<G1>,
        ::core::marker::PhantomData<G2>,
    )
{
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

impl<F: Field, G: Write<F>> Write<F> for ::core::marker::PhantomData<Box<G>> {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Box<Bound<'dr, D, G>>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        G::write_gadget(this, dr, buf)
    }
}
