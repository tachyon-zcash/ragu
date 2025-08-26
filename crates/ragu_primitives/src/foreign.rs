use ff::Field;
use ragu_core::{Result, drivers::Driver};

use alloc::boxed::Box;

use crate::serialize::{Buffer, GadgetSerialize};

impl<F: Field> GadgetSerialize<F> for () {
    fn serialize_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        _: &(),
        _: &mut D,
        _: &mut B,
    ) -> Result<()> {
        Ok(())
    }
}

impl<F: Field, G: GadgetSerialize<F>, const N: usize> GadgetSerialize<F>
    for [::core::marker::PhantomData<G>; N]
{
    fn serialize_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &[G::Rebind<'dr, D>; N],
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        for item in this {
            G::serialize_gadget(item, dr, buf)?;
        }
        Ok(())
    }
}

impl<F: Field, G1: GadgetSerialize<F>, G2: GadgetSerialize<F>> GadgetSerialize<F>
    for (
        ::core::marker::PhantomData<G1>,
        ::core::marker::PhantomData<G2>,
    )
{
    fn serialize_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &(G1::Rebind<'dr, D>, G2::Rebind<'dr, D>),
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        G1::serialize_gadget(&this.0, dr, buf)?;
        G2::serialize_gadget(&this.1, dr, buf)?;
        Ok(())
    }
}

impl<F: Field, G: GadgetSerialize<F>> GadgetSerialize<F> for ::core::marker::PhantomData<Box<G>> {
    fn serialize_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Box<G::Rebind<'dr, D>>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        G::serialize_gadget(this, dr, buf)
    }
}
