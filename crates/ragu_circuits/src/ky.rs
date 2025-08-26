use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{DirectSum, Driver, DriverTypes},
    maybe::{Always, MaybeKind},
};
use ragu_primitives::GadgetExt;

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use super::Circuit;

struct PublicInputs<F>(PhantomData<F>);

impl<F: Field> DriverTypes for PublicInputs<F> {
    type ImplField = F;
    type ImplWire = F;
    type MaybeKind = Always<()>;
    type LCadd = DirectSum<F>;
    type LCenforce = ();
}

impl<F: Field> Driver<'_> for PublicInputs<F> {
    type F = F;
    type Wire = F;
    const ONE: Self::Wire = F::ONE;

    fn alloc(&mut self, f: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        Ok(f()?.value())
    }

    fn mul(
        &mut self,
        f: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let (a, b, c) = f()?;
        Ok((a.value(), b.value(), c.value()))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        lc(DirectSum::default()).value
    }

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        Ok(())
    }
}

pub fn eval<F: Field, C: Circuit<F>>(circuit: &C, instance: C::Instance<'_>) -> Result<Vec<F>> {
    let mut collector = PublicInputs(PhantomData);
    let mut pubinputs = vec![];
    circuit
        .instance(&mut collector, Always::maybe_just(|| instance))?
        .serialize(&mut collector, &mut pubinputs)?;

    Ok(pubinputs
        .into_iter()
        .map(|x| *x.wire())
        .chain(Some(F::ONE))
        .rev()
        .collect())
}
