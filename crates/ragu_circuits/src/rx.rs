use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes},
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_primitives::GadgetExt;

use super::{Circuit, Rank, structured};

struct Collector<'a, F: Field, R: Rank> {
    rx: structured::View<'a, F, R, structured::Forward>,
    available_b: Option<usize>,
}

impl<F: Field, R: Rank> DriverTypes for Collector<'_, F, R> {
    type ImplField = F;
    type ImplWire = ();
    type MaybeKind = Always<()>;
    type LCadd = ();
    type LCenforce = ();
}

impl<'a, F: Field, R: Rank> Driver<'a> for Collector<'a, F, R> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, value: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(index) = self.available_b.take() {
            let a = self.rx.a[index];
            let b = value()?;
            self.rx.b[index] = b.value();
            self.rx.c[index] = a * b.value();
            Ok(())
        } else {
            let index = self.rx.a.len();
            self.mul(|| Ok((value()?, Coeff::Zero, Coeff::Zero)))?;
            self.available_b = Some(index);
            Ok(())
        }
    }

    fn mul(
        &mut self,
        values: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<((), (), ())> {
        let (a, b, c) = values()?;
        self.rx.a.push(a.value());
        self.rx.b.push(b.value());
        self.rx.c.push(c.value());

        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        Ok(())
    }
}

pub fn eval<'witness, F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    witness: C::Witness<'witness>,
) -> Result<(structured::Polynomial<F, R>, C::Aux<'witness>)> {
    let mut rx = structured::Polynomial::<F, R>::new();
    let aux = {
        let mut dr = Collector {
            rx: rx.forward(),
            available_b: None,
        };
        dr.mul(|| Ok((Coeff::One, Coeff::One, Coeff::One)))?;
        let (io, aux) = circuit.witness(&mut dr, Always::maybe_just(|| witness))?;
        io.serialize(&mut dr, &mut ())?;

        if dr.rx.a.len() > R::n() || dr.rx.b.len() > R::n() || dr.rx.c.len() > R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }

        aux.take()
    };
    Ok((rx, aux))
}
