//! [`Driver`] that records gate placements into a [`sparse::View`].

use ragu_arithmetic::{Coeff, ff::Field};
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes},
    maybe::Always,
};

use crate::polynomials::{
    Rank,
    sparse::{self, view::Trace},
};

pub(crate) struct RxDriver<F: Field, R: Rank> {
    view: sparse::View<F, R, Trace>,
}

impl<F: Field, R: Rank> RxDriver<F, R> {
    pub(crate) fn with_capacity(gates: usize) -> Self {
        let mut view = sparse::View::trace();
        view.a.reserve_exact(gates);
        view.b.reserve_exact(gates);
        view.c.reserve_exact(gates);
        view.d.reserve_exact(gates);
        Self { view }
    }

    pub(crate) fn build(self) -> sparse::Polynomial<F, R> {
        self.view.build()
    }
}

impl<F: Field, R: Rank> DriverTypes for RxDriver<F, R> {
    type ImplField = F;
    type ImplWire = ();
    type MaybeKind = Always<()>;
    type LCadd = ();
    type LCenforce = ();
    type Extra = usize;

    fn gate(
        &mut self,
        values: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<((), (), (), usize)> {
        let (a, b, c) = values()?;
        let index = self.view.a.len();
        self.view.a.push(a.value());
        self.view.b.push(b.value());
        self.view.c.push(c.value());
        self.view.d.push(F::ZERO);
        Ok(((), (), (), index))
    }

    fn assign_extra(&mut self, index: usize, value: impl Fn() -> Result<Coeff<F>>) -> Result<()> {
        self.view.d[index] = value()?.value();
        Ok(())
    }
}

impl<'dr, F: Field, R: Rank> Driver<'dr> for RxDriver<F, R> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        Ok(())
    }
}
