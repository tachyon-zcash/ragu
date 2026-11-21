//! [`Driver`] that records gate placements into a [`sparse::View`].

use ragu_core::{
    Coeff, Result,
    drivers::{Driver, DriverTypes},
    maybe::Always,
};
use udon::field::Field;

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

    /// Builds the polynomial, with `blind_gate` at the `a` and `d` wires of
    /// the blind gate.
    pub(crate) fn build(mut self, blind_gate: [F; 2]) -> sparse::Polynomial<F, R> {
        if blind_gate != [F::ZERO, F::ZERO] {
            assert!(
                self.view.a.len() <= R::blind_gate(),
                "the stage reaches the blind gate"
            );
            self.view.a.resize(R::n(), F::ZERO);
            self.view.d.resize(R::n(), F::ZERO);
            self.view.a[R::blind_gate()] = blind_gate[0];
            self.view.d[R::blind_gate()] = blind_gate[1];
        }
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
