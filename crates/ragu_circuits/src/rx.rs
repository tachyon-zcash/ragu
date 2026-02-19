//! Assembly of the $r(X)$ trace polynomial.
//!
//! The [`eval`] function in this module processes some witness data for a
//! particular [`Circuit`] and assembles the corresponding $r(X)$ trace polynomial.

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, emulator::Emulator},
    gadgets::{Bound, GadgetKind},
    maybe::{Always, Maybe, MaybeKind},
    routines::Routine,
};
use ragu_primitives::GadgetExt;

use super::{Circuit, DriverScope, Rank, registry, structured};

/// Opaque trace produced by [`CircuitExt::rx`](crate::CircuitExt::rx).
///
/// Callers must go through
/// [`Registry::assemble`](crate::registry::Registry::assemble) (or
/// [`assemble_trivial`](Self::assemble_trivial) in tests) to obtain the final
/// polynomial.
pub struct Trace<F: Field, R: Rank>(pub(crate) structured::Polynomial<F, R>);

impl<F: Field, R: Rank> Trace<F, R> {
    /// Assembles the trace into a polynomial using a trivial floor plan.
    ///
    /// For use in tests and benchmarks that don't have a registry.
    pub fn assemble_trivial(mut self) -> structured::Polynomial<F, R> {
        let key = registry::Key::default();
        {
            let view = self.0.forward();
            view.a[0] = key.value();
            view.b[0] = key.inverse();
            view.c[0] = F::ONE;
        }
        self.0
    }
}

struct Evaluator<'a, F: Field, R: Rank> {
    rx: structured::View<'a, F, R, structured::Forward>,
    available_b: Option<usize>,
}

impl<F: Field, R: Rank> DriverScope<Option<usize>> for Evaluator<'_, F, R> {
    fn scope(&mut self) -> &mut Option<usize> {
        &mut self.available_b
    }
}

impl<F: Field, R: Rank> DriverTypes for Evaluator<'_, F, R> {
    type ImplField = F;
    type ImplWire = ();
    type MaybeKind = Always<()>;
    type LCadd = ();
    type LCenforce = ();
}

impl<'a, F: Field, R: Rank> Driver<'a> for Evaluator<'a, F, R> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, value: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        // Packs two allocations into one multiplication gate when possible, enabling consecutive
        // allocations to share gates.
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

    fn routine<Ro: Routine<Self::F> + 'a>(
        &mut self,
        routine: Ro,
        input: Bound<'a, Self, Ro::Input>,
    ) -> Result<Bound<'a, Self, Ro::Output>> {
        self.with_scope(None, |this| {
            let mut dummy = Emulator::wireless();
            let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
            let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
            routine.execute(this, input, aux)
        })
    }
}

pub fn eval<'witness, F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    witness: C::Witness<'witness>,
) -> Result<(Trace<F, R>, C::Aux<'witness>)> {
    let mut rx = structured::Polynomial::<F, R>::new();
    let aux = {
        let mut dr = Evaluator {
            rx: rx.forward(),
            available_b: None,
        };
        dr.mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
        let (io, aux) = circuit.witness(&mut dr, Always::maybe_just(|| witness))?;
        io.write(&mut dr, &mut ())?;

        if dr.rx.a.len() > R::n() || dr.rx.b.len() > R::n() || dr.rx.c.len() > R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }

        aux.take()
    };
    Ok((Trace(rx), aux))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polynomials::TestRank;
    use crate::tests::SquareCircuit;
    use ragu_pasta::Fp;

    #[test]
    fn test_rx() {
        let circuit = SquareCircuit { times: 10 };
        let witness: Fp = Fp::from(3);
        let (trace, _aux) = eval::<Fp, _, TestRank>(&circuit, witness).unwrap();
        let rx = trace.assemble_trivial();
        let mut coeffs = rx.iter_coeffs().collect::<Vec<_>>();
        let size_of_vec = coeffs.len() / 4;
        let c = coeffs.drain(..size_of_vec).collect::<Vec<_>>();
        let b = coeffs.drain(..size_of_vec).rev().collect::<Vec<_>>();
        let a = coeffs.drain(..size_of_vec).collect::<Vec<_>>();
        let d = coeffs.drain(..size_of_vec).rev().collect::<Vec<_>>();
        for i in 0..size_of_vec {
            assert_eq!(a[i] * b[i], c[i]);
            assert_eq!(d[i], Fp::ZERO);
        }
    }
}
