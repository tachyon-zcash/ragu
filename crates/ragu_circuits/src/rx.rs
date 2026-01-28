use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, emulator::Emulator},
    gadgets::GadgetKind,
    maybe::{Always, Maybe, MaybeKind},
    routines::{Prediction, Routine},
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
        input: <Ro::Input as GadgetKind<Self::F>>::Rebind<'a, Self>,
    ) -> Result<<Ro::Output as GadgetKind<Self::F>>::Rebind<'a, Self>> {
        // Temporarily store currently `available_b` to reset the allocation
        // logic within the routine.
        let tmp = self.available_b.take();
        let mut dummy = Emulator::wireless();
        let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
        let result = match routine.predict(&mut dummy, &dummy_input)? {
            Prediction::Known(_, aux) | Prediction::Unknown(aux) => {
                routine.execute(self, input, aux)?
            }
        };
        // Restore the allocation logic state, discarding the state from within
        // the routine.
        self.available_b = tmp;
        Ok(result)
    }
}

pub fn eval<'witness, F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    witness: C::Witness<'witness>,
    key: F,
) -> Result<(structured::Polynomial<F, R>, C::Aux<'witness>)> {
    let mut rx = structured::Polynomial::<F, R>::new();
    let aux = {
        let mut dr = Collector {
            rx: rx.forward(),
            available_b: None,
        };
        let keyinv = key.invert().unwrap(); // TODO(ebfull)
        dr.mul(|| Ok((Coeff::Arbitrary(key), Coeff::Arbitrary(keyinv), Coeff::One)))?;
        let (io, aux) = circuit.witness(&mut dr, Always::maybe_just(|| witness))?;
        io.write(&mut dr, &mut ())?;

        if dr.rx.a.len() > R::n() || dr.rx.b.len() > R::n() || dr.rx.c.len() > R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }

        aux.take()
    };
    Ok((rx, aux))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polynomials::R;
    use crate::tests::SquareCircuit;
    use ragu_pasta::Fp;

    #[test]
    fn test_rx() {
        let circuit = SquareCircuit { times: 10 };
        let witness: Fp = Fp::from(3);
        let key = Fp::ONE;
        let (rx, _aux) = eval::<Fp, _, R<6>>(&circuit, witness, key).unwrap();
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
