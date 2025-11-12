use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::GadgetKind,
    maybe::Empty,
    routines::{Prediction, Routine},
};
use ragu_primitives::GadgetExt;

use alloc::vec;

use crate::{
    Circuit,
    polynomials::{
        Rank,
        unstructured::{self, Polynomial},
    },
};

use super::{Wire, WireSum};

struct Collector<F: Field, R: Rank> {
    result: unstructured::Polynomial<F, R>,
    multiplication_constraints: usize,
    linear_constraints: usize,
    x: F,
    x_inv: F,
    one: F,         // x^{4 * n - 1}
    current_u_x: F, // x^{2 * n - 1 - i}
    current_v_x: F, // x^{2 * n + i}
    current_w_x: F, // x^{4 * n - 1 - i}
    available_b: Option<Wire<F>>,
    _marker: core::marker::PhantomData<R>,
}

impl<F: Field, R: Rank> DriverTypes for Collector<F, R> {
    type MaybeKind = Empty;
    type LCadd = WireSum<F>;
    type LCenforce = WireSum<F>;
    type ImplField = F;
    type ImplWire = Wire<F>;
}

impl<'dr, F: Field, R: Rank> Driver<'dr> for Collector<F, R> {
    type F = F;
    type Wire = Wire<F>;

    const ONE: Self::Wire = Wire::One;

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(wire) = self.available_b.take() {
            Ok(wire)
        } else {
            let (a, b, _) = self.mul(|| unreachable!())?;
            self.available_b = Some(b);

            Ok(a)
        }
    }

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let index = self.multiplication_constraints;
        if index == R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }
        self.multiplication_constraints += 1;

        let a = self.current_u_x;
        let b = self.current_v_x;
        let c = self.current_w_x;

        self.current_u_x *= self.x_inv;
        self.current_v_x *= self.x;
        self.current_w_x *= self.x_inv;

        Ok((Wire::Value(a), Wire::Value(b), Wire::Value(c)))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        Wire::Value(lc(WireSum::new(self.one)).value)
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let q = self.linear_constraints;
        if q == R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }
        self.linear_constraints += 1;

        self.result[q] = lc(WireSum::new(self.one)).value;

        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: <Ro::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<Ro::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
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

pub fn eval<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    x: F,
) -> Result<unstructured::Polynomial<F, R>> {
    if x == F::ZERO {
        // The polynomial is zero if x is zero.
        return Ok(Polynomial::new());
    }

    let multiplication_constraints = 0;
    let linear_constraints = 0;
    let x_inv = x.invert().expect("x is not zero");
    let xn = x.pow_vartime([R::n() as u64]);
    let xn2 = xn.square();
    let current_u_x = xn2 * x_inv;
    let current_v_x = xn2;
    let xn4 = xn2.square();
    let current_w_x = xn4 * x_inv;

    let mut collector = Collector::<F, R> {
        result: unstructured::Polynomial::new(),
        multiplication_constraints,
        linear_constraints,
        x,
        x_inv,
        current_u_x,
        current_v_x,
        current_w_x,
        one: current_w_x,
        available_b: None,
        _marker: core::marker::PhantomData,
    };
    let (a_0, _b_0, c_0) = collector.mul(|| unreachable!())?;

    // Placeholder linear constraint: a_0 - c_0 * K = 0.
    collector.enforce_zero(|lc| lc.add(&a_0).sub(&c_0))?;
    let one = c_0;

    let mut outputs = vec![];
    let (io, _) = circuit.witness(&mut collector, Empty)?;
    io.write(&mut collector, &mut outputs)?;
    for output in outputs {
        collector.enforce_zero(|lc| lc.add(output.wire()))?;
    }
    collector.enforce_zero(|lc| lc.add(&one))?;

    collector.result[0..collector.linear_constraints].reverse();
    assert_eq!(collector.result[0], collector.one);

    Ok(collector.result)
}
