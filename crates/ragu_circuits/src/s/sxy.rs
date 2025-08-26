use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, LinearExpression},
    maybe::Empty,
};
use ragu_primitives::GadgetExt;

use alloc::vec;

use crate::{Circuit, polynomials::Rank};

use super::{Wire, WireSum};

struct Collector<F, R> {
    result: F,
    multiplication_constraints: usize,
    linear_constraints: usize,
    x: F,
    x_inv: F,
    y: F,
    one: F,         // x^{4 * max_n - 1}
    current_u_x: F, // x^{2 * max_n - 1 - i}
    current_v_x: F, // x^{2 * max_n + i}
    current_w_x: F, // x^{4 * max_n - 1 - i}
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

impl<F: Field, R: Rank> Driver<'_> for Collector<F, R> {
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
        if index >= R::n() {
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
        if q >= R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }
        self.linear_constraints += 1;

        self.result *= self.y;
        self.result += lc(WireSum::new(self.one)).value;

        Ok(())
    }
}

pub fn eval<F: Field, C: Circuit<F>, R: Rank>(circuit: &C, x: F, y: F) -> Result<F> {
    if x == F::ZERO {
        // The polynomial is zero if x is zero.
        return Ok(F::ZERO);
    }

    let x_inv = x.invert().expect("x is not zero");
    let xn = x.pow_vartime([R::n() as u64]); // xn = x^n
    let xn2 = xn.square(); // xn2 = x^(2n)
    let current_u_x = xn2 * x_inv; // x^(2n - 1)
    let current_v_x = xn2; // x^(2n)
    let xn4 = xn2.square(); // x^(4n)
    let current_w_x = xn4 * x_inv; // x^(4n - 1)

    if y == F::ZERO {
        // If y is zero, the only linear constraint enforces the 'one' wire for
        // the public inputs.
        return Ok(current_w_x);
    }

    let mut dr = Collector::<F, R> {
        result: F::ZERO,
        multiplication_constraints: 0,
        linear_constraints: 0,
        x,
        x_inv,
        y,
        current_u_x,
        current_v_x,
        current_w_x,
        one: current_w_x,
        available_b: None,
        _marker: core::marker::PhantomData,
    };

    let one = dr.mul(|| unreachable!())?.2;

    let mut outputs = vec![];

    let (io, _) = circuit.witness(&mut dr, Empty)?;
    io.serialize(&mut dr, &mut outputs)?;
    for output in outputs {
        dr.enforce_zero(|lc| lc.add(output.wire()))?;
    }
    dr.enforce_zero(|lc| lc.add(&one))?;

    Ok(dr.result)
}
