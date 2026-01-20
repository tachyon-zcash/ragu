//! Evaluates the wiring polynomial $s(x, y)$ at fixed $x$ and $y$.
//!
//! See the [parent module][`super`] for background on $s(X, Y)$, and the
//! [`sx`][super::sx] module for how partial evaluation $s(x, Y)$ works.
//!
//! This module employs similar driver logic as `sx` but is more memory efficient
//! since it only needs to track a single accumulated value instead of a vector of
//! coefficients. More importantly, it is subject to more aggressive optimizations
//! through multi-dimensional routine memoization.
//! See <https://github.com/tachyon-zcash/ragu/issues/58> for details.

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

use crate::{Circuit, polynomials::Rank};

use super::{WireEval, WireEvalSum};

/// A driver that computes the full evaluation $s(x, y)$.
struct Evaluator<F, R> {
    result: F,
    multiplication_constraints: usize,
    linear_constraints: usize,
    x: F,
    x_inv: F,
    y: F,
    one: F,         // x^{4 * n - 1}
    current_u_x: F, // x^{2 * n - 1 - i}
    current_v_x: F, // x^{2 * n + i}
    current_w_x: F, // x^{4 * n - 1 - i}
    available_b: Option<WireEval<F>>,
    _marker: core::marker::PhantomData<R>,
}

impl<F: Field, R: Rank> DriverTypes for Evaluator<F, R> {
    type MaybeKind = Empty;
    type LCadd = WireEvalSum<F>;
    type LCenforce = WireEvalSum<F>;
    type ImplField = F;
    type ImplWire = WireEval<F>;
}

impl<'dr, F: Field, R: Rank> Driver<'dr> for Evaluator<F, R> {
    type F = F;
    type Wire = WireEval<F>;

    const ONE: Self::Wire = WireEval::One;

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

        Ok((WireEval::Value(a), WireEval::Value(b), WireEval::Value(c)))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        WireEval::Value(lc(WireEvalSum::new(self.one)).value)
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let q = self.linear_constraints;
        if q == R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }
        self.linear_constraints += 1;

        self.result *= self.y;
        self.result += lc(WireEvalSum::new(self.one)).value;

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

/// Evaluates the wiring polynomial $s(X, Y)$ at fixed point $(x, y)$ with mesh key `key`.
///
/// The mesh key augments the original `circuit` with one additional `key`-related
/// linear constraint, binding the circuit to an outer [`Mesh`][crate::mesh::Mesh] context.
pub fn eval<F: Field, C: Circuit<F>, R: Rank>(circuit: &C, x: F, y: F, key: F) -> Result<F> {
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

    let mut evaluator = Evaluator::<F, R> {
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

    let (key_wire, _, one) = evaluator.mul(|| unreachable!())?;

    // Enforce linear constraint key_wire = key to randomize non-trivial
    // evaluations of this wiring polynomial.
    evaluator.enforce_zero(|lc| {
        lc.add(&key_wire)
            .add_term(&one, Coeff::NegativeArbitrary(key))
    })?;

    let mut outputs = vec![];

    let (io, _) = circuit.witness(&mut evaluator, Empty)?;
    io.write(&mut evaluator, &mut outputs)?;
    for output in outputs {
        evaluator.enforce_zero(|lc| lc.add(output.wire()))?;
    }
    evaluator.enforce_zero(|lc| lc.add(&one))?;

    Ok(evaluator.result)
}
