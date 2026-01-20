//! Partial evaluation of $s(X, Y)$ at a fixed point $X = x$.
//!
//! See the [parent module][`super`] for background on $s(X, Y)$.
//!
//! This module provides [`eval`], which computes $s(x, Y)$: the wiring polynomial
//! evaluated at a concrete $x$, yielding a univariate polynomial in $Y$.
//!
//! The output $s(x, Y) = \sum_j c_j \cdot Y^j$ has one coefficient per linear constraint
//! in the circuit. Each $c_j$ is computed by evaluating a univariate polynomial in
//! $X$ that consists of a linear combination of monomial terms at $X = x$.
//!
//! # How it works
//!
//! A specialized driver re-interprets circuit operations to compute polynomial
//! coefficients directly:
//!
//! - `mul()`: returns wire handles that are actually monomial evaluations
//!   ($x^{2n-1-i}$, $x^{2n+i}$, $x^{4n-1-i}$ for the $i$-th multiplication gate).
//!
//! - `add()`: accumulates a linear combination of these evaluations and returns
//!   the sum as a handle to the virtual wire.
//!
//! - `enforce_zero()`: stores the accumulated sum as coefficient $c_j$ and
//!   advances to the next constraint.
//!
//! Since the wiring polynomial encodes only linear constraints, multiplication
//! gates (`a · b = c`) are not enforced—`mul()` simply prepares the monomial
//! basis that linear constraints reference.

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

use super::{WireEval, WireEvalSum};

/// A driver that computes the partial evaluation $s(x, Y)$.
struct Evaluator<F: Field, R: Rank> {
    result: unstructured::Polynomial<F, R>,
    multiplication_constraints: usize,
    linear_constraints: usize,
    x: F,
    x_inv: F,
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
        if let Some(monomial) = self.available_b.take() {
            Ok(monomial)
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

        self.result[q] = lc(WireEvalSum::new(self.one)).value;

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

/// Evaluates the wiring polynomial $s(x, Y)$ at a fixed $x$, with mesh key `key`.
///
/// The mesh key augments the original `circuit` with one additional `key`-related
/// linear constraint, binding the circuit to an outer [`Mesh`][crate::mesh::Mesh] context.
pub fn eval<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    x: F,
    key: F,
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

    let mut evaluator = Evaluator::<F, R> {
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
    // c_0 = 1, reserve the constant ONE wire
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
    // enforcing public output wires = k_j in the public wires, see `ky::eval()`
    for output in outputs {
        evaluator.enforce_zero(|lc| lc.add(output.wire()))?;
    }
    // enforcing c_0 = k_0 (=1)
    evaluator.enforce_zero(|lc| lc.add(&one))?;

    // Order (built in reverse order):
    // - ONE wire constraint
    // - public output for the actual circuit logic
    // - mesh key binding constraint
    evaluator.result[0..evaluator.linear_constraints].reverse();
    assert_eq!(evaluator.result[0], evaluator.one);

    Ok(evaluator.result)
}
