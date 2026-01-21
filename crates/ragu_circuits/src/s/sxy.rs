//! Full evaluation of $s(X, Y)$ at a fixed point $(x, y)$.
//!
//! This module provides [`eval`], which computes $s(x, y)$: the wiring
//! polynomial evaluated at concrete points for both variables, yielding a
//! single field element. See the [parent module][`super`] for background on
//! $s(X, Y)$.
//!
//! # Design
//!
//! This module uses the same running monomial pattern as [`sx`] (see the
//! [`common`] module), but differs in how it accumulates results. Where [`sx`]
//! stores each coefficient $c\_j$ in a vector, this module uses Horner's rule
//! to accumulate directly into a single field element.
//!
//! ### Horner's Rule Evaluation
//!
//! The wiring polynomial $s(x, Y) = \sum\_{j = 0}^{q - 1} c\_j Y^j$ can be
//! evaluated at $Y = y$ using Horner's rule:
//!
//! $$
//! s(x, y) = (\cdots((c\_{q-1} \cdot y + c\_{q-2}) \cdot y + \cdots) \cdot y + c\_0
//! $$
//!
//! Each [`Driver::enforce_zero`] call produces one coefficient $c\_j$. By
//! processing constraints in reverse order (highest $j$ first), the evaluator
//! can accumulate the result with a single multiply-add per constraint:
//! `result = result * y + c_j`.
//!
//! The [`sx`] module builds coefficients in the same reverse order specifically
//! to enable this Horner evaluation pattern here.
//!
//! ### Memory Efficiency
//!
//! Where [`sx`] allocates a coefficient vector of size $q$ (the number of
//! linear constraints), this module maintains only a single field element
//! accumulator.
//!
//! ### Memoization Eligibility
//!
//! Because [`sxy`](self) produces a single scalar result rather than a polynomial,
//! routine memoization can cache these scalar values directly. When the same
//! routine executes with related inputs across multiple evaluations, cached
//! results may be reused or transformed with simple linear operations. See
//! [issue #58](https://github.com/tachyon-zcash/ragu/issues/58) for the planned
//! multi-dimensional memoization strategy.
//!
//! [`common`]: super::common
//! [`sx`]: super::sx
//! [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero

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

use super::common::{WireEval, WireEvalSum};

/// A [`Driver`] that computes the full evaluation $s(x, y)$.
///
/// Given fixed evaluation points $x, y \in \mathbb{F}$, this driver interprets
/// circuit synthesis operations to produce $s(x, y)$ as a single field element
/// using Horner's rule (see [module documentation][`self`]).
///
/// Wires are represented using the running monomial pattern described in the
/// [`common`] module. Each call to [`Driver::enforce_zero`] applies one Horner
/// step: `result = result * y + coefficient`.
///
/// [`common`]: super::common
/// [`Driver`]: ragu_core::drivers::Driver
/// [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
struct Evaluator<F, R> {
    /// Horner accumulator for the evaluation result.
    ///
    /// Updated by each [`enforce_zero`](Driver::enforce_zero) call via
    /// `result = result * y + c_j`, where $c\_j$ is the evaluated linear
    /// combination.
    result: F,

    /// Number of multiplication gates consumed so far.
    ///
    /// Incremented by [`mul()`](Driver::mul). Must not exceed [`Rank::n()`].
    multiplication_constraints: usize,

    /// Number of linear constraints processed so far.
    ///
    /// Incremented by [`enforce_zero`](Driver::enforce_zero). Must not exceed
    /// [`Rank::num_coeffs()`].
    linear_constraints: usize,

    /// The evaluation point $x$.
    x: F,

    /// Cached inverse $x^{-1}$, used to advance decreasing monomials.
    x_inv: F,

    /// The evaluation point $y$, used for Horner accumulation.
    y: F,

    /// Evaluation of the `ONE` wire: $x^{4n - 1}$.
    ///
    /// Passed to [`WireEvalSum::new`] so that [`WireEval::One`] variants can be
    /// resolved during linear combination accumulation.
    one: F,

    /// Running monomial for $a$ wires: $x^{2n - 1 - i}$ at gate $i$.
    current_u_x: F,

    /// Running monomial for $b$ wires: $x^{2n + i}$ at gate $i$.
    current_v_x: F,

    /// Running monomial for $c$ wires: $x^{4n - 1 - i}$ at gate $i$.
    current_w_x: F,

    /// Stashed $b$ wire from paired allocation (see [`Driver::alloc`]).
    ///
    /// [`Driver::alloc`]: ragu_core::drivers::Driver::alloc
    available_b: Option<WireEval<F>>,

    /// Marker for the rank type parameter.
    _marker: core::marker::PhantomData<R>,
}

/// Configures associated types for the [`Evaluator`] driver.
///
/// - `MaybeKind = Empty`: No witness values are needed; evaluation uses only
///   the polynomial structure.
/// - `LCadd` / `LCenforce`: Use [`WireEvalSum`] to accumulate linear
///   combinations as immediate field element sums.
/// - `ImplWire`: [`WireEval`] represents wires as evaluated monomials.
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

    /// Allocates a wire using paired allocation.
    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(wire) = self.available_b.take() {
            Ok(wire)
        } else {
            let (a, b, _) = self.mul(|| unreachable!())?;
            self.available_b = Some(b);

            Ok(a)
        }
    }

    /// Consumes a multiplication gate, returning evaluated monomials for $(a, b, c)$.
    ///
    /// Returns the current values of the running monomials as [`WireEval::Value`]
    /// wires, then advances the monomials for the next gate:
    /// - $a$: multiplied by $x^{-1}$ (decreasing exponent)
    /// - $b$: multiplied by $x$ (increasing exponent)
    /// - $c$: multiplied by $x^{-1}$ (decreasing exponent)
    ///
    /// # Errors
    ///
    /// Returns [`Error::MultiplicationBoundExceeded`] if the gate count reaches
    /// [`Rank::n()`].
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

    /// Computes a linear combination of wire evaluations.
    ///
    /// Evaluates the linear combination immediately using [`WireEvalSum`] and
    /// returns the sum as a [`WireEval::Value`].
    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        WireEval::Value(lc(WireEvalSum::new(self.one)).value)
    }

    /// Applies one Horner step: `result = result * y + coefficient`.
    ///
    /// Evaluates the linear combination to get coefficient $c\_j$, then
    /// performs the Horner accumulation step. This processes constraints in
    /// reverse order so that the final result equals $s(x, y)$.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LinearBoundExceeded`] if the constraint count reaches
    /// [`Rank::num_coeffs()`].
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

    /// Executes a routine with isolated allocation state.
    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: <Ro::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<Ro::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
        let tmp = self.available_b.take();
        let mut dummy = Emulator::wireless();
        let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
        let result = match routine.predict(&mut dummy, &dummy_input)? {
            Prediction::Known(_, aux) | Prediction::Unknown(aux) => {
                routine.execute(self, input, aux)?
            }
        };
        self.available_b = tmp;
        Ok(result)
    }
}

/// Evaluates the wiring polynomial $s(X, Y)$ at fixed point $(x, y)$.
///
/// See the [module documentation][`self`] for the Horner evaluation algorithm.
///
/// # Arguments
///
/// - `circuit`: The circuit whose wiring polynomial to evaluate.
/// - `x`: The evaluation point for the $X$ variable.
/// - `y`: The evaluation point for the $Y$ variable.
/// - `key`: The mesh key that binds this evaluation to a [`Mesh`] context by
///   enforcing `key_wire - key = 0` as a constraint. This randomizes
///   evaluations of $s(x, y)$, preventing trivial forgeries across mesh
///   contexts.
///
/// [`Mesh`]: crate::mesh::Mesh
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
        // If y is zero, all terms y^j for j > 0 vanish, leaving only the ONE
        // wire coefficient.
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
