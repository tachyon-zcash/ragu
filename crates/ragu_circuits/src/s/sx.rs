//! Partial evaluation of $s(X, Y)$ at a fixed point $X = x$.
//!
//! This module provides [`eval`], which computes $s(x, Y)$: the wiring
//! polynomial evaluated at a concrete $x$, yielding a univariate polynomial in
//! $Y$. See the [parent module][`super`] for background on $s(X, Y)$.
//!
//! The output $s(x, Y) = \sum\_{j} c\_{j} Y^j$ has one coefficient per linear
//! constraint in the circuit. Each $c\_{j}$ is computed by evaluating a
//! univariate polynomial in $X$ that consists of a linear combination of
//! monomial terms at $X = x$.
//!
//! # Design
//!
//! Rather than pre-computing $s(X, Y)$ as a bivariate polynomial and then
//! evaluating it (which would require $O(n \cdot q)$ storage), this module uses
//! a specialized [`Driver`] that interprets circuit synthesis operations to
//! produce coefficients directly. Wires become evaluated monomials, and linear
//! combinations become field arithmetic.
//!
//! The driver redefines each operation as follows:
//!
//! - [`mul()`][`Driver::mul`]: Returns wire handles that hold monomial
//!   evaluations $x^{2n - 1 - i}$, $x^{2n + i}$, $x^{4n - 1 - i}$ for the $i$-th gate.
//!
//! - [`add()`][`Driver::add`]: Accumulates a linear combination of monomial
//!   evaluations and returns the sum as a virtual wire.
//!
//! - [`enforce_zero()`][`Driver::enforce_zero`]: Evaluates the linear
//!   combination to produce coefficient $c\_{j}$ and advances to the next
//!   constraint.
//!
//! ### Monomial Basis
//!
//! Wires are represented as evaluated monomials using the running monomial
//! pattern described in the [`common`] module. The `ONE` wire evaluates to
//! $x^{4n - 1}$.
//!
//! [`common`]: super::common
//!
//! ### Coefficient Order
//!
//! Linear constraints are recorded in the order they're encountered during
//! synthesis. However, [`eval`] builds coefficients in reverse order (appending
//! each new constraint to the result vector), then reverses the entire sequence
//! at the end.
//!
//! This reverse-order construction exists so that [`sxy`] can evaluate $s(x, y)
//! = \sum\_{j} c\_{j} y^j$ using Horner's rule: by processing constraints in
//! reverse, [`sxy`] accumulates $(\cdots((c\_{q-1}) \cdot y + c\_{q-2}) \cdot y +
//! \cdots) \cdot y + c\_0$ with a single running product.
//!
//! The final coefficient order is:
//! 1. $c\_0$: `ONE` wire constraint (the constant $x^{4n - 1}$)
//! 2. $c\_1, \ldots, c\_k$: public output constraints
//! 3. $c\_{k+1}$: mesh key binding constraint
//! 4. $c\_{k+2}, \ldots, c\_{q-1}$: circuit-specific constraints
//!
//! [`Driver`]: ragu_core::drivers::Driver
//! [`Driver::add`]: ragu_core::drivers::Driver::add
//! [`Driver::alloc`]: ragu_core::drivers::Driver::alloc
//! [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
//! [`Driver::mul`]: ragu_core::drivers::Driver::mul
//! [`sxy`]: super::sxy

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

use super::common::{WireEval, WireEvalSum};

/// A [`Driver`] that computes the partial evaluation $s(x, Y)$.
///
/// Given a fixed evaluation point $x \in \mathbb{F}$, this driver interprets
/// circuit synthesis operations to produce the coefficients of $s(x, Y)$
/// directly as field elements.
///
/// Wires are represented using the running monomial pattern described in the
/// [`common`] module. Each call to [`Driver::enforce_zero`] stores one
/// coefficient in the result polynomial.
///
/// [`common`]: super::common
/// [`Driver`]: ragu_core::drivers::Driver
/// [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
struct Evaluator<F: Field, R: Rank> {
    /// Accumulated polynomial coefficients, built in reverse synthesis order.
    ///
    /// Each [`enforce_zero`](Driver::enforce_zero) call appends one
    /// coefficient. The vector is reversed at the end of [`eval`] to produce
    /// the canonical order.
    result: unstructured::Polynomial<F, R>,

    /// Number of multiplication gates consumed so far.
    ///
    /// Incremented by [`mul()`](Driver::mul). Must not exceed [`Rank::n()`].
    multiplication_constraints: usize,

    /// Number of linear constraints recorded so far.
    ///
    /// Incremented by [`enforce_zero`](Driver::enforce_zero). Must not exceed
    /// [`Rank::num_coeffs()`].
    linear_constraints: usize,

    /// The evaluation point $x$.
    x: F,

    /// Cached inverse $x^{-1}$, used to advance decreasing monomials.
    x_inv: F,

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
/// - `MaybeKind = Empty`: No witness values are needed; we only evaluate the
///   polynomial structure.
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
        if let Some(monomial) = self.available_b.take() {
            Ok(monomial)
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
    /// returns the sum as a [`WireEval::Value`]. No deferred computation is
    /// needed because all wire values are concrete field elements.
    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        WireEval::Value(lc(WireEvalSum::new(self.one)).value)
    }

    /// Records a linear constraint as a polynomial coefficient.
    ///
    /// Evaluates the linear combination to get coefficient $c\_q$, stores it at
    /// index $q$ in the result polynomial, and increments the constraint
    /// counter.
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

        self.result[q] = lc(WireEvalSum::new(self.one)).value;

        Ok(())
    }

    /// Executes a routine with isolated allocation state.
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

/// Evaluates $s(x, Y)$ at a fixed $x$, returning a univariate polynomial in
/// $Y$.
///
/// See the [module documentation][`self`] for the evaluation algorithm and
/// coefficient order.
///
/// # Arguments
///
/// - `circuit`: The circuit whose wiring polynomial to evaluate.
/// - `x`: The evaluation point for the $X$ variable.
/// - `key`: The mesh key that binds this evaluation to a [`Mesh`] context by
///   enforcing `key_wire - key = 0` as a constraint. This randomizes
///   evaluations of $s(x, Y)$, preventing trivial forgeries across mesh
///   contexts.
///
/// # Special Cases
///
/// If $x = 0$, returns the zero polynomial since all monomials vanish.
///
/// [`Mesh`]: crate::mesh::Mesh
pub fn eval<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    x: F,
    key: F,
) -> Result<unstructured::Polynomial<F, R>> {
    if x == F::ZERO {
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
    // Gate 0: key_wire = a, one = c (the `ONE` wire).
    let (key_wire, _, one) = evaluator.mul(|| unreachable!())?;

    // Mesh key constraint: key_wire - key = 0.
    evaluator.enforce_zero(|lc| {
        lc.add(&key_wire)
            .add_term(&one, Coeff::NegativeArbitrary(key))
    })?;

    let mut outputs = vec![];
    let (io, _) = circuit.witness(&mut evaluator, Empty)?;
    io.write(&mut evaluator, &mut outputs)?;

    // Public output constraints (one per output wire).
    for output in outputs {
        evaluator.enforce_zero(|lc| lc.add(output.wire()))?;
    }

    // `ONE` wire constraint.
    evaluator.enforce_zero(|lc| lc.add(&one))?;

    // Reverse to canonical coefficient order (see module docs).
    evaluator.result[0..evaluator.linear_constraints].reverse();
    assert_eq!(evaluator.result[0], evaluator.one);

    Ok(evaluator.result)
}
