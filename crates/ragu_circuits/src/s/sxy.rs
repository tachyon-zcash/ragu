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
//! Each constraint produces one coefficient $c\_j$. By processing constraints
//! in reverse order (highest $j$ first), we accumulate the result with a
//! single multiply-add per constraint: `result = result * y + c_j`.
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
//! [`common`]: super::common
//! [`sx`]: super::sx

use alloc::vec;
use ff::Field;

use crate::{metrics::SynthesisTrace, polynomials::Rank, registry};

/// Running monomials for (a, b, c) wire evaluations at each gate.
struct Monomials<F> {
    u: F, // a-wire: x^(2n-1-i)
    v: F, // b-wire: x^(2n+i)
    w: F, // c-wire: x^(4n-1-i)
    x: F,
    x_inv: F,
}

impl<F: Field> Monomials<F> {
    /// Returns (a, b, c) evaluations and advances to next gate.
    fn next_gate(&mut self) -> (F, F, F) {
        let result = (self.u, self.v, self.w);
        self.u *= self.x_inv;
        self.v *= self.x;
        self.w *= self.x_inv;
        result
    }
}

/// Evaluates $s(x, y)$ by replaying the synthesis trace.
pub fn eval<F: Field, R: Rank>(trace: &SynthesisTrace<F>, x: F, y: F, key: &registry::Key<F>) -> F {
    if x == F::ZERO {
        return F::ZERO;
    }

    let x_inv = x.invert().expect("x is not zero");
    let xn = x.pow_vartime([R::n() as u64]);
    let xn2 = xn.square();
    let xn4 = xn2.square();
    let one_eval = xn4 * x_inv; // x^(4n-1), the ONE wire evaluation

    if y == F::ZERO {
        // All terms y^j for j > 0 vanish, leaving only the ONE wire coefficient.
        return one_eval;
    }

    let mut monomials = Monomials {
        u: xn2 * x_inv, // x^(2n-1)
        v: xn2,         // x^(2n)
        w: one_eval,    // x^(4n-1)
        x,
        x_inv,
    };

    // Compute total wire count for Vec allocation
    let num_wires = trace.mul_wire_ids.len() * 3 + trace.add_wires.len();
    let mut wire_evals = vec![F::ZERO; num_wires];

    // Evaluate mul wires
    for (a_id, b_id, c_id) in &trace.mul_wire_ids {
        let (a, b, c) = monomials.next_gate();
        wire_evals[*a_id] = a;
        wire_evals[*b_id] = b;
        wire_evals[*c_id] = c;
    }

    // Evaluate add wires that were lazily deferred during trace capture
    for (id, lc) in &trace.add_wires {
        let sum: F = lc
            .iter()
            .map(|term| term.coeff * wire_evals[term.wire])
            .sum();
        wire_evals[*id] = sum;
    }

    // Horner accumulation: result = result * y + coefficient
    // Key constraint: key_wire - key * ONE
    let mut result = wire_evals[0] - key.value() * one_eval;

    // Replay trace constraints
    for lc in &trace.constraints {
        result *= y;
        result += lc
            .iter()
            .map(|term| term.coeff * wire_evals[term.wire])
            .sum::<F>();
    }

    result
}
