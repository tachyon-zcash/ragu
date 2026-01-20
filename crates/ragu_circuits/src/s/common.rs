//! Shared types for wire evaluation during polynomial synthesis.
//!
//! # Design
//!
//! The [`sx`] and [`sxy`] evaluators compute polynomial coefficients directly
//! as field elements during circuit synthesis. Since both evaluators produce
//! immediate field element results, they can share the same wire representation
//! types defined here.
//!
//! In contrast, [`sy`] requires deferred computation through a virtual wire
//! system with reference counting, because $s(X, y)$ coefficients cannot be
//! computed in streaming order during synthesis (see [`sy`] module documentation).
//!
//! [`sx`]: super::sx
//! [`sxy`]: super::sxy
//! [`sy`]: super::sy

use arithmetic::Coeff;
use ff::Field;
use ragu_core::drivers::LinearExpression;

/// An evaluated value at a wire position.
///
/// During polynomial evaluation, this type represents the evaluated value of a
/// wire in the wiring polynomial $s(X, Y)$. Unlike traditional wire handles
/// that index into a constraint system, a `WireEval` directly contains the
/// computed value at a particular position in the polynomial.
///
/// # Variants
///
/// * `Value(F)` - The evaluated value of a wire (or linear combination of wires
///   from [`Driver::add`]).
/// * `One` - A special variant that corresponds to the ONE wire.
///
/// Note that `One` here has nothing to do with $x^0 = 1$ (the constant term).
/// During circuit arithmetization, the `ONE` wire corresponds to a specific term
/// in the overall wiring polynomial $s(X, Y)$. While the evaluation of this
/// wire depends on evaluation point $x$ (or $y$), the type system requires
/// `const Driver::ONE: Wire` to be a constant value. Thus we introduce this
/// special variant to represent the evaluation for the `ONE` wire.
/// Technically, `WireEval::One` is another `WireEval::Value(_)`.
///
/// # Relationship to `Driver::Wire`
///
/// When a circuit is executed under a standard constraint system driver,
/// `Wire` represents an index. When executed under a polynomial evaluation
/// driver (like `Evaluator`), `Wire` is bound to this `WireEval` type,
/// allowing the same gadget code to compute polynomial evaluations instead
/// of building constraints.
///
/// [`Driver::add`]: ragu_core::drivers::Driver::add
#[derive(Clone)]
pub(super) enum WireEval<F> {
    Value(F),
    One,
}

/// Accumulates linear combinations of wire evaluations during polynomial evaluation.
pub(super) struct WireEvalSum<F: Field> {
    pub(super) value: F,
    one: F,
    gain: Coeff<F>,
}

impl<F: Field> WireEvalSum<F> {
    pub(super) fn new(one: F) -> Self {
        Self {
            value: F::ZERO,
            one,
            gain: Coeff::One,
        }
    }
}

impl<F: Field> LinearExpression<WireEval<F>, F> for WireEvalSum<F> {
    fn add_term(mut self, wire_eval: &WireEval<F>, coeff: Coeff<F>) -> Self {
        self.value += match wire_eval {
            WireEval::Value(v) => *v,
            WireEval::One => self.one,
        } * (coeff * self.gain).value();
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain = self.gain * coeff;
        self
    }
}
