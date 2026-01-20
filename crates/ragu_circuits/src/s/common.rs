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

/// Represents a wire's evaluated monomial during polynomial synthesis.
///
/// In the wiring polynomial $s(X, Y)$, each wire corresponds to a monomial
/// $x^j$ for some exponent $j$. When evaluating $s(x, y)$ at concrete points,
/// wires become field elements rather than indices.
///
/// # Variants
///
/// - `Value(F)` — Holds the evaluated monomial for a wire from [`Driver::mul`],
///   or a linear combination of such evaluations from [`Driver::add`].
///
/// - `One` — Represents the ONE wire. This variant exists because
///   `const Driver::ONE` must be a compile-time constant, but the ONE wire's
///   actual evaluation (e.g., $x^{4n-1}$) depends on the evaluation point.
///   [`WireEvalSum::add_term`] resolves `One` to the cached evaluation at
///   runtime.
///
/// [`Driver::mul`]: ragu_core::drivers::Driver::mul
/// [`Driver::add`]: ragu_core::drivers::Driver::add
/// [`WireEvalSum::add_term`]: WireEvalSum::add_term
#[derive(Clone)]
pub(super) enum WireEval<F> {
    Value(F),
    One,
}

/// An accumulator for linear combinations of [`WireEval`]s during polynomial evaluation.
///
/// Implements [`LinearExpression`] to support [`Driver::add`], which builds
/// linear combinations of wires. The accumulator tracks both the running sum
/// and the context needed to resolve [`WireEval::One`] variants.
///
/// [`Driver::add`]: ragu_core::drivers::Driver::add
pub(super) struct WireEvalSum<F: Field> {
    /// Running sum of accumulated wire evaluations.
    pub(super) value: F,
    /// Cached evaluation of the ONE wire, used to resolve [`WireEval::One`].
    one: F,
    /// Coefficient multiplier for subsequently added terms; supports nested
    /// [`Driver::add`](ragu_core::drivers::Driver::add) calls.
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
