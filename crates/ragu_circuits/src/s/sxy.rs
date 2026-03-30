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
//! The [`sx`] module reverses each routine's coefficient range after synthesis
//! to align with the $Y$-power assignment that Horner's rule produces here.
//!
//! ### Memory Efficiency
//!
//! Where [`sx`] allocates a coefficient vector of size $q$ (the number of
//! constraints), this module maintains only a single field element
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

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, emulator::Emulator},
    gadgets::Bound,
    maybe::Empty,
    routines::Routine,
};

use crate::{DriverScope, floor_planner::ConstraintSegment, polynomials::Rank, raw::RawCircuit};

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
/// Per-routine state saved and restored across routine boundaries.
struct SxyScope<F> {
    /// Stashed $d$ wire from paired allocation.
    available_d: Option<WireEval<F>>,
    /// Running monomial for $a$ wires: $x^{2n - 1 - i}$ at gate $i$.
    current_a_x: F,
    /// Running monomial for $b$ wires: $x^{2n + i}$ at gate $i$.
    current_b_x: F,
    /// Running monomial for $c$ wires: $x^{4n - 1 - i}$ at gate $i$.
    current_c_x: F,
    /// Absolute index of the next gate to be written.
    /// Initialized to `segment.gate_start` on routine entry.
    gates: usize,
    /// Absolute index of the next constraint to be written.
    /// Initialized to `segment.constraint_start` on routine entry.
    constraints: usize,

    /// Local Horner accumulator for this routine's constraints.
    result: F,

    /// Accumulated child contributions already positioned at absolute
    /// Y-powers.
    sum: F,
}

struct Evaluator<'fp, F, R> {
    /// Per-routine scoped state.
    scope: SxyScope<F>,

    /// The evaluation point $x$.
    x: F,

    /// Cached inverse $x^{-1}$, used to advance decreasing monomials.
    x_inv: F,

    /// The evaluation point $y$, used for Horner accumulation.
    y: F,

    /// Evaluation of the `ONE` wire: $x^{2n}$.
    ///
    /// Passed to [`WireEvalSum::new`] so that [`WireEval::One`] variants can be
    /// resolved during linear combination accumulation.
    one: F,

    /// Base monomial $x^{2n-1}$, used to compute routine starting monomials.
    base_a_x: F,

    /// Base monomial $x^{2n}$, used to compute routine starting monomials.
    base_b_x: F,

    /// Base monomial $x^{4n-1}$, used to compute routine starting monomials
    /// for the $c$ wire.
    base_c_x: F,

    /// Correction factor $(x^{-2n})$ that converts a $b$-wire monomial
    /// $x^{2n+i}$ into the corresponding $d$-wire monomial $x^i$.
    ///
    /// Only read by [`gate`](DriverTypes::gate), not by [`mul`](Driver::mul),
    /// so the extra multiplication is skipped when callers don't need the
    /// $d$ wire.
    b_to_d: F,

    /// Floor plan mapping DFS segment index to absolute offsets.
    floor_plan: &'fp [ConstraintSegment],

    /// Global monotonic DFS counter for routine entries.
    current_routine: usize,

    /// Marker for the rank type parameter.
    _marker: core::marker::PhantomData<R>,
}

impl<F: Field, R: Rank> DriverScope<SxyScope<F>> for Evaluator<'_, F, R> {
    fn scope(&mut self) -> &mut SxyScope<F> {
        &mut self.scope
    }
}

impl<F: Field, R: Rank> Evaluator<'_, F, R> {
    /// Advances the gate counter and running monomials, returning the raw
    /// $(a, b, c)$ monomial evaluations before advancement.
    ///
    /// This is the shared core of [`gate`](DriverTypes::gate) and
    /// [`mul`](Driver::mul). The $d$-wire monomial ($b \cdot \text{b\_to\_d}$)
    /// is only computed by `gate`, saving one field multiplication per `mul` call.
    fn advance_gate(&mut self) -> Result<(F, F, F)> {
        let index = self.scope.gates;
        if index == R::n() {
            return Err(Error::GateBoundExceeded { limit: R::n() });
        }
        self.scope.gates += 1;

        let a = self.scope.current_a_x;
        let b = self.scope.current_b_x;
        let c = self.scope.current_c_x;

        self.scope.current_a_x *= self.x_inv;
        self.scope.current_b_x *= self.x;
        self.scope.current_c_x *= self.x_inv;

        Ok((a, b, c))
    }
}

/// Configures associated types for the [`Evaluator`] driver.
///
/// - `MaybeKind = Empty`: No witness values are needed; evaluation uses only
///   the polynomial structure.
/// - `LCadd` / `LCenforce`: Use [`WireEvalSum`] to accumulate linear
///   combinations as immediate field element sums.
/// - `ImplWire`: [`WireEval`] represents wires as evaluated monomials.
impl<F: Field, R: Rank> DriverTypes for Evaluator<'_, F, R> {
    type MaybeKind = Empty;
    type LCadd = WireEvalSum<F>;
    type LCenforce = WireEvalSum<F>;
    type ImplField = F;
    type ImplWire = WireEval<F>;

    /// Consumes a gate, returning evaluated monomials for $(a, b, c, d)$.
    ///
    /// Returns the current values of the running monomials as [`WireEval::Value`]
    /// wires, then advances the monomials for the next gate:
    /// - $a$: multiplied by $x^{-1}$ (decreasing exponent)
    /// - $b$: multiplied by $x$ (increasing exponent)
    /// - $c$: multiplied by $x^{-1}$ (decreasing exponent)
    ///
    /// The $d$-wire monomial $x^i$ is derived from $b = x^{2n+i}$ via
    /// `b_to_d`. This computation is confined to `gate` and skipped
    /// by the [`mul`](Driver::mul) override.
    ///
    /// # Errors
    ///
    /// Returns [`Error::GateBoundExceeded`] if the gate count reaches
    /// [`Rank::n()`].
    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(WireEval<F>, WireEval<F>, WireEval<F>, WireEval<F>)> {
        let (a, b, c) = self.advance_gate()?;
        let d = b * self.b_to_d;

        Ok((
            WireEval::Value(a),
            WireEval::Value(b),
            WireEval::Value(c),
            WireEval::Value(d),
        ))
    }
}

impl<'dr, F: Field, R: Rank> Driver<'dr> for Evaluator<'_, F, R> {
    type F = F;
    type Wire = WireEval<F>;

    const ONE: Self::Wire = WireEval::One;

    /// Allocates a wire using paired allocation with layout $(0, b, 0, d)$.
    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(monomial) = self.scope.available_d.take() {
            Ok(monomial)
        } else {
            let (_, b, _, d) = self.gate(|| unreachable!())?;
            self.scope.available_d = Some(d);
            Ok(b)
        }
    }

    /// Advances the gate counter and returns $(a, b, c)$ without computing the
    /// $d$-wire monomial.
    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let (a, b, c) = self.advance_gate()?;
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
    /// Returns [`Error::ConstraintBoundExceeded`] if the constraint count reaches
    /// `Rank::num_coeffs() - 1` (the last slot is reserved for the registry
    /// key constraint).
    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let q = self.scope.constraints;
        if q >= R::num_coeffs() - 1 {
            return Err(Error::ConstraintBoundExceeded {
                limit: R::num_coeffs() - 1,
            });
        }
        self.scope.constraints += 1;

        self.scope.result *= self.y;
        self.scope.result += lc(WireEvalSum::new(self.one)).value;

        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        self.current_routine += 1;
        let seg = &self.floor_plan[self.current_routine];
        let gate_start = seg.gate_start;
        let constraint_start = seg.constraint_start;

        // Jump to this routine's absolute position in the polynomial;
        // see "Polynomial Encoding and Scope Jumps" in the `s` module doc.
        let init_scope = SxyScope {
            available_d: None,
            current_a_x: self.base_a_x * self.x_inv.pow_vartime([gate_start as u64]),
            current_b_x: self.base_b_x * self.x.pow_vartime([gate_start as u64]),
            current_c_x: self.base_c_x * self.x_inv.pow_vartime([gate_start as u64]),
            gates: gate_start,
            constraints: constraint_start,
            result: F::ZERO,
            sum: F::ZERO,
        };

        // Manual save/restore: we need to capture the routine's result
        // before restoring parent state.
        let saved = core::mem::replace(&mut self.scope, init_scope);
        let exec_result = {
            let aux = Emulator::predict(&routine, &input)?.into_aux();
            routine.execute(self, input, aux)
        };
        // Verify this routine consumed exactly the expected constraints.
        assert_eq!(
            self.scope.gates,
            seg.gate_start + seg.num_gates,
            "routine gate count must match floor plan"
        );
        assert_eq!(
            self.scope.constraints,
            seg.constraint_start + seg.num_constraints,
            "routine constraint count must match floor plan"
        );

        // Position the routine's local Horner result at its absolute Y offset,
        // then combine with any nested child contributions.
        let y_pow_constraint_start = self.y.pow_vartime([constraint_start as u64]);
        let routine_contribution = y_pow_constraint_start * self.scope.result + self.scope.sum;
        self.scope = saved;
        self.scope.sum += routine_contribution;

        exec_result
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
/// - `floor_plan`: Per-segment absolute offsets, computed by
///   [`floor_plan()`](crate::floor_planner::floor_plan).
pub fn eval<F: Field, RC: RawCircuit<F>, R: Rank>(
    circuit: &RC,
    x: F,
    y: F,
    floor_plan: &[ConstraintSegment],
) -> Result<F> {
    if x == F::ZERO {
        // The polynomial is zero if x is zero.
        return Ok(F::ZERO);
    }

    let x_inv = x.invert().expect("x is not zero");
    let xn = x.pow_vartime([R::n() as u64]); // xn = x^n
    let xn2 = xn.square(); // xn2 = x^(2n)
    let base_a_x = xn2 * x_inv; // x^(2n - 1)
    let base_b_x = xn2; // x^(2n)
    let xn4 = xn2.square(); // x^(4n)
    let base_c_x = xn4 * x_inv; // x^(4n - 1)
    let xn_inv = x_inv.pow_vartime([R::n() as u64]); // x^(-n)
    let base_b_x_inv = xn_inv.square(); // x^(-2n)
    let one = base_b_x; // x^(2n)

    if y == F::ZERO {
        // If y is zero, all terms y^j for j > 0 vanish, leaving only the ONE
        // wire coefficient.
        return Ok(one);
    }

    let mut evaluator = Evaluator::<F, R> {
        scope: SxyScope {
            available_d: None,
            current_a_x: base_a_x,
            current_b_x: base_b_x,
            current_c_x: base_c_x,
            gates: 0,
            constraints: 0,
            result: F::ZERO,
            sum: F::ZERO,
        },
        x,
        x_inv,
        y,
        one,
        base_a_x,
        base_b_x,
        base_c_x,
        b_to_d: base_b_x_inv,
        floor_plan,
        current_routine: 0,
        _marker: core::marker::PhantomData,
    };

    crate::raw::orchestrate(&mut evaluator, circuit, Empty)?;

    // Verify all floor plan segments were consumed and counts match.
    assert_eq!(
        evaluator.current_routine + 1,
        evaluator.floor_plan.len(),
        "floor plan routine count must match synthesis"
    );
    assert_eq!(
        evaluator.scope.gates, evaluator.floor_plan[0].num_gates,
        "root gate count must match floor plan"
    );
    assert_eq!(
        evaluator.scope.constraints, evaluator.floor_plan[0].num_constraints,
        "root constraint count must match floor plan"
    );

    // The root's local Horner result plus any child contributions.
    Ok(evaluator.scope.result + evaluator.scope.sum)
}
