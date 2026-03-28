//! Partial evaluation of $s(X, Y)$ at a fixed point $X = x$.
//!
//! This module provides [`eval`], which computes $s(x, Y)$: the wiring
//! polynomial evaluated at a concrete $x$, yielding a univariate polynomial in
//! $Y$. See the [parent module][`super`] for background on $s(X, Y)$.
//!
//! The output $s(x, Y) = \sum\_{j} c\_{j} Y^j$ has one coefficient per
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
//! - [`mul()`][`Driver::mul`] / [`gate()`][`DriverTypes::gate`]: Returns wire
//!   handles that hold monomial evaluations $x^{2n - 1 - i}$, $x^{2n + i}$,
//!   $x^{4n - 1 - i}$, $x^{i}$ for the $i$-th gate.
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
//! $x^{2n}$.
//!
//! [`common`]: super::common
//!
//! ### Coefficient Order
//!
//! Each [`Driver::enforce_zero`] call writes its coefficient to the next
//! indexed position in the result vector within the current routine's range.
//! Because Horner's rule in [`sxy`] assigns decreasing $Y$-powers to
//! later-emitted constraints (the first emitted gets the highest power), the
//! synthesis-order storage is reversed relative to the canonical polynomial
//! convention where index $j$ is the coefficient of $Y^j$.
//!
//! To reconcile this, [`eval`] reverses each routine's coefficient range after
//! synthesis completes. This per-routine reversal ensures that both this module
//! and [`sxy`] agree on which constraint maps to which $Y$-power.
//!
//! After reversal, the root segment's coefficients are ordered as:
//! 1. $c\_{0}$: `ONE` wire constraint (the constant $x^{2n}$)
//! 2. $c\_{1}, \ldots, c\_{p}$: public output constraints
//! 3. $c\_{p+1}, \ldots, c\_{p+m}$: circuit-specific constraints
//!
//! This follows from the root segment's synthesis order — circuit body first,
//! then public outputs, and `ONE` last — being flipped by the reversal.
//!
//! The registry key constraint is **not** included in these coefficients; it
//! occupies the fixed $Y^{4n-1}$ slot and is injected at the registry level.
//!
//! [`Driver`]: ragu_core::drivers::Driver
//! [`Driver::add`]: ragu_core::drivers::Driver::add
//! [`Driver::alloc`]: ragu_core::drivers::Driver::alloc
//! [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
//! [`Driver::mul`]: ragu_core::drivers::Driver::mul
//! [`DriverTypes::gate`]: ragu_core::drivers::DriverTypes::gate
//! [`sxy`]: super::sxy

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, emulator::Emulator},
    gadgets::Bound,
    maybe::Empty,
    routines::Routine,
};
use ragu_primitives::GadgetExt;

use alloc::{vec, vec::Vec};

use crate::{
    Circuit, DriverScope,
    floor_planner::ConstraintSegment,
    polynomials::{Rank, sparse},
};

use super::{
    DriverExt,
    common::{WireEval, WireEvalSum},
};

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
/// Per-routine state saved and restored across routine boundaries.
struct SxScope<F> {
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
}

struct Evaluator<'fp, F: Field, R: Rank> {
    /// Accumulated polynomial coefficients, built in reverse synthesis order.
    ///
    /// Each [`enforce_zero`](Driver::enforce_zero) call appends one
    /// coefficient. The vector is reversed at the end of [`eval`] to produce
    /// the canonical order.
    result: Vec<F>,

    /// Per-routine scoped state.
    scope: SxScope<F>,

    /// The evaluation point $x$.
    x: F,

    /// Cached inverse $x^{-1}$, used to advance decreasing monomials.
    x_inv: F,

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

impl<F: Field, R: Rank> DriverScope<SxScope<F>> for Evaluator<'_, F, R> {
    fn scope(&mut self) -> &mut SxScope<F> {
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
/// - `MaybeKind = Empty`: No witness values are needed; we only evaluate the
///   polynomial structure.
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
    /// returns the sum as a [`WireEval::Value`]. No deferred computation is
    /// needed because all wire values are concrete field elements.
    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        WireEval::Value(lc(WireEvalSum::new(self.one)).value)
    }

    /// Records a constraint as a polynomial coefficient.
    ///
    /// Evaluates the linear combination to get coefficient $c\_q$, stores it at
    /// index $q$ in the result polynomial, and increments the constraint
    /// counter.
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

        self.result[q] = lc(WireEvalSum::new(self.one)).value;

        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        self.current_routine += 1;
        let seg = &self.floor_plan[self.current_routine];

        // Jump to this routine's absolute position in the polynomial;
        // see "Polynomial Encoding and Scope Jumps" in the `s` module doc.
        let init_scope = SxScope {
            available_d: None,
            current_a_x: self.base_a_x * self.x_inv.pow_vartime([seg.gate_start as u64]),
            current_b_x: self.base_b_x * self.x.pow_vartime([seg.gate_start as u64]),
            current_c_x: self.base_c_x * self.x_inv.pow_vartime([seg.gate_start as u64]),
            gates: seg.gate_start,
            constraints: seg.constraint_start,
        };

        self.with_scope(init_scope, |this| {
            let aux = Emulator::predict(&routine, &input)?.into_aux();
            let result = routine.execute(this, input, aux)?;

            // Verify this routine consumed exactly the expected constraints.
            assert_eq!(
                this.scope.gates,
                seg.gate_start + seg.num_gates,
                "routine gate count must match floor plan"
            );
            assert_eq!(
                this.scope.constraints,
                seg.constraint_start + seg.num_constraints,
                "routine constraint count must match floor plan"
            );

            Ok(result)
        })
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
/// - `floor_plan`: Per-segment absolute offsets, computed by
///   [`floor_plan()`](crate::floor_planner::floor_plan).
///
/// # Special Cases
///
/// If $x = 0$, returns the zero polynomial since all monomials vanish.
pub fn eval<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    x: F,
    floor_plan: &[ConstraintSegment],
) -> Result<sparse::Polynomial<F, R>> {
    if x == F::ZERO {
        return Ok(sparse::Polynomial::new());
    }

    let x_inv = x.invert().expect("x is not zero");
    let xn = x.pow_vartime([R::n() as u64]);
    let xn2 = xn.square();
    let base_a_x = xn2 * x_inv;
    let base_b_x = xn2;
    let xn4 = xn2.square();
    let base_c_x = xn4 * x_inv;
    let xn_inv = x_inv.pow_vartime([R::n() as u64]);
    let base_b_x_inv = xn_inv.square();
    let one = base_b_x;

    let mut evaluator = Evaluator::<F, R> {
        // Zero-initialized: the evaluator fills specific indices during
        // synthesis. Unfilled indices must remain zero as they represent
        // unused wire slots.
        result: vec![F::ZERO; R::num_coeffs()],
        scope: SxScope {
            available_d: None,
            current_a_x: base_a_x,
            current_b_x: base_b_x,
            current_c_x: base_c_x,
            gates: 0,
            constraints: 0,
        },
        x,
        x_inv,
        one,
        base_a_x,
        base_b_x,
        base_c_x,
        b_to_d: base_b_x_inv,
        floor_plan,
        current_routine: 0,
        _marker: core::marker::PhantomData,
    };

    // Allocate the ONE gate (gate 0). The registry key constraint is
    // injected at the registry level, not here.
    evaluator.mul(|| unreachable!())?;

    let mut outputs = vec![];
    let io = circuit.witness(&mut evaluator, Empty)?.into_output();
    io.write(&mut evaluator, &mut outputs)?;

    // Enforcing public inputs
    evaluator.enforce_public_outputs(outputs.iter().map(|output| output.wire()))?;
    evaluator.enforce_one()?;

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

    // Reverse to canonical coefficient order within each routine's constraint
    // range.
    for seg in evaluator.floor_plan {
        evaluator.result[seg.constraint_start..seg.constraint_start + seg.num_constraints]
            .reverse();
    }
    assert_eq!(evaluator.result[0], evaluator.one);

    Ok(sparse::Polynomial::from_coeffs(evaluator.result))
}
