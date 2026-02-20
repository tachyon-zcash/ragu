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
//! After reversal, the root routine's coefficients are ordered as:
//! 1. $c\_{0}$: `ONE` wire constraint (the constant $x^{4n - 1}$)
//! 2. $c\_{1}, \ldots, c\_{p}$: public output constraints
//! 3. $c\_{p+1}, \ldots, c\_{p+m}$: circuit-specific constraints
//! 4. $c\_{p+m+1}$: registry key binding constraint
//!
//! This follows from the root's synthesis order — registry key first, then
//! circuit body, public outputs, and ONE last — being flipped by the reversal.
//!
//! [`Driver`]: ragu_core::drivers::Driver
//! [`Driver::add`]: ragu_core::drivers::Driver::add
//! [`Driver::alloc`]: ragu_core::drivers::Driver::alloc
//! [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
//! [`Driver::mul`]: ragu_core::drivers::Driver::mul
//! [`sxy`]: super::sxy

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, emulator::Emulator},
    gadgets::{Bound, GadgetKind},
    maybe::Empty,
    routines::Routine,
};
use ragu_primitives::GadgetExt;

use alloc::vec;

use crate::{
    Circuit, DriverScope,
    floor_planner::RoutineSlot,
    polynomials::{
        Rank,
        unstructured::{self, Polynomial},
    },
    registry,
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
    /// Stashed $b$ wire from paired allocation.
    available_b: Option<WireEval<F>>,
    /// Running monomial for $a$ wires: $x^{2n - 1 - i}$ at gate $i$.
    current_u_x: F,
    /// Running monomial for $b$ wires: $x^{2n + i}$ at gate $i$.
    current_v_x: F,
    /// Running monomial for $c$ wires: $x^{4n - 1 - i}$ at gate $i$.
    current_w_x: F,
    /// Number of multiplication gates consumed so far in this routine.
    multiplication_constraints: usize,
    /// Number of linear constraints recorded so far in this routine.
    linear_constraints: usize,
}

struct Evaluator<'fp, F: Field, R: Rank> {
    /// Accumulated polynomial coefficients, built in reverse synthesis order.
    ///
    /// Each [`enforce_zero`](Driver::enforce_zero) call appends one
    /// coefficient. The vector is reversed at the end of [`eval`] to produce
    /// the canonical order.
    result: unstructured::Polynomial<F, R>,

    /// Per-routine scoped state.
    scope: SxScope<F>,

    /// The evaluation point $x$.
    x: F,

    /// Cached inverse $x^{-1}$, used to advance decreasing monomials.
    x_inv: F,

    /// Evaluation of the `ONE` wire: $x^{4n - 1}$.
    ///
    /// Passed to [`WireEvalSum::new`] so that [`WireEval::One`] variants can be
    /// resolved during linear combination accumulation.
    one: F,

    /// Base monomial $x^{2n-1}$, used to compute routine starting monomials.
    base_u_x: F,

    /// Base monomial $x^{2n}$, used to compute routine starting monomials.
    base_v_x: F,

    /// Floor plan mapping DFS routine index to absolute offsets.
    floor_plan: &'fp [RoutineSlot],

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
}

impl<'dr, F: Field, R: Rank> Driver<'dr> for Evaluator<'_, F, R> {
    type F = F;
    type Wire = WireEval<F>;

    const ONE: Self::Wire = WireEval::One;

    /// Allocates a wire using paired allocation.
    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(monomial) = self.scope.available_b.take() {
            Ok(monomial)
        } else {
            let (a, b, _) = self.mul(|| unreachable!())?;
            self.scope.available_b = Some(b);

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
        let index = self.scope.multiplication_constraints;
        if index == R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }
        self.scope.multiplication_constraints += 1;

        let a = self.scope.current_u_x;
        let b = self.scope.current_v_x;
        let c = self.scope.current_w_x;

        self.scope.current_u_x *= self.x_inv;
        self.scope.current_v_x *= self.x;
        self.scope.current_w_x *= self.x_inv;

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
        let q = self.scope.linear_constraints;
        if q == R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }
        self.scope.linear_constraints += 1;

        self.result[q] = lc(WireEvalSum::new(self.one)).value;

        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        self.current_routine += 1;
        let slot = &self.floor_plan[self.current_routine];

        let init_scope = SxScope {
            available_b: None,
            current_u_x: self.base_u_x * self.x_inv.pow_vartime([slot.multiplication_start as u64]),
            current_v_x: self.base_v_x * self.x.pow_vartime([slot.multiplication_start as u64]),
            current_w_x: self.one * self.x_inv.pow_vartime([slot.multiplication_start as u64]),
            multiplication_constraints: slot.multiplication_start,
            linear_constraints: slot.linear_start,
        };

        self.with_scope(init_scope, |this| {
            let mut dummy = Emulator::wireless();
            let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
            let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
            let result = routine.execute(this, input, aux)?;

            // Verify this routine consumed exactly the expected constraints.
            assert_eq!(
                this.scope.multiplication_constraints,
                slot.multiplication_start + slot.num_multiplication_constraints,
                "routine multiplication constraint count must match floor plan"
            );
            assert_eq!(
                this.scope.linear_constraints,
                slot.linear_start + slot.num_linear_constraints,
                "routine linear constraint count must match floor plan"
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
/// - `key`: The registry key that binds this evaluation to a [`Registry`] context by
///   enforcing `key_wire - key = 0` as a constraint. This randomizes
///   evaluations of $s(x, Y)$, preventing trivial forgeries across registry
///   contexts.
///
/// - `floor_plan`: Per-routine absolute offsets, computed by
///   [`floor_plan()`](crate::floor_planner::floor_plan).
///
/// # Special Cases
///
/// If $x = 0$, returns the zero polynomial since all monomials vanish.
///
/// [`Registry`]: crate::registry::Registry
pub fn eval<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    x: F,
    key: &registry::Key<F>,
    floor_plan: &[RoutineSlot],
) -> Result<unstructured::Polynomial<F, R>> {
    if x == F::ZERO {
        return Ok(Polynomial::new());
    }

    let x_inv = x.invert().expect("x is not zero");
    let xn = x.pow_vartime([R::n() as u64]);
    let xn2 = xn.square();
    let base_u_x = xn2 * x_inv;
    let base_v_x = xn2;
    let xn4 = xn2.square();
    let one = xn4 * x_inv;

    let mut evaluator = Evaluator::<F, R> {
        result: unstructured::Polynomial::new(),
        scope: SxScope {
            available_b: None,
            current_u_x: base_u_x,
            current_v_x: base_v_x,
            current_w_x: one,
            multiplication_constraints: 0,
            linear_constraints: 0,
        },
        x,
        x_inv,
        one,
        base_u_x,
        base_v_x,
        floor_plan,
        current_routine: 0,
        _marker: core::marker::PhantomData,
    };

    // Allocate the key_wire and ONE wires
    let (key_wire, _, _one) = evaluator.mul(|| unreachable!())?;

    // Registry key constraint
    evaluator.enforce_registry_key(&key_wire, key)?;

    let mut outputs = vec![];
    let (io, _) = circuit.witness(&mut evaluator, Empty)?;
    io.write(&mut evaluator, &mut outputs)?;

    // Enforcing public inputs
    evaluator.enforce_public_outputs(outputs.iter().map(|output| output.wire()))?;
    evaluator.enforce_one()?;

    // Verify all floor plan slots were consumed and counts match.
    assert_eq!(
        evaluator.current_routine + 1,
        evaluator.floor_plan.len(),
        "floor plan routine count must match synthesis"
    );
    assert_eq!(
        evaluator.scope.multiplication_constraints,
        evaluator.floor_plan[0].num_multiplication_constraints,
        "root multiplication constraint count must match floor plan"
    );
    assert_eq!(
        evaluator.scope.linear_constraints, evaluator.floor_plan[0].num_linear_constraints,
        "root linear constraint count must match floor plan"
    );

    // Reverse to canonical coefficient order within each routine's linear
    // constraint range.
    for slot in evaluator.floor_plan {
        evaluator.result[slot.linear_start..slot.linear_start + slot.num_linear_constraints]
            .reverse();
    }
    assert_eq!(evaluator.result[0], evaluator.one);

    Ok(evaluator.result)
}
