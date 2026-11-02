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
//! a specialized [`Driver`] that interprets circuit operations to produce
//! coefficients directly. Wires become evaluated monomials, and linear
//! combinations become field arithmetic.
//!
//! The driver redefines each operation as follows:
//!
//! - [`gate()`][`DriverTypes::gate`]: Returns wire handles for the $(A, B, C)$
//!   monomials $x^{2n + i}$, $x^{2n - 1 - i}$, $x^{4n - 1 - i}$ at the
//!   $i$-th gate, plus an [`Extra`] token for the $D$-wire monomial $x^{i}$.
//! - [`assign_extra()`][`DriverTypes::assign_extra`]: Converts the [`Extra`]
//!   token into the $D$-wire monomial $x^{i}$.
//! - [`mul()`][`Driver::mul`]: Like [`gate()`][`DriverTypes::gate`] but
//!   discards the [`Extra`]; returns only the $(A, B, C)$ monomials.
//!
//! [`Extra`]: DriverTypes::Extra
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
//! Wires are represented directly as evaluated monomials (field elements),
//! advanced via the running-monomial pattern: at gate $i$ the driver holds
//! $x^{2n+i}$, $x^{2n-1-i}$, and $x^{4n-1-i}$ for $a$, $b$, and $c$. The
//! `ONE` wire evaluates to $1$ (monomial $x^0$).
//!
//! ### Coefficient Order
//!
//! Each [`Driver::enforce_zero`] call writes its coefficient to the next
//! indexed position in the result vector within the current routine's range.
//! Because Horner's rule in [`sxy`] assigns decreasing $Y$-powers to
//! later-emitted constraints (the first emitted gets the highest power), the
//! emission-order storage is reversed relative to the canonical polynomial
//! convention where index $j$ is the coefficient of $Y^j$.
//!
//! To reconcile this, [`eval`] reverses each routine's coefficient range after
//! constraint emission completes. This per-routine reversal ensures that both
//! this module and [`sxy`] agree on which constraint maps to which $Y$-power.
//!
//! After reversal, the root segment's coefficients are ordered as:
//! 1. $c\_{0}$: `ONE` wire constraint (the constant $1$)
//! 2. $c\_{1}, \ldots, c\_{p}$: public output constraints
//! 3. $c\_{p+1}, \ldots, c\_{p+m}$: circuit-specific constraints
//!
//! This follows from the root segment's emission order — circuit body first,
//! then public outputs, and `ONE` last — being flipped by the reversal.
//!
//! The registry tag constraint is **not** included in these coefficients; it
//! occupies the fixed $Y^{4n-1}$ slot and is injected at the registry level.
//!
//! [`Driver`]: ragu_core::drivers::Driver
//! [`Driver::add`]: ragu_core::drivers::Driver::add
//! [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
//! [`Driver::mul`]: ragu_core::drivers::Driver::mul
//! [`DriverTypes::gate`]: ragu_core::drivers::DriverTypes::gate
//! [`sxy`]: super::sxy

use alloc::{vec, vec::Vec};

use ragu_core::{
    Coeff, Error, Result,
    convert::{StripWires, WireMap as _, extract_wires},
    drivers::{
        DirectSum, Driver, DriverTypes,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, GadgetKind as _},
    maybe::Empty,
    routines::Routine,
};
use udon::field::Field;

use super::{
    memo::{MemoCache, Placement, WireInjector},
    record::{self, Recorded},
};
use crate::{
    DeepFingerprint, DriverScope, RoutineIdentity, SegmentRecord,
    floor_planner::ConstraintSegment,
    polynomials::{Rank, sparse},
    raw::RawCircuit,
};

/// Per-routine state saved and restored across routine boundaries.
struct SxScope<F> {
    /// Running monomial for $a$ wires: $x^{2n + i}$ at gate $i$.
    current_a_x: F,
    /// Running monomial for $b$ wires: $x^{2n - 1 - i}$ at gate $i$.
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

/// A [`Driver`] that computes the partial evaluation $s(x, Y)$.
///
/// Given a fixed evaluation point $x \in \mathbb{F}$, this driver interprets
/// circuit operations to produce the coefficients of $s(x, Y)$ directly as
/// field elements. Each call to [`Driver::enforce_zero`] stores one coefficient
/// in the result polynomial.
///
/// [`Driver`]: ragu_core::drivers::Driver
/// [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
struct Evaluator<'fp, F: Field, R: Rank> {
    /// Accumulated polynomial coefficients, built in reverse emission order.
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

    /// Base monomial $x^{2n}$, used to compute routine starting monomials.
    base_a_x: F,

    /// Base monomial $x^{2n-1}$, used to compute routine starting monomials.
    base_b_x: F,

    /// Base monomial $x^{4n-1}$, used to compute routine starting monomials
    /// for the $c$ wire.
    base_c_x: F,

    /// Correction factor $(x^{-2n})$ that converts an $a$-wire monomial
    /// $x^{2n+i}$ into the corresponding $d$-wire monomial $x^i$.
    ///
    /// Only used by [`assign_extra`](DriverTypes::assign_extra), so the
    /// multiplication is skipped when callers keep the default $D = 0$.
    a_to_d: F,

    /// Floor plan mapping DFS segment index to absolute offsets.
    floor_plan: &'fp [ConstraintSegment],

    /// Global monotonic DFS counter for routine entries.
    current_routine: usize,

    /// Per-segment constraint records (from metrics), used to extract fingerprints.
    segment_records: &'fp [SegmentRecord],

    /// Cache for memoized routine contributions (optional).
    memo_cache: Option<&'fp mut MemoCache<F>>,

    /// Routine nesting depth; memoization only applies at depth 0.
    routine_depth: usize,

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
/// - `MaybeKind = Empty`: No witness input is needed; we only evaluate the
///   polynomial structure.
/// - `LCadd` / `LCenforce`: Use [`DirectSum`] to accumulate linear combinations
///   as immediate field element sums.
/// - `ImplWire`: Wires are represented directly as evaluated monomials in $F$.
impl<F: Field, R: Rank> DriverTypes for Evaluator<'_, F, R> {
    type MaybeKind = Empty;
    type LCadd = DirectSum<F>;
    type LCenforce = DirectSum<F>;
    type ImplField = F;
    type ImplWire = F;
    type Extra = F;

    /// Consumes a gate, returning evaluated monomials for $(a, b, c)$ and the
    /// raw $a$-wire monomial as [`Extra`](DriverTypes::Extra).
    ///
    /// Returns the current values of the running monomials, then advances the
    /// monomials for the next gate:
    /// - $a$: multiplied by $x$ (increasing exponent)
    /// - $b$: multiplied by $x^{-1}$ (decreasing exponent)
    /// - $c$: multiplied by $x^{-1}$ (decreasing exponent)
    ///
    /// The $d$-wire monomial $x^i$ is derived from $a = x^{2n+i}$ via
    /// `a_to_d` in [`assign_extra`](DriverTypes::assign_extra).
    ///
    /// # Errors
    ///
    /// Returns [`Error::GateBoundExceeded`] if the gate count reaches
    /// [`Rank::n()`].
    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(F, F, F, F)> {
        let index = self.scope.gates;
        if index == R::n() {
            return Err(Error::GateBoundExceeded { limit: R::n() });
        }
        self.scope.gates += 1;

        let a = self.scope.current_a_x;
        let b = self.scope.current_b_x;
        let c = self.scope.current_c_x;

        self.scope.current_a_x *= self.x;
        self.scope.current_b_x *= self.x_inv;
        self.scope.current_c_x *= self.x_inv;

        Ok((a, b, c, a))
    }

    /// Converts the raw $a$-wire monomial carried by [`Extra`](DriverTypes::Extra)
    /// into the corresponding $d$-wire monomial by multiplying by `a_to_d`.
    fn assign_extra(&mut self, a: Self::Extra, _: impl Fn() -> Result<Coeff<F>>) -> Result<F> {
        Ok(a * self.a_to_d)
    }
}

impl<'dr, F: Field, R: Rank> Driver<'dr> for Evaluator<'_, F, R> {
    type F = F;
    type Wire = F;

    const ONE: Self::Wire = F::ONE;

    /// Computes a linear combination of wire evaluations.
    ///
    /// Evaluates the linear combination immediately using [`DirectSum`] and
    /// returns the sum as a field element. No deferred computation is needed
    /// because all wire values are concrete field elements.
    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        lc(DirectSum::default()).value()
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
    /// tag constraint).
    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let q = self.scope.constraints;
        if q >= R::num_coeffs() - 1 {
            return Err(Error::ConstraintBoundExceeded {
                limit: R::num_coeffs() - 1,
            });
        }
        self.scope.constraints += 1;

        self.result[q] = lc(DirectSum::default()).value();

        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        self.current_routine += 1;
        let index = self.current_routine;
        let seg = &self.floor_plan[index];

        // Only top-level routines are memoized; a recording covers the whole
        // subtree. On a miss the routine is recorded in a position-free frame
        // (see the `record` module); either way its constraints and output
        // wires are replayed at this placement.
        let memo = (self.routine_depth == 0 && self.memo_cache.is_some())
            .then(|| self.fingerprint_at(index));

        if let Some(fingerprint) = memo {
            let cache = self.memo_cache.as_mut().expect("memo implies a cache");
            let inputs = match cache.lookup(&fingerprint) {
                Some(_) => extract_wires(&input, |w: &F| *w)?,
                None => {
                    let (recorded, inputs) = record::record(
                        &routine,
                        &input,
                        self.record_params(),
                        self.floor_plan,
                        index,
                        |w: &F| *w,
                    )?;
                    self.memo_cache
                        .as_mut()
                        .expect("memo implies a cache")
                        .insert(fingerprint, recorded);
                    inputs
                }
            };

            // Replay every segment's constraints at its absolute position, in
            // emission order; the per-segment reversal in `eval` makes them
            // canonical afterwards.
            let xm = self.x.pow_u64(seg.gate_start as u64);
            let xm_inv = self.x_inv.pow_u64(seg.gate_start as u64);
            let sharing = self
                .memo_cache
                .as_ref()
                .is_some_and(|cache| cache.is_sharing());
            let recorded = self
                .memo_cache
                .as_ref()
                .and_then(|cache| cache.get(&fingerprint))
                .expect("recording was just looked up or inserted");
            for segment in &recorded.constraints {
                let start = seg.constraint_start + segment.constraint_start;
                for (k, form) in segment.forms.iter().enumerate() {
                    // In sharing mode the registry adds the position-dependent
                    // part once for every circuit with this block here.
                    self.result[start + k] = if sharing {
                        form.evaluate_interface(&inputs)
                    } else {
                        form.evaluate(xm, xm_inv, &inputs)
                    };
                }
            }
            let output_wires: Vec<F> = recorded
                .outputs
                .iter()
                .map(|form| form.evaluate(xm, xm_inv, &inputs))
                .collect();
            let num_segments = recorded.num_segments;
            if sharing {
                let placement = Placement {
                    gate_start: seg.gate_start,
                    constraint_start: seg.constraint_start,
                };
                self.memo_cache
                    .as_mut()
                    .expect("memo implies a cache")
                    .note_shared(fingerprint, placement);
            }

            // Reconstruct the output gadget from the replayed wires:
            // 1. Execute on a wireless emulator to get a template with unit wires.
            // 2. Use WireInjector to replace the unit wires with the values.
            type W<F> = Emulator<Wireless<Empty, F>>;

            let aux = Emulator::predict(&routine, &input)?.into_aux();
            let wireless_input = StripWires::<Self>::remap(&input)?;
            let template = routine.execute(&mut W::<F>::wireless(), wireless_input, aux)?;

            let mut injector = WireInjector::<_, W<F>, Self>::new(&output_wires);
            let output = Ro::Output::map_gadget(&template, &mut injector)?;
            debug_assert!(
                injector.is_exhausted(),
                "replayed wires should be fully consumed"
            );

            // The recording already includes the nested sub-routines, so
            // skip their segments.
            self.current_routine += num_segments - 1;

            return Ok(output);
        }

        // Jump to this routine's absolute position in the polynomial;
        // see "Polynomial Encoding and Scope Jumps" in the `s` module doc.
        let x_pow = self.x.pow_u64(seg.gate_start as u64);
        let x_inv_pow = self.x_inv.pow_u64(seg.gate_start as u64);
        let init_scope = SxScope {
            current_a_x: self.base_a_x * x_pow,
            current_b_x: self.base_b_x * x_inv_pow,
            current_c_x: self.base_c_x * x_inv_pow,
            gates: seg.gate_start,
            constraints: seg.constraint_start,
        };

        self.routine_depth += 1;
        let result = self.with_scope(init_scope, |this| {
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
        });
        self.routine_depth -= 1;
        result
    }
}

impl<F: Field, R: Rank> Evaluator<'_, F, R> {
    /// Fingerprint recorded for the routine segment at `index`.
    fn fingerprint_at(&self, index: usize) -> DeepFingerprint {
        match self.segment_records[index].identity() {
            RoutineIdentity::Routine(fp) => *fp,
            RoutineIdentity::Root => unreachable!("routine segments are never Root"),
        }
    }

    /// Evaluation-point data shared with the routine recorder. `s(x, Y)`
    /// has no fixed `y`; the recorder's Horner view is unused here.
    fn record_params(&self) -> record::Params<F> {
        record::Params {
            x: self.x,
            x_inv: self.x_inv,
            y: F::ZERO,
            y_inv: F::ZERO,
            base_a_x: self.base_a_x,
            base_b_x: self.base_b_x,
            base_c_x: self.base_c_x,
            a_to_d: self.a_to_d,
        }
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
#[cfg_attr(not(test), allow(dead_code))]
pub fn eval<F: Field, RC: RawCircuit<F>, R: Rank>(
    circuit: &RC,
    x: F,
    floor_plan: &[ConstraintSegment],
    segment_records: &[SegmentRecord],
) -> Result<sparse::Polynomial<F, R>> {
    eval_inner::<F, RC, R>(circuit, x, floor_plan, segment_records, None)
}

/// Evaluates $s(x, Y)$ with routine memoization.
///
/// Like [`eval`], but records each top-level routine's constraints in a
/// position-free form and replays them for every later invocation with the
/// same fingerprint, within this circuit and across circuits that share
/// `cache`; see the [`memo`](super::memo) and [`record`] modules.
pub(crate) fn eval_with_cache<F: Field, RC: RawCircuit<F>, R: Rank>(
    circuit: &RC,
    x: F,
    floor_plan: &[ConstraintSegment],
    segment_records: &[SegmentRecord],
    cache: &mut MemoCache<F>,
) -> Result<sparse::Polynomial<F, R>> {
    eval_inner::<F, RC, R>(circuit, x, floor_plan, segment_records, Some(cache))
}

/// The position-independent part of a recorded block placed at `placement`,
/// as a polynomial in $Y$ at this $x$, scaled by `scale`. This is what the
/// evaluators leave out in sharing mode; see [`MemoCache`].
pub(crate) fn shared_block<F: Field, R: Rank>(
    recorded: &Recorded<F>,
    placement: Placement,
    x: F,
    scale: F,
) -> sparse::Polynomial<F, R> {
    let x_inv = if x == F::ZERO {
        F::ZERO
    } else {
        x.invert().expect("x is not zero")
    };
    let xm = x.pow_u64(placement.gate_start as u64);
    let xm_inv = x_inv.pow_u64(placement.gate_start as u64);

    let mut coeffs = vec![F::ZERO; R::num_coeffs()];
    for segment in &recorded.constraints {
        let start = placement.constraint_start + segment.constraint_start;
        let len = segment.forms.len();
        for (k, form) in segment.forms.iter().enumerate() {
            // Emission order is reversed within a segment, as in `eval`.
            coeffs[start + len - 1 - k] = form.evaluate_internal(xm, xm_inv) * scale;
        }
    }
    sparse::Polynomial::from_coeffs(coeffs)
}

fn eval_inner<F: Field, RC: RawCircuit<F>, R: Rank>(
    circuit: &RC,
    x: F,
    floor_plan: &[ConstraintSegment],
    segment_records: &[SegmentRecord],
    memo_cache: Option<&mut MemoCache<F>>,
) -> Result<sparse::Polynomial<F, R>> {
    // At x = 0 every monomial other than x^0 vanishes; the d[0] ONE wire
    // (at x^0) still contributes F::ONE. Set x_inv = 0 so the running
    // monomials stay zero through constraint emission.
    let x_inv = if x == F::ZERO {
        F::ZERO
    } else {
        x.invert().expect("x is not zero")
    };
    let xn = x.pow_u64(R::n() as u64);
    let xn2 = xn.square();
    let base_a_x = xn2;
    let base_b_x = xn2 * x_inv;
    let xn4 = xn2.square();
    let base_c_x = xn4 * x_inv;
    let xn_inv = x_inv.pow_u64(R::n() as u64);
    let base_a_x_inv = xn_inv.square();

    let mut evaluator = Evaluator::<F, R> {
        // Zero-initialized: the evaluator fills specific indices during
        // constraint emission. Unfilled indices must remain zero as they
        // represent unused wire slots.
        result: vec![F::ZERO; R::num_coeffs()],
        scope: SxScope {
            current_a_x: base_a_x,
            current_b_x: base_b_x,
            current_c_x: base_c_x,
            gates: 0,
            constraints: 0,
        },
        x,
        x_inv,
        base_a_x,
        base_b_x,
        base_c_x,
        a_to_d: base_a_x_inv,
        floor_plan,
        current_routine: 0,
        segment_records,
        memo_cache,
        routine_depth: 0,
        _marker: core::marker::PhantomData,
    };

    crate::raw::orchestrate(&mut evaluator, circuit, Empty)?;

    // Verify all floor plan segments were consumed and counts match.
    assert_eq!(
        evaluator.current_routine + 1,
        evaluator.floor_plan.len(),
        "floor plan routine count must match constraint emission"
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
    assert_eq!(evaluator.result[0], F::ONE);

    Ok(sparse::Polynomial::from_coeffs(evaluator.result))
}
