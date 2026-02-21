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

use alloc::{collections::BTreeMap, vec};

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

use crate::{
    Circuit, DriverScope, floor_plan::FloorPlan, floor_planner::RoutineSlot, polynomials::Rank,
    registry, routines::RoutineId,
};

use super::{
    DriverExt,
    common::{CachedRoutine, MemoCache, WireEval, WireEvalSum, WireExtractor, WireInjector},
};

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
    /// Number of linear constraints processed so far in this routine.
    linear_constraints: usize,

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

    /// Canonical floor plan for inter-circuit memoization (optional).
    type_floor_plan: Option<&'fp FloorPlan>,

    /// Cache for memoized routine contributions (optional).
    memo_cache: Option<&'fp mut MemoCache<F>>,

    /// Per-routine-type invocation counters for cache key computation.
    invocation_counts: BTreeMap<RoutineId, usize>,

    /// Routine nesting depth; memoization only applies at depth 0.
    routine_depth: usize,

    /// Marker for the rank type parameter.
    _marker: core::marker::PhantomData<R>,
}

impl<F: Field, R: Rank> DriverScope<SxyScope<F>> for Evaluator<'_, F, R> {
    fn scope(&mut self) -> &mut SxyScope<F> {
        &mut self.scope
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
}

impl<'dr, F: Field, R: Rank> Driver<'dr> for Evaluator<'_, F, R> {
    type F = F;
    type Wire = WireEval<F>;

    const ONE: Self::Wire = WireEval::One;

    /// Allocates a wire using paired allocation.
    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(wire) = self.scope.available_b.take() {
            Ok(wire)
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
        let q = self.scope.linear_constraints;
        if q == R::num_coeffs() {
            return Err(Error::LinearBoundExceeded(R::num_coeffs()));
        }
        self.scope.linear_constraints += 1;

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
        let slot = &self.floor_plan[self.current_routine];
        let multiplication_start = slot.multiplication_start;
        let linear_start = slot.linear_start;

        // Compute cache key: (routine_id, canonical_position)
        let routine_id = RoutineId::of::<Ro>();
        let invocation_index = *self.invocation_counts.get(&routine_id).unwrap_or(&0);
        self.invocation_counts
            .entry(routine_id)
            .and_modify(|c| *c += 1)
            .or_insert(1);

        // Check for cache hit (only at top-level routines, depth == 0)
        let can_memoize =
            self.routine_depth == 0 && self.type_floor_plan.is_some() && self.memo_cache.is_some();

        if can_memoize {
            let type_floor_plan = self.type_floor_plan.unwrap();
            if let Some(canonical_pos) =
                type_floor_plan.get_invocation(&routine_id, invocation_index)
            {
                // SAFETY: We just checked memo_cache.is_some()
                let cache = self.memo_cache.as_ref().unwrap();
                if let Some(cached) = cache.get(&routine_id, canonical_pos) {
                    // Cache hit: reconstruct output without re-executing routine
                    let y_pow_linear_start = self.y.pow_vartime([linear_start as u64]);
                    self.scope.sum += y_pow_linear_start * cached.contribution;

                    // Reconstruct output gadget from cached wires:
                    // 1. Execute with wireless emulator to get a template with unit wires
                    // 2. Use WireInjector to convert unit wires to cached WireEval wires
                    let mut dummy = Emulator::wireless();
                    let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
                    let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();

                    let mut wireless = Emulator::wireless();
                    let wireless_input = Ro::Input::map_gadget(&input, &mut wireless)?;
                    let template = routine.execute(&mut wireless, wireless_input, aux)?;

                    let mut injector = WireInjector::<_, Self>::new(&cached.output_wires);
                    let output = Ro::Output::map_gadget(&template, &mut injector)?;
                    debug_assert!(
                        injector.is_exhausted(),
                        "wire cache should be fully consumed"
                    );

                    return Ok(output);
                }
            }
        }

        // Cache miss: execute routine normally
        let init_scope = SxyScope {
            available_b: None,
            current_u_x: self.base_u_x * self.x_inv.pow_vartime([multiplication_start as u64]),
            current_v_x: self.base_v_x * self.x.pow_vartime([multiplication_start as u64]),
            current_w_x: self.one * self.x_inv.pow_vartime([multiplication_start as u64]),
            multiplication_constraints: multiplication_start,
            linear_constraints: linear_start,
            result: F::ZERO,
            sum: F::ZERO,
        };

        // Manual save/restore: we need to capture the routine's result
        // before restoring parent state.
        let saved = core::mem::replace(&mut self.scope, init_scope);
        self.routine_depth += 1;
        let exec_result = {
            let mut dummy = Emulator::wireless();
            let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
            let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
            routine.execute(self, input, aux)
        };
        self.routine_depth -= 1;

        // Verify this routine consumed exactly the expected constraints.
        assert_eq!(
            self.scope.multiplication_constraints,
            slot.multiplication_start + slot.num_multiplication_constraints,
            "routine multiplication constraint count must match floor plan"
        );
        assert_eq!(
            self.scope.linear_constraints,
            slot.linear_start + slot.num_linear_constraints,
            "routine linear constraint count must match floor plan"
        );

        // Position the routine's local Horner result at its absolute Y offset,
        // then combine with any nested child contributions.
        let y_pow_linear_start = self.y.pow_vartime([linear_start as u64]);
        let routine_contribution = self.scope.result + self.scope.sum;

        // Store in cache if memoization is enabled
        if can_memoize {
            let type_floor_plan = self.type_floor_plan.unwrap();
            if let Some(canonical_pos) =
                type_floor_plan.get_invocation(&routine_id, invocation_index)
            {
                // Extract output wires for caching
                if let Ok(ref output) = exec_result {
                    let mut extractor = WireExtractor::new();
                    // map_gadget visits all wires in the gadget, extracting them
                    let _ = Ro::Output::map_gadget(output, &mut extractor);
                    let output_wires = extractor.into_wires();

                    let entry = CachedRoutine {
                        contribution: routine_contribution,
                        num_multiplications: slot.num_multiplication_constraints,
                        num_constraints: slot.num_linear_constraints,
                        output_wires,
                    };

                    // SAFETY: We checked memo_cache.is_some() above
                    self.memo_cache
                        .as_mut()
                        .unwrap()
                        .insert(routine_id, canonical_pos, entry);
                }
            }
        }

        self.scope = saved;
        self.scope.sum += y_pow_linear_start * routine_contribution;

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
/// - `key`: The registry key that binds this evaluation to a [`Registry`] context by
///   enforcing `key_wire - key = 0` as a constraint. This randomizes
///   evaluations of $s(x, y)$, preventing trivial forgeries across registry
///   contexts.
/// - `floor_plan`: Per-routine absolute offsets, computed by
///   [`floor_plan()`](crate::floor_planner::floor_plan).
///
/// [`Registry`]: crate::registry::Registry
pub fn eval<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    x: F,
    y: F,
    key: &registry::Key<F>,
    floor_plan: &[RoutineSlot],
) -> Result<F> {
    if x == F::ZERO {
        // The polynomial is zero if x is zero.
        return Ok(F::ZERO);
    }

    let x_inv = x.invert().expect("x is not zero");
    let xn = x.pow_vartime([R::n() as u64]); // xn = x^n
    let xn2 = xn.square(); // xn2 = x^(2n)
    let base_u_x = xn2 * x_inv; // x^(2n - 1)
    let base_v_x = xn2; // x^(2n)
    let xn4 = xn2.square(); // x^(4n)
    let one = xn4 * x_inv; // x^(4n - 1)

    if y == F::ZERO {
        // If y is zero, all terms y^j for j > 0 vanish, leaving only the ONE
        // wire coefficient.
        return Ok(one);
    }

    let mut evaluator = Evaluator::<F, R> {
        scope: SxyScope {
            available_b: None,
            current_u_x: base_u_x,
            current_v_x: base_v_x,
            current_w_x: one,
            multiplication_constraints: 0,
            linear_constraints: 0,
            result: F::ZERO,
            sum: F::ZERO,
        },
        x,
        x_inv,
        y,
        one,
        base_u_x,
        base_v_x,
        floor_plan,
        current_routine: 0,
        type_floor_plan: None,
        memo_cache: None,
        invocation_counts: BTreeMap::new(),
        routine_depth: 0,
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

    // The root's local Horner result plus any child contributions.
    Ok(evaluator.scope.result + evaluator.scope.sum)
}

/// Evaluates $s(x, y)$ with inter-circuit memoization.
///
/// Like [`eval`], but caches routine contributions for reuse across circuits.
/// Routines at the same canonical position (via `type_floor_plan`) share
/// cached results when the same `cache` is passed to multiple calls.
///
/// # Arguments
///
/// - `circuit`: The circuit whose wiring polynomial to evaluate.
/// - `x`: The evaluation point for the $X$ variable.
/// - `y`: The evaluation point for the $Y$ variable.
/// - `key`: The registry key for constraint binding.
/// - `floor_plan`: Per-routine absolute offsets (per-circuit).
/// - `type_floor_plan`: Canonical routine positions for cache keys.
/// - `cache`: Shared cache for inter-circuit memoization.
pub(crate) fn eval_with_cache<F: Field, C: Circuit<F>, R: Rank>(
    circuit: &C,
    x: F,
    y: F,
    key: &registry::Key<F>,
    floor_plan: &[RoutineSlot],
    type_floor_plan: &FloorPlan,
    cache: &mut MemoCache<F>,
) -> Result<F> {
    if x == F::ZERO {
        return Ok(F::ZERO);
    }

    let x_inv = x.invert().expect("x is not zero");
    let xn = x.pow_vartime([R::n() as u64]);
    let xn2 = xn.square();
    let base_u_x = xn2 * x_inv;
    let base_v_x = xn2;
    let xn4 = xn2.square();
    let one = xn4 * x_inv;

    if y == F::ZERO {
        return Ok(one);
    }

    let mut evaluator = Evaluator::<F, R> {
        scope: SxyScope {
            available_b: None,
            current_u_x: base_u_x,
            current_v_x: base_v_x,
            current_w_x: one,
            multiplication_constraints: 0,
            linear_constraints: 0,
            result: F::ZERO,
            sum: F::ZERO,
        },
        x,
        x_inv,
        y,
        one,
        base_u_x,
        base_v_x,
        floor_plan,
        current_routine: 0,
        type_floor_plan: Some(type_floor_plan),
        memo_cache: Some(cache),
        invocation_counts: BTreeMap::new(),
        routine_depth: 0,
        _marker: core::marker::PhantomData,
    };

    let (key_wire, _, _one) = evaluator.mul(|| unreachable!())?;
    evaluator.enforce_registry_key(&key_wire, key)?;

    let mut outputs = vec![];
    let (io, _) = circuit.witness(&mut evaluator, Empty)?;
    io.write(&mut evaluator, &mut outputs)?;

    evaluator.enforce_public_outputs(outputs.iter().map(|output| output.wire()))?;
    evaluator.enforce_one()?;

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

    Ok(evaluator.scope.result + evaluator.scope.sum)
}
