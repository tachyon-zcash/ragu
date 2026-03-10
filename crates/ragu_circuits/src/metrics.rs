//! Circuit constraint analysis, metrics collection, and routine identity
//! fingerprinting.
//!
//! This module provides constraint system analysis by simulating circuit
//! execution without computing assignment values, counting the number of
//! gates and constraints a circuit emits. It simultaneously computes
//! Schwartz–Zippel fingerprints for each routine invocation via the
//! merged [`Counter`] driver, which combines constraint counting with identity
//! evaluation in a single DFS traversal.
//!
//! # Fingerprinting
//!
//! Every routine invocation is recorded with two fingerprints, separating
//! polynomial equivalence (floor planning) from memoization safety
//! (cache keys):
//!
//! - [`BaseFingerprint`] — `(num_gates, num_constraints, eval)`. Captures
//!   the routine's local $s(X,Y)$ contribution: the gate/constraint shape of
//!   its base segment and the Schwartz–Zippel evaluation scalar obtained by
//!   running the routine on four independent geometric sequences (one per
//!   `a`/`b`/`c`/`d` wire) with constraint coefficients folded via Horner in
//!   `y`. Two routines with the same `BaseFingerprint` contribute the same
//!   thing to $s(X,Y)$ with overwhelming probability.
//!
//! - [`DeepFingerprint`] — `{ base, deep }`. Extends the base fingerprint
//!   with a recursive 64-bit BLAKE2b digest that binds the raw
//!   geometric-sequence evaluations of the routine's output-gadget wires
//!   and the deep fingerprints of every direct child routine. Two invocations
//!   with the same `DeepFingerprint` are structurally identical at every
//!   nesting level and can be memoized together with their entire subtree.
//!
//! Type identity is deliberately *not* part of the fingerprint. Under the
//! relaxed-fungibility model, routine equivalence is layout-keyed: two routines
//! that contribute identically to $s(X, Y)$ and produce the same wire layout
//! are equivalent for memoization purposes regardless of the Rust types of
//! their `Input` or `Output` gadgets. Allocation determinism on `GadgetKind`
//! ensures that reconstructing the typed output gadget from cached wire values
//! yields the correct result independent of static type identity.
//!
//! Fingerprints are wrapped in [`RoutineIdentity`], an enum that distinguishes
//! the root circuit body ([`Root`](RoutineIdentity::Root)) from actual routine
//! invocations ([`Routine`](RoutineIdentity::Routine)). `RoutineIdentity`
//! deliberately does **not** implement comparison or hashing traits, forcing
//! callers to handle the root variant explicitly rather than accidentally
//! including it in equivalence maps.

use alloc::vec::Vec;

use ragu_core::{
    Coeff, Result,
    convert::{WireMap, extract_wires},
    drivers::{DirectSum, Driver, DriverTypes, emulator::Emulator},
    gadgets::{Bound, GadgetKind as _},
    maybe::Empty,
    routines::Routine,
};
use udon::field::Field;

use super::{Circuit, raw::RawCircuit};

/// The structural identity of a routine record.
///
/// Distinguishes the root circuit body from actual routine invocations. The
/// root cannot be floated or memoized, so it has no fingerprint — callers must
/// handle it explicitly.
///
/// This type deliberately does **not** implement [`PartialEq`], [`Eq`],
/// [`Hash`], or ordering traits. Code that builds equivalence maps over
/// fingerprints must match on the [`Routine`](RoutineIdentity::Routine) variant
/// and handle [`Root`](RoutineIdentity::Root) separately.
#[derive(Clone, Copy, Debug)]
pub enum RoutineIdentity {
    /// The root circuit body (segment 0). Cannot be floated or memoized.
    Root,
    /// An actual routine invocation with a full deep fingerprint.
    Routine(DeepFingerprint),
}

/// Polynomial-equivalence fingerprint for a single routine invocation.
///
/// Captures the routine's local contribution to the wiring polynomial
/// $s(X, Y)$: the gate/constraint shape of its base segment together with a
/// Schwartz–Zippel evaluation scalar. Two routines sharing a
/// `BaseFingerprint` make the same contribution to $s(X, Y)$ with
/// overwhelming probability.
///
/// `BaseFingerprint` is what the floor planner uses to group segments with
/// the same polynomial shape. Nested-subtree information is deliberately
/// excluded — it does not affect the polynomial contribution of the base
/// segment alone; it lives only in the enclosing [`DeepFingerprint`].
///
/// The 64-bit `eval` truncation gives ~2^{-64} collision probability per pair,
/// which is adequate for floor-planner and intra-circuit memoization
/// equivalence classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BaseFingerprint {
    num_gates: usize,
    num_constraints: usize,
    eval: u64,
}

impl BaseFingerprint {
    fn new<F: Field>(eval: F, num_gates: usize, num_constraints: usize) -> Self {
        // The low 64 bits of the canonical little-endian encoding.
        let mut low = [0u8; 8];
        for (dst, src) in low.iter_mut().zip(eval.to_bytes().as_ref()) {
            *dst = *src;
        }
        Self {
            num_gates,
            num_constraints,
            eval: u64::from_le_bytes(low),
        }
    }

    /// The number of gates in the routine's base segment.
    pub fn num_gates(&self) -> usize {
        self.num_gates
    }

    /// The number of constraints in the routine's base segment.
    pub fn num_constraints(&self) -> usize {
        self.num_constraints
    }
}

/// Full recursive fingerprint for a routine invocation.
///
/// Augments [`BaseFingerprint`] with a 64-bit BLAKE2b digest that recursively
/// folds in the raw values of the routine's output-gadget wires (which carry
/// positional information relative to the routine's own scope) and the deep
/// fingerprints of every direct child routine. Two invocations with matching
/// `DeepFingerprint`s are structurally identical at every nesting level —
/// same base shape, same output wire placement, same recursive subtree.
///
/// Type identity is *not* part of the digest: under relaxed fungibility,
/// routines whose outputs differ only in Rust type wrapper (e.g. `Element`
/// vs a newtype wrapping it, with the same wire layout) are treated as
/// equivalent. Allocation determinism on `GadgetKind` is what makes
/// substitution between such routines safe at memoization time.
///
/// The separation from [`BaseFingerprint`] matters because deep equivalence is
/// a stronger claim than base equivalence and enables stronger memoization
/// (caching an entire routine subtree, not just the base segment).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeepFingerprint {
    base: BaseFingerprint,
    deep: u64,
}

/// Domain tag for the deep fingerprint hash.
const DEEP_HASH_PERSONAL: &[u8; 16] = b"ragu_deep_hash__";

impl DeepFingerprint {
    /// Builds a [`DeepFingerprint`] from a routine's base segment shape,
    /// output-gadget wire values, and direct child deep hashes.
    ///
    /// The deep hash absorbs, in order:
    ///
    /// 1. all [`BaseFingerprint`] fields: `eval`, `num_gates`,
    ///    `num_constraints`;
    /// 2. the number of output-gadget wires (length-bound to avoid
    ///    concatenation ambiguity on the subsequent stream) followed by
    ///    each output wire's raw field-element value in canonical byte
    ///    repr;
    /// 3. the number of direct child routines (length-bound) followed by
    ///    each child's deep hash.
    ///
    /// Hashing output-wire values directly (rather than collapsing them
    /// to a single scalar first) keeps the hash sensitive to wire-order
    /// permutations that leave the output gadget tuple-equal. The stored
    /// `deep` is the first 8 bytes of the BLAKE2b digest interpreted as a
    /// little-endian `u64`.
    fn new<F: Field, Ro: Routine<F>>(
        base: BaseFingerprint,
        output_wires: &[F],
        children: &[u64],
    ) -> Self {
        let _ = core::marker::PhantomData::<Ro>;
        let mut state = blake2b_simd::Params::new()
            .personal(DEEP_HASH_PERSONAL)
            .to_state();
        state.update(&base.eval.to_le_bytes());
        state.update(&(base.num_gates as u64).to_le_bytes());
        state.update(&(base.num_constraints as u64).to_le_bytes());
        state.update(&(output_wires.len() as u64).to_le_bytes());
        for w in output_wires {
            state.update(w.to_bytes().as_ref());
        }
        state.update(&(children.len() as u64).to_le_bytes());
        for child in children {
            state.update(&child.to_le_bytes());
        }
        let bytes = state.finalize();
        let bytes = bytes.as_array();
        let deep = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        Self { base, deep }
    }

    /// Returns the base fingerprint (polynomial equivalence only).
    pub fn base(&self) -> &BaseFingerprint {
        &self.base
    }

    /// Returns the recursive deep hash.
    pub fn deep(&self) -> u64 {
        self.deep
    }

    /// Returns the raw constraint evaluation scalar.
    #[cfg(test)]
    pub(crate) fn eval(&self) -> u64 {
        self.base.eval
    }

    /// Creates a fingerprint with synthetic values for testing.
    #[cfg(test)]
    pub(crate) fn test(eval: u64, num_gates: usize, num_constraints: usize) -> Self {
        Self {
            base: BaseFingerprint {
                num_gates,
                num_constraints,
                eval,
            },
            deep: eval,
        }
    }
}

/// Constraint counts for one segment of the circuit.
///
/// Each record captures the gates and constraints contributed
/// by a single segment in DFS order. Segments are the primary boundary for
/// floor planning: the floor planner decides where each segment's constraints
/// are placed in the polynomial layout.
///
/// The circuit is divided into segments whose boundaries are [`Routine`] calls:
/// - **Index 0** is the *root segment* — it is not backed by any [`Routine`]
///   and accumulates every constraint emitted directly at circuit scope
///   (outside any routine call).
/// - **Indices 1+** each correspond to one [`Routine`] invocation and capture
///   only the constraints *local* to that routine's scope. Constraints
///   delegated to a nested sub-routine are counted in the sub-routine's own
///   segment, not in the parent's.
///
/// # Example
///
/// Consider a circuit with this constraint-emission order:
///
/// ```text
/// [c0]  RoutineA  [c1]  RoutineB{ [b0]  RoutineC  [b1] }  [c2]
///
/// root segment: { c0: 3*mul + 2*lc, c1: 1*mul + 1*lc, c2: 1*lc }
/// RoutineA: 2*mul + 3*lc
/// RoutineB: { b0: 1*mul + 2*lc, b1: 1*lc }
/// RoutineC: 1*mul + 2*lc
/// ```
///
/// The resulting segment records (DFS order) are:
///
/// | index | segment        | mul | lc | note                       |
/// |-------|----------------|-----|----|----------------------------|
/// | 0     | root segment   |  4  |  4 | c0+c1+c2                   |
/// | 1     | `RoutineA`     |  2  |  3 | A's own constraints        |
/// | 2     | `RoutineB`     |  1  |  3 | b0+b1; `RoutineC` excluded |
/// | 3     | `RoutineC`     |  1  |  2 | C's own constraints        |
#[derive(Debug, Clone, Copy)]
pub struct SegmentRecord {
    num_gates: usize,
    num_constraints: usize,
    identity: RoutineIdentity,
}

impl SegmentRecord {
    /// The number of gates in this segment.
    pub fn num_gates(&self) -> usize {
        self.num_gates
    }

    /// The number of constraints in this segment, including constraints
    /// on wires of the input gadget and on wires allocated within the segment.
    pub fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    /// The structural identity of this routine invocation.
    pub(crate) fn identity(&self) -> &RoutineIdentity {
        &self.identity
    }

    /// Creates a segment record with synthetic values for testing.
    #[cfg(test)]
    pub(crate) fn test(
        num_gates: usize,
        num_constraints: usize,
        identity: RoutineIdentity,
    ) -> Self {
        Self {
            num_gates,
            num_constraints,
            identity,
        }
    }
}

/// A summary of a circuit's constraint topology.
///
/// Captures constraint counts and per-routine records by simulating circuit
/// execution without computing actual values.
pub struct CircuitMetrics {
    /// The number of constraints, including those for instance enforcement.
    pub(crate) num_constraints: usize,

    /// The number of gates, including those used for allocations.
    pub(crate) num_gates: usize,

    /// The degree of the instance polynomial $k(Y)$.
    pub(crate) degree_ky: usize,

    /// Per-segment constraint records in DFS emission order.
    ///
    /// See [`SegmentRecord`] for the indexing convention: index 0 is the
    /// root segment (not backed by a [`Routine`]); indices 1+ each correspond
    /// to a [`Routine`] invocation.
    pub(crate) segments: Vec<SegmentRecord>,
}

/// Per-routine state that is saved and restored across routine boundaries.
///
/// Contains both the constraint counting record index and the identity
/// evaluation state (geometric sequence runners and Horner accumulator).
struct CounterScope<F> {
    /// Index into [`Counter::segments`] for the current routine.
    current_segment: usize,

    /// Running monomial for $a$ wires: $x_0^{i+1}$ at gate $i$.
    current_a: F,

    /// Running monomial for $b$ wires: $x_1^{i+1}$ at gate $i$.
    current_b: F,

    /// Running monomial for $c$ wires: $x_2^{i+1}$ at gate $i$.
    current_c: F,

    /// Running monomial for $d$ wires: $x_3^{i+1}$ at gate $i$.
    current_d: F,

    /// Per-scope remap sequence for [`WireMap`]-driven interface wire minting.
    /// Initialized fresh on every scope push (`cur = base`), so each routine's
    /// input-gadget wires mint the same `base, base^2, …` prefix regardless
    /// of caller context.
    remap: ReinitWires<F>,

    /// Horner accumulator for the fingerprint evaluation result. Seeded to
    /// `F::ZERO` on every scope push.
    result: F,

    /// Deep hashes of direct child routines, collected during execution.
    /// Folded into this scope's own `DeepFingerprint` on exit.
    child_deep_hashes: Vec<u64>,
}

/// A [`WireMap`] that mints each source wire as a fresh value from an
/// independent geometric sequence.
///
/// Holds a never-mutated `base` (the geometric ratio) and a running `cur`
/// that advances by `base` on every [`convert_wire`](ReinitWires::convert_wire)
/// call. Keeps the base and the running counter co-located so the "base is
/// only read" invariant is auditable in one place.
///
/// Each routine scope owns its own `ReinitWires` and re-initializes it on
/// entry (`cur = base`), so input-gadget wires observe the same prefix
/// `base, base^2, …` regardless of caller context — which is what makes
/// structurally identical routine invocations produce identical fingerprints.
/// On return to the parent scope, the parent's `ReinitWires` is restored and
/// continues from where it left off, appending the child's output-gadget
/// wires to the parent's sequence.
struct ReinitWires<F> {
    /// Geometric ratio. Never mutated after construction.
    base: F,
    /// Running counter. Each call to [`mint`](Self::mint) returns the current
    /// value, then multiplies it by `base`.
    cur: F,
}

impl<F: Copy + core::ops::MulAssign> ReinitWires<F> {
    fn new(base: F) -> Self {
        Self { base, cur: base }
    }

    fn mint(&mut self) -> F {
        let v = self.cur;
        self.cur *= self.base;
        v
    }
}

/// [`WireMap`] for `Counter`→`Counter`: every source wire is replaced by a
/// fresh value from this `ReinitWires` sequence. No gates are allocated and
/// no constraint counts change.
impl<F: Field> WireMap<F> for ReinitWires<F> {
    type Src = Counter<F>;
    type Dst = Counter<F>;

    fn convert_wire(&mut self, _: &F) -> Result<F> {
        Ok(self.mint())
    }
}

/// A [`Driver`] that simultaneously counts constraints and computes routine
/// identity fingerprints via Schwartz–Zippel evaluation.
///
/// Assigns four independent geometric sequences (bases $x_0, x_1, x_2, x_3$) to
/// the $a$, $b$, $c$, $d$ wires and accumulates constraint values via Horner's
/// rule over $y$. When entering a routine, the identity state is saved and
/// reset so that each routine is fingerprinted independently of its calling
/// context.
///
/// Nested routine outputs are treated as auxiliary inputs to the caller: on
/// return, output wires are remapped to fresh allocations in the parent scope
/// rather than folding the child's fingerprint scalar. This makes each
/// routine's base fingerprint capture only its *internal* constraint structure;
/// the deep fingerprint captures the full recursive subtree.
struct Counter<F> {
    scope: CounterScope<F>,
    num_constraints: usize,
    num_gates: usize,
    segments: Vec<SegmentRecord>,

    /// Base for the $a$-wire geometric sequence.
    x0: F,

    /// Base for the $b$-wire geometric sequence.
    x1: F,

    /// Base for the $c$-wire geometric sequence.
    x2: F,

    /// Base for the $d$-wire geometric sequence.
    x3: F,

    /// Immutable base for the remap geometric sequence used by
    /// [`ReinitWires`]. Read once when each scope's `remap` is constructed;
    /// never mutated. Independent from `x0..x3` so remap-minted wire values
    /// cannot collide with allocated wire values.
    x_remap: F,

    /// Multiplier for Horner accumulation, applied per [`enforce_zero`] call.
    ///
    /// [`enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
    y: F,
}

impl<F: Field> Counter<F> {
    fn new() -> Self {
        let base_state = blake2b_simd::Params::new()
            .personal(b"ragu_counter____")
            .to_state();
        let point = |index: u8| {
            F::from_uniform_bytes(base_state.clone().update(&[index]).finalize().as_array())
        };

        let x0 = point(0);
        let x1 = point(1);
        let x2 = point(2);
        let x3 = point(3);
        let y = point(4);
        let x_remap = point(5);

        Self {
            scope: CounterScope {
                current_segment: 0,
                current_a: x0,
                current_b: x1,
                current_c: x2,
                current_d: x3,
                remap: ReinitWires::new(x_remap),
                result: F::ZERO,
                child_deep_hashes: Vec::new(),
            },
            num_constraints: 0,
            num_gates: 0,
            segments: alloc::vec![SegmentRecord {
                num_gates: 0,
                num_constraints: 0,
                identity: RoutineIdentity::Root,
            }],
            x0,
            x1,
            x2,
            x3,
            y,
            x_remap,
        }
    }
}

impl<F: Field> DriverTypes for Counter<F> {
    type MaybeKind = Empty;
    type ImplField = F;
    type ImplWire = F;
    type LCadd = DirectSum<F>;
    type LCenforce = DirectSum<F>;
    type Extra = F;

    /// Consumes a gate: increments gate counts and returns wire values from
    /// four independent geometric sequences, advancing each by its base.
    /// The $d$-wire monomial is returned as `Extra`.
    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(F, F, F, F)> {
        self.num_gates += 1;
        self.segments[self.scope.current_segment].num_gates += 1;

        let a = self.scope.current_a;
        let b = self.scope.current_b;
        let c = self.scope.current_c;
        let d = self.scope.current_d;

        self.scope.current_a *= self.x0;
        self.scope.current_b *= self.x1;
        self.scope.current_c *= self.x2;
        self.scope.current_d *= self.x3;

        Ok((a, b, c, d))
    }

    fn assign_extra(&mut self, extra: Self::Extra, _: impl Fn() -> Result<Coeff<F>>) -> Result<F> {
        Ok(extra)
    }
}

impl<'dr, F: Field> Driver<'dr> for Counter<F> {
    type F = F;
    type Wire = F;
    const ONE: Self::Wire = F::ONE;

    /// Computes a linear combination of wire evaluations.
    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        lc(DirectSum::default()).value()
    }

    /// Increments constraint count and applies one Horner step:
    /// `result = result * y + coefficient`.
    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        self.num_constraints += 1;
        self.segments[self.scope.current_segment].num_constraints += 1;
        self.scope.result = self
            .scope
            .result
            .mul_add(&self.y, &lc(DirectSum::default()).value());
        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        // Push a new segment with placeholder identity (overwritten at exit).
        self.segments.push(SegmentRecord {
            num_gates: 0,
            num_constraints: 0,
            identity: RoutineIdentity::Root,
        });
        let segment_idx = self.segments.len() - 1;

        // Save parent scope and reset to fresh identity state.
        let saved = core::mem::replace(
            &mut self.scope,
            CounterScope {
                current_segment: segment_idx,
                current_a: self.x0,
                current_b: self.x1,
                current_c: self.x2,
                current_d: self.x3,
                remap: ReinitWires::new(self.x_remap),
                result: F::ZERO,
                child_deep_hashes: Vec::new(),
            },
        );

        // Remap input wires to fresh tokens disjoint from the routine's
        // geometric sequences so the fingerprint captures only internal
        // structure, not caller context. Uses the child scope's fresh
        // `ReinitWires`, so wires observe the same positional prefix every
        // invocation.
        let new_input = Ro::Input::map_gadget(&input, &mut self.scope.remap)?;

        // Predict and execute the routine on this driver.
        let aux = Emulator::predict(&routine, &new_input)?.into_aux();
        let output = routine.execute(self, new_input, aux)?;

        // Collect the raw output-wire values BEFORE parent-context remap
        // so the deep hash binds their positions relative to the child's
        // scope, not the parent's.
        let output_wires = extract_wires(&output, |w: &F| *w)?;

        // Build the fingerprint from the child's Horner accumulator,
        // segment counts, collected output wires, and accumulated child
        // deep hashes.
        let seg = &self.segments[segment_idx];
        let base = BaseFingerprint::new(self.scope.result, seg.num_gates, seg.num_constraints);
        let fingerprint =
            DeepFingerprint::new::<F, Ro>(base, &output_wires, &self.scope.child_deep_hashes);
        self.segments[segment_idx].identity = RoutineIdentity::Routine(fingerprint);

        // Restore parent scope, then record this child's deep hash so the
        // parent's own deep fingerprint (computed when the parent itself
        // returns) binds it.
        self.scope = saved;
        self.scope.child_deep_hashes.push(fingerprint.deep);

        // Remap child output wires as fresh tokens in the parent context.
        // The child's geometric sequences share bases with the parent
        // (both start at x0..x3), so child-allocated values overlap
        // systematically with parent-allocated values; the remap
        // re-tokenizes them onto the parent's `ReinitWires` sequence.
        let parent_output = Ro::Output::map_gadget(&output, &mut self.scope.remap)?;

        Ok(parent_output)
    }
}

/// Evaluates the constraint topology of a circuit.
///
/// # Errors
///
/// Propagates any error from the raw orchestration pass used to analyze the
/// circuit.
pub fn eval<F: Field, C: Circuit<F>>(circuit: &C) -> Result<CircuitMetrics> {
    eval_raw(&super::raw::CircuitAdapterRef(circuit))
}

/// Evaluates the constraint topology of a [`RawCircuit`].
pub(crate) fn eval_raw<F: Field, RC: RawCircuit<F>>(circuit: &RC) -> Result<CircuitMetrics> {
    let mut collector = Counter::<F>::new();

    let result = super::raw::orchestrate(&mut collector, circuit, Empty)?;

    let recorded_gates: usize = collector.segments.iter().map(|r| r.num_gates).sum();
    let recorded_constraints: usize = collector.segments.iter().map(|r| r.num_constraints).sum();
    assert_eq!(recorded_gates, collector.num_gates);
    assert_eq!(recorded_constraints, collector.num_constraints);

    assert!(
        matches!(collector.segments[0].identity, RoutineIdentity::Root),
        "first segment must be Root"
    );
    assert_eq!(
        collector
            .segments
            .iter()
            .filter(|s| matches!(s.identity, RoutineIdentity::Root))
            .count(),
        1,
        "exactly one segment must be Root"
    );

    Ok(CircuitMetrics {
        num_constraints: collector.num_constraints,
        num_gates: collector.num_gates,
        degree_ky: result.degree_ky,
        segments: collector.segments,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use core::marker::PhantomData;

    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::Bound,
        pasta::Fp,
        routines::{Prediction, Routine},
    };
    use ragu_primitives::allocator::Allocator;

    use super::*;
    use crate::WithAux;

    /// [`WireMap`] adapter that maps wires from an arbitrary source driver into
    /// [`Counter`] via fresh allocations. Used by [`fingerprint_routine`] where
    /// the source driver is generic.
    struct CounterRemap<'a, F, Src: DriverTypes> {
        counter: &'a mut Counter<F>,
        _marker: PhantomData<Src>,
    }

    impl<F: Field, Src: DriverTypes<ImplField = F>> WireMap<F> for CounterRemap<'_, F, Src> {
        type Src = Src;
        type Dst = Counter<F>;

        fn convert_wire(&mut self, _: &Src::ImplWire) -> Result<F> {
            Ok(self.counter.scope.remap.mint())
        }
    }

    /// Computes the [`RoutineIdentity`] for a single routine invocation.
    ///
    /// Creates a fresh [`Counter`], maps the caller's `input` gadget into the
    /// counter (allocating fresh wires for each input wire), then predicts and
    /// executes the routine. Nested routine calls within the routine are
    /// fingerprinted independently; their output wires are treated as auxiliary
    /// inputs to the caller rather than folded into the caller's fingerprint.
    ///
    /// # Arguments
    ///
    /// - `routine`: The routine to fingerprint.
    /// - `input`: The caller's input gadget, bound to driver `D`.
    pub(crate) fn fingerprint_routine<'dr, F, D, Ro>(
        routine: &Ro,
        input: &Bound<'dr, D, Ro::Input>,
    ) -> Result<RoutineIdentity>
    where
        F: Field,
        D: Driver<'dr, F = F>,
        Ro: Routine<F>,
    {
        let mut counter = Counter::<F>::new();

        // Remap input wires into Counter via the dedicated `x_remap`
        // sequence, mirroring Counter::routine. No gates allocated, no
        // counts incremented.
        let new_input = {
            let mut remap = CounterRemap {
                counter: &mut counter,
                _marker: PhantomData::<D>,
            };
            Ro::Input::map_gadget(input, &mut remap)?
        };

        // Predict (on a wireless emulator) then execute on the counter.
        let aux = Emulator::predict(routine, &new_input)?.into_aux();
        let output = routine.execute(&mut counter, new_input, aux)?;

        // Collect output wire values before any parent-context remap
        // (there is no parent here, but the ordering mirrors Counter::routine).
        let output_wires = extract_wires(&output, |w: &F| *w)?;

        // Segment 0 holds only this routine's own constraints; nested
        // routine constraints live in their own segments.
        let seg = &counter.segments[0];
        let base = BaseFingerprint::new(counter.scope.result, seg.num_gates, seg.num_constraints);
        Ok(RoutineIdentity::Routine(DeepFingerprint::new::<F, Ro>(
            base,
            &output_wires,
            &counter.scope.child_deep_hashes,
        )))
    }

    // A routine that performs a single allocation via `().alloc`. Verifies
    // that metrics evaluation succeeds when a routine makes an odd number
    // of allocator calls.
    #[derive(Clone)]
    struct SingleAllocRoutine;

    impl Routine<Fp> for SingleAllocRoutine {
        type Input = ();
        type Output = ();
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            _input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            ().alloc(dr, || Ok(Coeff::One))?;
            Ok(())
        }

        fn predict<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _dr: &mut D,
            _input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            Ok(Prediction::Unknown(D::unit()))
        }
    }

    struct SingleAllocCircuit;

    impl Circuit<Fp> for SingleAllocCircuit {
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _dr: &mut D,
            _instance: DriverValue<D, Self::Instance<'source>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Ok(())
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            _witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
        {
            dr.routine(SingleAllocRoutine, ())?;
            Ok(WithAux::new((), D::unit()))
        }
    }

    #[test]
    fn single_alloc_in_routine() {
        super::eval::<Fp, _>(&SingleAllocCircuit).expect("metrics eval should succeed");
    }
}
