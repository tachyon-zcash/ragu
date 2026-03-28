//! Circuit constraint analysis, metrics collection, and routine identity
//! fingerprinting.
//!
//! This module provides constraint system analysis by simulating circuit
//! execution without computing actual values, counting the number of
//! gates and constraints a circuit requires. It simultaneously
//! computes Schwartz–Zippel fingerprints for each routine invocation via the
//! merged [`Counter`] driver, which combines constraint counting with identity
//! evaluation in a single DFS traversal.
//!
//! # Fingerprinting
//!
//! A routine's fingerprint is the tuple `(TypeId(Input), TypeId(Output),
//! eval, num_mul, num_lc)`. The [`TypeId`] pairs cheaply narrow equivalence
//! candidates by type; the constraint counts further partition by shape; the
//! scalar confirms structural equivalence via random evaluation
//! (Schwartz–Zippel).
//!
//! The fingerprint is wrapped in [`RoutineIdentity`], an enum that
//! distinguishes the root circuit body ([`Root`](RoutineIdentity::Root)) from
//! actual routine invocations ([`Routine`](RoutineIdentity::Routine)).
//! `RoutineIdentity` deliberately does **not** implement comparison or hashing
//! traits, forcing callers to explicitly handle the root variant rather than
//! accidentally including it in equivalence maps.
//!
//! The scalar is the routine's $s(X,Y)$ contribution (see
//! [`sxy::eval`](super::s::sxy::eval)) evaluated at deterministic
//! pseudorandom points derived from a domain-separated BLAKE2b hash: three
//! independent geometric sequences are assigned to the $a$, $b$, $c$ wires and
//! constraint values are accumulated via Horner's rule. If two routines produce
//! the same fingerprint, they are structurally equivalent with overwhelming
//! probability.
//!
//! [`TypeId`]: core::any::TypeId

use ff::{FromUniformBytes, PrimeField};
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    convert::WireMap,
    drivers::{Driver, DriverTypes, emulator::Emulator},
    gadgets::{Bound, GadgetKind as _},
    maybe::Empty,
    routines::Routine,
};
use ragu_primitives::GadgetExt;

use alloc::vec::Vec;
use core::any::TypeId;

use super::Circuit;
use super::s::common::{WireEval, WireEvalSum};

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
    /// The root circuit body (record 0). Cannot be floated or memoized.
    Root,
    /// An actual routine invocation with a Schwartz–Zippel fingerprint.
    Routine(RoutineFingerprint),
}

/// A Schwartz–Zippel fingerprint for a routine invocation's constraint
/// structure.
///
/// Two routines share a fingerprint when they have matching [`TypeId`] pairs,
/// matching evaluation scalars, and matching constraint counts. The scalar is
/// the low 64 bits of the field element produced by running the routine's
/// synthesis on the `Counter` driver.
///
/// The 64-bit truncation gives ~2^{-64} collision probability per pair,
/// adequate for floor-planner equivalence classes. If fingerprints are
/// ever used for security-critical decisions, store the full field
/// representation (`[u8; 32]`) instead — the cost is negligible.
///
/// The constraint counts duplicate the values in the enclosing
/// [`SegmentRecord`]. This is intentional: it makes the fingerprint a
/// self-contained `Hash + Eq` key so callers can use it directly in
/// equivalence maps without also comparing the segment record.
///
/// [`TypeId`]: core::any::TypeId
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RoutineFingerprint {
    input_kind: TypeId,
    output_kind: TypeId,
    eval: u64,
    local_num_gates: usize,
    local_num_constraints: usize,
}

impl RoutineFingerprint {
    /// Constructs a [`RoutineFingerprint`] from a routine's `Input`/`Output`
    /// type ids, a field element evaluation, and local constraint counts.
    fn of<F: PrimeField, Ro: Routine<F>>(
        eval: F,
        local_num_gates: usize,
        local_num_constraints: usize,
    ) -> Self {
        Self {
            input_kind: TypeId::of::<Ro::Input>(),
            output_kind: TypeId::of::<Ro::Output>(),
            eval: ragu_arithmetic::low_u64(&eval),
            local_num_gates,
            local_num_constraints,
        }
    }

    /// Returns the raw evaluation scalar.
    #[cfg(test)]
    pub(crate) fn eval(&self) -> u64 {
        self.eval
    }
}

/// Constraint counts for one segment of the circuit, collected during synthesis.
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
/// Consider a circuit with this synthesis order:
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
    // TODO: consumed by the floor planner (not yet implemented)
    #[allow(dead_code)]
    pub(crate) fn identity(&self) -> &RoutineIdentity {
        &self.identity
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
    // TODO(ebfull): not sure if we'll need this later
    #[allow(dead_code)]
    pub(crate) degree_ky: usize,

    /// Per-segment constraint records in DFS synthesis order.
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
    /// Stashed $d$ wire from paired allocation (see [`Driver::alloc`]).
    available_d: Option<WireEval<F>>,

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

    /// Horner accumulator for the fingerprint evaluation result.
    result: F,
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
/// routine's fingerprint capture only its *internal* constraint structure.
struct Counter<F> {
    scope: CounterScope<F>,
    num_constraints: usize,
    num_gates: usize,
    segments: Vec<SegmentRecord>,

    /// When false, `gate` advances geometric sequences but does not increment
    /// constraint counts.  Used during input and output wire remapping in
    /// [`routine`](Driver::routine), where only `alloc` (and transitively
    /// `mul`, which calls `gate`) is reachable via [`WireMap::convert_wire`].
    counting: bool,

    /// Base for the $a$-wire geometric sequence.
    x0: F,

    /// Base for the $b$-wire geometric sequence.
    x1: F,

    /// Base for the $c$-wire geometric sequence.
    x2: F,

    /// Base for the $d$-wire geometric sequence.
    x3: F,

    /// Multiplier for Horner accumulation, applied per [`enforce_zero`] call.
    ///
    /// [`enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
    y: F,

    /// Evaluation of the `ONE` wire, derived from an independent BLAKE2b
    /// point so it cannot collide with any geometric-sequence wire value.
    ///
    /// Passed to [`WireEvalSum::new`] so that [`WireEval::One`] variants can be
    /// resolved during linear combination accumulation.
    one: F,

    /// Initial value of the Horner accumulator for each routine scope.
    ///
    /// A nonzero seed derived from the same BLAKE2b PRF ensures that leading
    /// `enforce_zero` calls with zero-valued linear combinations still shift
    /// the accumulator (via `result = h * y + lc_value`), preventing
    /// degenerate collisions. Without this, a routine whose first linear
    /// combination evaluates to zero (`lc_value = 0`) would produce
    /// `0 * y^{n-1} + c_2 * y^{n-2} + …`, colliding with a shorter routine
    /// that starts at `c_2`. The nonzero seed lifts the accumulator to
    /// `h * y^n + c_1 * y^{n-1} + …`, making the leading power of `y`
    /// always visible.
    h: F,
}

impl<F: FromUniformBytes<64>> Counter<F> {
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
        let h = point(5);
        let one = point(6);

        Self {
            scope: CounterScope {
                available_d: None,
                current_segment: 0,
                current_a: x0,
                current_b: x1,
                current_c: x2,
                current_d: x3,
                result: h,
            },
            num_constraints: 0,
            num_gates: 0,
            segments: alloc::vec![SegmentRecord {
                num_gates: 0,
                num_constraints: 0,
                identity: RoutineIdentity::Root,
            }],
            counting: true,
            x0,
            x1,
            x2,
            x3,
            y,
            one,
            h,
        }
    }

    /// Runs `f` with `counting` set to `false`, restoring it afterward.
    ///
    /// Used during wire remapping so that `gate` advances geometric
    /// sequences without incrementing constraint counts, and
    /// `enforce_zero` is a no-op.
    fn uncounted<R>(&mut self, f: impl FnOnce(&mut Self) -> Result<R>) -> Result<R> {
        self.counting = false;
        let result = f(self);
        self.counting = true;
        result
    }
}

impl<F: FromUniformBytes<64>> DriverTypes for Counter<F> {
    type MaybeKind = Empty;
    type ImplField = F;
    type ImplWire = WireEval<F>;
    type LCadd = WireEvalSum<F>;
    type LCenforce = WireEvalSum<F>;

    /// Consumes a gate: increments gate counts and returns
    /// wire values from four independent geometric sequences, advancing each
    /// by its base.
    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(WireEval<F>, WireEval<F>, WireEval<F>, WireEval<F>)> {
        if self.counting {
            self.num_gates += 1;
            self.segments[self.scope.current_segment].num_gates += 1;
        }

        let a = self.scope.current_a;
        let b = self.scope.current_b;
        let c = self.scope.current_c;
        let d = self.scope.current_d;

        self.scope.current_a *= self.x0;
        self.scope.current_b *= self.x1;
        self.scope.current_c *= self.x2;
        self.scope.current_d *= self.x3;

        Ok((
            WireEval::Value(a),
            WireEval::Value(b),
            WireEval::Value(c),
            WireEval::Value(d),
        ))
    }
}

impl<'dr, F: FromUniformBytes<64>> Driver<'dr> for Counter<F> {
    type F = F;
    type Wire = WireEval<F>;
    const ONE: Self::Wire = WireEval::One;

    /// Allocates a wire using paired allocation with layout $(0, b, 0, d)$.
    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(wire) = self.scope.available_d.take() {
            Ok(wire)
        } else {
            let (_, b, _, d) = self.gate(|| unreachable!())?;
            self.scope.available_d = Some(d);
            Ok(b)
        }
    }

    /// Computes a linear combination of wire evaluations.
    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        WireEval::Value(lc(WireEvalSum::new(self.one)).value)
    }

    /// Increments constraint count and applies one Horner step:
    /// `result = result * y + coefficient`.
    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        self.num_constraints += 1;
        self.segments[self.scope.current_segment].num_constraints += 1;
        self.scope.result *= self.y;
        self.scope.result += lc(WireEvalSum::new(self.one)).value;
        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        // Push new segment with placeholder identity.
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
                available_d: None,
                current_segment: segment_idx,
                current_a: self.x0,
                current_b: self.x1,
                current_c: self.x2,
                current_d: self.x3,
                result: self.h,
            },
        );

        // Remap input wires to fixed positions in the fresh scope so the
        // fingerprint captures only internal structure, not caller context.
        // Uncounted: these gates only seed the geometric sequences.
        let new_input = self.uncounted(|c| Ro::Input::map_gadget(&input, c))?;
        self.scope.available_d = None; // match sxy/trace initial state

        // Predict and execute.
        let aux = Emulator::predict(&routine, &new_input)?.into_aux();
        let output = routine.execute(self, new_input, aux)?;

        // Extract fingerprint from the child's Horner accumulator and counts.
        let seg = &self.segments[segment_idx];
        self.segments[segment_idx].identity =
            RoutineIdentity::Routine(RoutineFingerprint::of::<F, Ro>(
                self.scope.result,
                seg.num_gates,
                seg.num_constraints,
            ));

        // Restore parent scope.
        self.scope = saved;

        // Remap child output wires as fresh parent allocations.
        //
        // The child's a/b/c sequences were reset to (x0, x1, x2) on entry,
        // so its output wires carry child-local evaluations. After restoring
        // the parent scope those values are no longer globally distinct —
        // they could collide with the parent's own wires. Re-allocating via
        // `map_gadget` assigns each output wire a fresh position in the
        // parent's geometric sequences.
        //
        // The remap calls `alloc` for each output wire, which may call
        // `gate` internally. This has two side effects on the parent scope:
        //
        // 1. Geometric sequences advance — `current_a`, `current_b`,
        //    `current_c` move past the remap gates.
        // 2. `available_d` changes — the remap may consume a pending
        //    d-wire or create a new one.
        //
        // Effect (1) is kept; effect (2) is rolled back. The asymmetry is
        // deliberate:
        //
        // Sequences must advance because the remapped output wires need
        // evaluations that are distinct from each other and from any
        // subsequent parent allocation. Letting the sequences advance past
        // the remap positions achieves this — each output wire lands at a
        // unique geometric position in the parent's sequence space.
        //
        // `available_d` must be restored because in the real drivers
        // (sxy, sx, sy), output wires are received directly from the
        // child's evaluation — no parent gates are consumed and the
        // parent's pairing state is untouched. The output remap is a
        // Counter-only operation that exists solely to assign parent-scope
        // evaluations to child output wires. If the remap were allowed to
        // mutate `available_d`, the parent's subsequent allocation pattern
        // would diverge from the real drivers: a pending d-wire could be
        // consumed or created by the remap, changing which wire types
        // subsequent `alloc` calls return. Restoring `available_d` keeps
        // the parent's pairing trajectory identical to the real drivers.
        //
        // After a routine call where the parent had a pending d-wire, the
        // stashed wire retains its pre-call geometric value while the
        // sequences have jumped forward past the remap positions. This
        // creates a non-contiguous gap in the parent's sequence coverage.
        // The gap is harmless — the stashed wire already has a distinct
        // value, and Schwartz–Zippel only requires that all wire
        // evaluations be distinct, not contiguous.
        let saved_d = self.scope.available_d.take();

        let parent_output = self.uncounted(|c| Ro::Output::map_gadget(&output, c))?;

        self.scope.available_d = saved_d;

        Ok(parent_output)
    }
}

/// [`WireMap`] for `Counter`→`Counter`: each source wire is replaced by a
/// fresh allocation, producing linearly independent wire values.
impl<F: FromUniformBytes<64>> WireMap<F> for Counter<F> {
    type Src = Self;
    type Dst = Self;

    fn convert_wire(&mut self, _: &WireEval<F>) -> Result<WireEval<F>> {
        self.alloc(|| unreachable!())
    }
}

/// Evaluates the constraint topology of a circuit.
pub fn eval<F: FromUniformBytes<64>, C: Circuit<F>>(circuit: &C) -> Result<CircuitMetrics> {
    let mut collector = Counter::<F>::new();
    let mut degree_ky = 0usize;

    // ONE gate
    collector.mul(|| Ok((Coeff::One, Coeff::One, Coeff::One)))?;

    // Circuit synthesis
    let io = circuit.witness(&mut collector, Empty)?.into_output();
    io.write(&mut collector, &mut degree_ky)?;

    // Public output constraints
    for _ in 0..degree_ky {
        collector.enforce_zero(|lc| lc)?;
    }

    // ONE constraint
    collector.enforce_zero(|lc| lc)?;

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
        degree_ky,
        segments: collector.segments,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::WithAux;
    use core::marker::PhantomData;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::Bound,
        routines::{Prediction, Routine},
    };
    use ragu_pasta::Fp;

    /// [`WireMap`] adapter that maps wires from an arbitrary source driver into
    /// [`Counter`] via fresh allocations. Used by [`fingerprint_routine`] where
    /// the source driver is generic.
    struct CounterRemap<'a, F, Src: DriverTypes> {
        counter: &'a mut Counter<F>,
        _marker: PhantomData<Src>,
    }

    impl<F: FromUniformBytes<64>, Src: DriverTypes<ImplField = F>> WireMap<F>
        for CounterRemap<'_, F, Src>
    {
        type Src = Src;
        type Dst = Counter<F>;

        fn convert_wire(&mut self, _: &Src::ImplWire) -> Result<WireEval<F>> {
            self.counter.alloc(|| unreachable!())
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
        F: FromUniformBytes<64>,
        D: Driver<'dr, F = F>,
        Ro: Routine<F>,
    {
        let mut counter = Counter::<F>::new();

        // Remap input wires into Counter, mirroring Counter::routine:
        // uncounted (seeding only) and available_d cleared afterward.
        let new_input = counter.uncounted(|c| {
            let mut remap = CounterRemap {
                counter: c,
                _marker: PhantomData::<D>,
            };
            Ro::Input::map_gadget(input, &mut remap)
        })?;
        counter.scope.available_d = None;

        // Predict (on a wireless emulator) then execute on the counter.
        let aux = Emulator::predict(routine, &new_input)?.into_aux();
        routine.execute(&mut counter, new_input, aux)?;

        // Segment 0 holds only this routine's own constraints; nested
        // routine constraints live in their own segments.
        let seg = &counter.segments[0];
        Ok(RoutineIdentity::Routine(RoutineFingerprint::of::<F, Ro>(
            counter.scope.result,
            seg.num_gates,
            seg.num_constraints,
        )))
    }

    // A routine that allocates exactly one wire, leaving the "d" slot dangling
    // in a pair-allocated driver like `Counter`.
    // This must not panic when processed.
    #[derive(Clone)]
    struct DanglingAllocRoutine;

    impl Routine<Fp> for DanglingAllocRoutine {
        type Input = ();
        type Output = ();
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            _input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            dr.alloc(|| Ok(Coeff::One))?;
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

    struct DanglingAllocCircuit;

    impl Circuit<Fp> for DanglingAllocCircuit {
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
            dr.routine(DanglingAllocRoutine, ())?;
            Ok(WithAux::new((), D::unit()))
        }
    }

    #[test]
    fn dangling_alloc_in_routine() {
        super::eval::<Fp, _>(&DanglingAllocCircuit).expect("metrics eval should succeed");
    }
}
