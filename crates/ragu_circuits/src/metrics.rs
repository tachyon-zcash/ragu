//! Circuit constraint analysis, metrics collection, and routine identity
//! fingerprinting.
//!
//! This module provides constraint system analysis by simulating circuit
//! execution without computing actual values, counting the number of
//! multiplication and linear constraints a circuit requires. It simultaneously
//! computes Schwartz–Zippel fingerprints for each routine invocation via the
//! merged [`Counter`] driver, which combines constraint counting with identity
//! evaluation in a single DFS traversal.
//!
//! # Fingerprinting
//!
//! A routine's fingerprint is the tuple `(TypeId(Input), TypeId(Output),
//! eval)`. The [`TypeId`] pairs cheaply narrow equivalence candidates by type;
//! the scalar confirms structural equivalence via random evaluation
//! (Schwartz–Zippel).
//!
//! The fingerprint is wrapped in [`RoutineIdentity`], an enum that
//! distinguishes the root circuit body ([`Root`](RoutineIdentity::Root)) from
//! actual routine invocations ([`Routine`](RoutineIdentity::Routine)).
//! `RoutineIdentity` deliberately does **not** implement comparison or hashing
//! traits, forcing callers to explicitly handle the root variant rather than
//! accidentally including it in equivalence maps.
//!
//! The fingerprint is computed by assigning three independent geometric
//! sequences to the $a$, $b$, $c$ wires and accumulating constraint values via
//! Horner's rule. If two routines produce the same fingerprint, they are
//! structurally equivalent with overwhelming probability.
//!
//! [`TypeId`]: core::any::TypeId

use ff::{Field, PrimeField};
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes, FromDriver, emulator::Emulator},
    gadgets::{Bound, GadgetKind},
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
/// Two routines share a fingerprint when they have matching [`TypeId`] pairs
/// and matching evaluation scalars. The scalar is the low 64 bits of the field
/// element produced by running the routine's synthesis on the `Counter`
/// driver.
///
/// [`TypeId`]: core::any::TypeId
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoutineFingerprint {
    input_kind: TypeId,
    output_kind: TypeId,
    fingerprint: u64,
}

impl RoutineFingerprint {
    /// Constructs a [`RoutineFingerprint`] from a routine's `Input`/`Output`
    /// type ids and a field element evaluation.
    fn of<F: PrimeField, Ro: Routine<F>>(eval: F) -> Self {
        Self {
            input_kind: TypeId::of::<Ro::Input>(),
            output_kind: TypeId::of::<Ro::Output>(),
            fingerprint: ragu_arithmetic::low_u64(eval),
        }
    }

    /// Returns the raw scalar component of the fingerprint.
    #[cfg(test)]
    pub(crate) fn scalar(&self) -> u64 {
        self.fingerprint
    }
}

/// Constraint counts for one segment of the circuit, collected during synthesis.
///
/// Each record captures the multiplication and linear constraints contributed
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
    /// The number of multiplication constraints in this segment.
    pub num_multiplication_constraints: usize,

    /// The number of linear constraints in this segment, including constraints
    /// on wires of the input gadget and on wires allocated within the segment.
    pub num_linear_constraints: usize,

    /// The structural identity of this routine invocation.
    // TODO: consumed by the floor planner (not yet implemented)
    #[allow(dead_code)]
    pub identity: RoutineIdentity,
}

/// A summary of a circuit's constraint topology.
///
/// Captures constraint counts and per-routine records by simulating circuit
/// execution without computing actual values.
pub struct CircuitMetrics {
    /// The number of linear constraints, including those for instance enforcement.
    pub num_linear_constraints: usize,

    /// The number of multiplication constraints, including those used for allocations.
    pub num_multiplication_constraints: usize,

    /// The degree of the instance polynomial $k(Y)$.
    // TODO(ebfull): not sure if we'll need this later
    #[allow(dead_code)]
    pub degree_ky: usize,

    /// Per-segment constraint records in DFS synthesis order.
    ///
    /// See [`SegmentRecord`] for the indexing convention: index 0 is the
    /// root segment (not backed by a [`Routine`]); indices 1+ each correspond
    /// to a [`Routine`] invocation.
    pub segments: Vec<SegmentRecord>,
}

/// Per-routine state that is saved and restored across routine boundaries.
///
/// Contains both the constraint counting record index and the identity
/// evaluation state (geometric sequence runners and Horner accumulator).
struct CounterScope<F> {
    /// Stashed $b$ wire from paired allocation (see [`Driver::alloc`]).
    available_b: Option<WireEval<F>>,

    /// Index into [`Counter::segments`] for the current routine.
    current_segment: usize,

    /// Running monomial for $a$ wires: $x_0^{i+1}$ at gate $i$.
    current_a: F,

    /// Running monomial for $b$ wires: $x_1^{i+1}$ at gate $i$.
    current_b: F,

    /// Running monomial for $c$ wires: $x_2^{i+1}$ at gate $i$.
    current_c: F,

    /// Horner accumulator for the fingerprint evaluation result.
    result: F,
}

/// A [`Driver`] that simultaneously counts constraints and computes routine
/// identity fingerprints via Schwartz–Zippel evaluation.
///
/// Assigns three independent geometric sequences (bases $x_0, x_1, x_2$) to
/// the $a$, $b$, $c$ wires and accumulates constraint values via Horner's rule
/// over $y$. When entering a routine, the identity state is saved and reset so
/// that each routine is fingerprinted independently of its calling context.
///
/// Nested routine outputs are treated as auxiliary inputs to the caller: on
/// return, output wires are remapped to fresh allocations in the parent scope
/// rather than folding the child's fingerprint scalar. This makes each
/// routine's fingerprint capture only its *internal* constraint structure.
struct Counter<F> {
    scope: CounterScope<F>,
    num_linear_constraints: usize,
    num_multiplication_constraints: usize,
    segments: Vec<SegmentRecord>,

    /// When false, `mul` and `enforce_zero` advance geometric sequences and
    /// accumulate Horner results but do not increment constraint counts. Used
    /// during input and output wire remapping in [`routine`](Driver::routine).
    counting: bool,

    /// Base for the $a$-wire geometric sequence.
    x0: F,

    /// Base for the $b$-wire geometric sequence.
    x1: F,

    /// Base for the $c$-wire geometric sequence.
    x2: F,

    /// Multiplier for Horner accumulation, applied per [`enforce_zero`] call.
    ///
    /// [`enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
    y: F,

    /// Evaluation of the `ONE` wire ($c$ wire from gate 0).
    ///
    /// Passed to [`WireEvalSum::new`] so that [`WireEval::One`] variants can be
    /// resolved during linear combination accumulation.
    one: F,
}

impl<F: PrimeField> Counter<F> {
    /// Creates a new counter with fixed NUMS constants.
    fn new() -> Self {
        let x0 = F::from(2);
        let x1 = F::from(3);
        let x2 = F::from(5);
        let y = F::from(7);

        Self {
            scope: CounterScope {
                available_b: None,
                current_segment: 0,
                current_a: x0,
                current_b: x1,
                current_c: x2,
                result: F::ZERO,
            },
            num_linear_constraints: 0,
            num_multiplication_constraints: 0,
            segments: alloc::vec![SegmentRecord {
                num_multiplication_constraints: 0,
                num_linear_constraints: 0,
                identity: RoutineIdentity::Root,
            }],
            counting: true,
            x0,
            x1,
            x2,
            y,
            one: x2, // c wire of gate 0
        }
    }
}

impl<F: Field> DriverTypes for Counter<F> {
    type MaybeKind = Empty;
    type ImplField = F;
    type ImplWire = WireEval<F>;
    type LCadd = WireEvalSum<F>;
    type LCenforce = WireEvalSum<F>;
}

impl<'dr, F: PrimeField> Driver<'dr> for Counter<F> {
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

    /// Consumes a multiplication gate: increments constraint counts and returns
    /// wire values from three independent geometric sequences, advancing each
    /// by its base.
    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        if self.counting {
            self.num_multiplication_constraints += 1;
            self.segments[self.scope.current_segment].num_multiplication_constraints += 1;
        }

        let a = self.scope.current_a;
        let b = self.scope.current_b;
        let c = self.scope.current_c;

        self.scope.current_a *= self.x0;
        self.scope.current_b *= self.x1;
        self.scope.current_c *= self.x2;

        Ok((WireEval::Value(a), WireEval::Value(b), WireEval::Value(c)))
    }

    /// Computes a linear combination of wire evaluations.
    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        WireEval::Value(lc(WireEvalSum::new(self.one)).value)
    }

    /// Increments linear constraint count and applies one Horner step:
    /// `result = result * y + coefficient`.
    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        if self.counting {
            self.num_linear_constraints += 1;
            self.segments[self.scope.current_segment].num_linear_constraints += 1;
        }

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
            num_multiplication_constraints: 0,
            num_linear_constraints: 0,
            identity: RoutineIdentity::Root,
        });
        let segment_idx = self.segments.len() - 1;

        // Save parent scope and reset to fresh identity state.
        let saved = core::mem::replace(
            &mut self.scope,
            CounterScope {
                available_b: None,
                current_segment: segment_idx,
                current_a: self.x0,
                current_b: self.x1,
                current_c: self.x2,
                result: F::ZERO,
            },
        );

        // Map input wires from parent's binding to fresh wires in the reset
        // scope. Counting is disabled because these gates exist solely to seed
        // the geometric sequences for fingerprinting.
        self.counting = false;
        let new_input = Ro::Input::map_gadget(&input, self)?;
        self.counting = true;
        // Clear residual pairing state from input remapping so that
        // execute starts with available_b = None, matching sxy/rx.
        self.scope.available_b = None;

        // Predict and execute.
        let mut dummy = Emulator::wireless();
        let dummy_input = Ro::Input::map_gadget(&new_input, &mut dummy)?;
        let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
        let output = routine.execute(self, new_input, aux)?;

        // Extract fingerprint from the child's Horner accumulator.
        self.segments[segment_idx].identity =
            RoutineIdentity::Routine(RoutineFingerprint::of::<F, Ro>(self.scope.result));

        // Restore parent scope.
        self.scope = saved;

        // Remap child output wires as fresh parent allocations.
        // Save and restore pairing state and geometric sequences so
        // that the uncounted gates don't drift from the sxy evaluator.
        let saved_b = self.scope.available_b.take();
        let saved_a = self.scope.current_a;
        let saved_b_geo = self.scope.current_b;
        let saved_c = self.scope.current_c;

        self.counting = false;
        let parent_output = Ro::Output::map_gadget(&output, self)?;
        self.counting = true;

        self.scope.available_b = saved_b;
        self.scope.current_a = saved_a;
        self.scope.current_b = saved_b_geo;
        self.scope.current_c = saved_c;

        Ok(parent_output)
    }
}

/// Allows [`Counter`] to receive input wires from any driver with the same
/// field type. Each source wire is mapped to a fresh allocation on the counter,
/// producing linearly independent wire values for the input gadget.
impl<'dr, F: PrimeField, D: Driver<'dr, F = F>> FromDriver<'dr, '_, D> for Counter<F> {
    type NewDriver = Self;

    fn convert_wire(&mut self, _: &D::Wire) -> Result<WireEval<F>> {
        self.alloc(|| unreachable!())
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
#[cfg(test)]
pub(crate) fn fingerprint_routine<'dr, F, D, Ro>(
    routine: &Ro,
    input: &Bound<'dr, D, Ro::Input>,
) -> Result<RoutineIdentity>
where
    F: PrimeField,
    D: Driver<'dr, F = F>,
    Ro: Routine<F>,
{
    let mut counter = Counter::<F>::new();

    // Map input from the caller's driver to Counter wires.
    let new_input = Ro::Input::map_gadget(input, &mut counter)?;

    // Predict (on a wireless emulator) then execute on the counter.
    let mut dummy = Emulator::wireless();
    let dummy_input = Ro::Input::map_gadget(&new_input, &mut dummy)?;
    let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
    routine.execute(&mut counter, new_input, aux)?;

    Ok(RoutineIdentity::Routine(RoutineFingerprint::of::<F, Ro>(
        counter.scope.result,
    )))
}

/// Evaluates the constraint topology of a circuit.
pub fn eval<F: PrimeField, C: Circuit<F>>(circuit: &C) -> Result<CircuitMetrics> {
    let mut collector = Counter::<F>::new();
    let mut degree_ky = 0usize;

    // ONE gate
    collector.mul(|| Ok((Coeff::One, Coeff::One, Coeff::One)))?;

    // Registry key constraint
    collector.enforce_zero(|lc| lc)?;

    // Circuit synthesis
    let (io, _) = circuit.witness(&mut collector, Empty)?;
    io.write(&mut collector, &mut degree_ky)?;

    // Public output constraints
    for _ in 0..degree_ky {
        collector.enforce_zero(|lc| lc)?;
    }

    // ONE constraint
    collector.enforce_zero(|lc| lc)?;

    let recorded_multiplications: usize = collector
        .segments
        .iter()
        .map(|r| r.num_multiplication_constraints)
        .sum();
    let recorded_linear_constraints: usize = collector
        .segments
        .iter()
        .map(|r| r.num_linear_constraints)
        .sum();
    assert_eq!(
        recorded_multiplications,
        collector.num_multiplication_constraints
    );
    assert_eq!(
        recorded_linear_constraints,
        collector.num_linear_constraints
    );

    Ok(CircuitMetrics {
        num_linear_constraints: collector.num_linear_constraints,
        num_multiplication_constraints: collector.num_multiplication_constraints,
        degree_ky,
        segments: collector.segments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::Bound,
        routines::{Prediction, Routine},
    };
    use ragu_pasta::Fp;

    // A routine that allocates exactly one wire, leaving the "b" slot dangling
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
            Ok(Prediction::Unknown(D::just(|| ())))
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
        ) -> Result<(
            Bound<'dr, D, Self::Output>,
            DriverValue<D, Self::Aux<'source>>,
        )> {
            dr.routine(DanglingAllocRoutine, ())?;
            Ok(((), D::just(|| ())))
        }
    }

    #[test]
    fn dangling_alloc_in_routine() {
        super::eval::<Fp, _>(&DanglingAllocCircuit).expect("metrics eval should succeed");
    }
}
