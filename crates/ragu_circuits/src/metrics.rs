//! Circuit constraint analysis, metrics collection, and routine identity
//! fingerprinting.
//!
//! This module provides constraint system analysis by simulating circuit
//! execution without computing actual values, counting the number of
//! multiplication and linear constraints a circuit requires. It simultaneously
//! computes hash-based fingerprints for each routine invocation via the merged
//! [`Counter`] driver, which combines constraint counting with identity
//! hashing in a single DFS traversal.
//!
//! # Fingerprinting
//!
//! A routine's fingerprint is the tuple `(TypeId(Input), TypeId(Output),
//! hash)`. The [`TypeId`] pairs cheaply narrow equivalence candidates by type;
//! the hash confirms structural equivalence by hashing the operation sequence
//! (wire IDs, coefficient tags, constraint boundaries).
//!
//! The fingerprint is wrapped in [`RoutineIdentity`], an enum that
//! distinguishes the root circuit body ([`Root`](RoutineIdentity::Root)) from
//! actual routine invocations ([`Routine`](RoutineIdentity::Routine)).
//! `RoutineIdentity` deliberately does **not** implement comparison or hashing
//! traits, forcing callers to explicitly handle the root variant rather than
//! accidentally including it in equivalence maps.
//!
//! [`TypeId`]: core::any::TypeId

use blake2b_simd::State as Blake2bState;
use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes, FromDriver, LinearExpression, emulator::Emulator},
    gadgets::{Bound, GadgetKind},
    maybe::Empty,
    routines::Routine,
};
use ragu_primitives::GadgetExt;

use alloc::vec::Vec;
use core::{any::TypeId, marker::PhantomData};

use super::Circuit;

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
    /// An actual routine invocation with a structural fingerprint.
    Routine(RoutineFingerprint),
}

/// A hash-based fingerprint for a routine invocation's constraint structure.
///
/// Two routines share a fingerprint when they have matching [`TypeId`] pairs
/// and matching hash digests. The digest is a `u64` produced by hashing the
/// sequence of wire IDs, coefficient tags, and constraint boundaries observed
/// during synthesis.
///
/// [`TypeId`]: core::any::TypeId
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoutineFingerprint {
    input_kind: TypeId,
    output_kind: TypeId,
    fingerprint: u64,
}

impl RoutineFingerprint {
    fn of<F: Field, Ro: Routine<F>>(hash: u64) -> Self {
        Self {
            input_kind: TypeId::of::<Ro::Input>(),
            output_kind: TypeId::of::<Ro::Output>(),
            fingerprint: hash,
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

fn coeff_tag<F: Field>(coeff: &Coeff<F>) -> u8 {
    match coeff {
        Coeff::Zero => 0,
        Coeff::One => 1,
        Coeff::Two => 2,
        Coeff::NegativeOne => 3,
        Coeff::Arbitrary(_) => 4,
        Coeff::NegativeArbitrary(_) => 5,
    }
}

/// Returns the low 64 bits of a BLAKE2b finalization.
fn finalize_u64(state: &Blake2bState) -> u64 {
    let hash = state.finalize();
    let bytes: [u8; 8] = hash.as_bytes()[..8].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

/// Creates a new BLAKE2b state with the fingerprinting personalization.
fn new_hash() -> Blake2bState {
    blake2b_simd::Params::new()
        .personal(b"ragu_fingerprint")
        .to_state()
}

/// A byte-buffer accumulator for linear combinations during fingerprinting.
///
/// Implements [`LinearExpression`] by recording wire IDs and coefficient tags
/// into a byte buffer. The caller feeds the buffer contents into the scope's
/// BLAKE2b state after the LC closure returns. No field arithmetic and no
/// per-LC hash state initialization.
struct LCHash {
    buf: Vec<u8>,
    gain_tag: u8,
}

impl LCHash {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            gain_tag: 1, // Coeff::One
        }
    }
}

impl<F: Field> LinearExpression<u32, F> for LCHash {
    fn add_term(mut self, wire: &u32, coeff: Coeff<F>) -> Self {
        self.buf.extend_from_slice(&wire.to_le_bytes());
        self.buf.push(coeff_tag(&coeff));
        self.buf.push(self.gain_tag);
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.buf.push(0xFF); // gain marker
        self.buf.push(coeff_tag(&coeff));
        self.gain_tag = coeff_tag(&coeff);
        self
    }
}

/// Per-routine state that is saved and restored across routine boundaries.
struct CounterScope {
    /// Stashed wire from paired allocation (see [`Driver::alloc`]).
    available_b: Option<u32>,

    /// Index into [`Counter::segments`] for the current routine.
    current_segment: usize,

    /// Next wire ID to assign. Resets to 1 on routine entry (0 is ONE).
    next_wire: u32,

    /// Running BLAKE2b state for the fingerprint.
    hash: Blake2bState,
}

/// A [`Driver`] that simultaneously counts constraints and computes routine
/// identity fingerprints via hash-based structural hashing.
///
/// Assigns sequential `u32` wire IDs and hashes the operation sequence
/// (mul gates, linear combinations, coefficient tags) into a running `u64`.
/// When entering a routine, the identity state is saved and reset so that
/// each routine is fingerprinted independently of its calling context.
///
/// Nested routine outputs are treated as auxiliary inputs to the caller: on
/// return, output wires are remapped to fresh allocations in the parent scope
/// rather than folding the child's hash. This makes each routine's fingerprint
/// capture only its *internal* constraint structure.
struct Counter<F> {
    scope: CounterScope,
    num_linear_constraints: usize,
    num_multiplication_constraints: usize,
    segments: Vec<SegmentRecord>,

    /// When false, `mul` and `enforce_zero` still advance wire IDs and update
    /// the hash but do not increment constraint counts. Used during input and
    /// output wire remapping in [`routine`](Driver::routine).
    counting: bool,

    _marker: PhantomData<F>,
}

impl<F: Field> Counter<F> {
    fn new() -> Self {
        Self {
            scope: CounterScope {
                available_b: None,
                current_segment: 0,
                // Wire 0 is ONE; first alloc/mul starts at 1.
                next_wire: 1,
                hash: new_hash(),
            },
            num_linear_constraints: 0,
            num_multiplication_constraints: 0,
            segments: alloc::vec![SegmentRecord {
                num_multiplication_constraints: 0,
                num_linear_constraints: 0,
                identity: RoutineIdentity::Root,
            }],
            counting: true,
            _marker: PhantomData,
        }
    }

    /// Allocates the next sequential wire ID.
    fn next_wire(&mut self) -> u32 {
        let id = self.scope.next_wire;
        self.scope.next_wire += 1;
        id
    }
}

impl<F: Field> DriverTypes for Counter<F> {
    type MaybeKind = Empty;
    type ImplField = F;
    type ImplWire = u32;
    type LCadd = LCHash;
    type LCenforce = LCHash;
}

impl<'dr, F: Field> Driver<'dr> for Counter<F> {
    type F = F;
    type Wire = u32;
    const ONE: Self::Wire = 0;

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(wire) = self.scope.available_b.take() {
            Ok(wire)
        } else {
            let (a, b, _) = self.mul(|| unreachable!())?;
            self.scope.available_b = Some(b);
            Ok(a)
        }
    }

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        if self.counting {
            self.num_multiplication_constraints += 1;
            self.segments[self.scope.current_segment].num_multiplication_constraints += 1;
        }

        let a = self.next_wire();
        let b = self.next_wire();
        let c = self.next_wire();

        self.scope.hash.update(&[0x01]); // mul marker
        self.scope.hash.update(&a.to_le_bytes());
        self.scope.hash.update(&b.to_le_bytes());
        self.scope.hash.update(&c.to_le_bytes());

        Ok((a, b, c))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let result = lc(LCHash::new());
        let wire = self.next_wire();
        self.scope.hash.update(&[0x02]); // add marker
        self.scope
            .hash
            .update(&(result.buf.len() as u32).to_le_bytes());
        self.scope.hash.update(&result.buf);
        self.scope.hash.update(&wire.to_le_bytes());
        wire
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        if self.counting {
            self.num_linear_constraints += 1;
            self.segments[self.scope.current_segment].num_linear_constraints += 1;
        }

        let result = lc(LCHash::new());
        self.scope.hash.update(&[0x03]); // enforce_zero marker
        self.scope
            .hash
            .update(&(result.buf.len() as u32).to_le_bytes());
        self.scope.hash.update(&result.buf);

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
                next_wire: 1, // 0 is ONE
                hash: new_hash(),
            },
        );

        // Map input wires from parent's binding to fresh wires in the
        // child scope. Counting is disabled because these gates exist
        // solely to seed the wire IDs for fingerprinting.
        self.counting = false;
        let new_input = Ro::Input::map_gadget(&input, self)?;
        self.counting = true;
        self.scope.available_b = None;

        // Predict and execute.
        let mut dummy = Emulator::wireless();
        let dummy_input = Ro::Input::map_gadget(&new_input, &mut dummy)?;
        let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
        let output = routine.execute(self, new_input, aux)?;

        // Extract fingerprint from the child's hash.
        self.segments[segment_idx].identity =
            RoutineIdentity::Routine(RoutineFingerprint::of::<F, Ro>(finalize_u64(
                &self.scope.hash,
            )));

        // Restore parent scope.
        self.scope = saved;

        // Remap child output wires as fresh parent allocations.
        // Save and restore identity state so the uncounted gates
        // don't drift the parent's hash or wire counter.
        let saved_b = self.scope.available_b.take();
        let saved_hash = self.scope.hash.clone();
        let saved_wire = self.scope.next_wire;

        self.counting = false;
        let parent_output = Ro::Output::map_gadget(&output, self)?;
        self.counting = true;

        self.scope.available_b = saved_b;
        self.scope.hash = saved_hash;
        self.scope.next_wire = saved_wire;

        Ok(parent_output)
    }
}

/// Allows [`Counter`] to receive input wires from any driver with the same
/// field type. Each source wire is mapped to a fresh allocation on the counter,
/// producing linearly independent wire values for the input gadget.
impl<'dr, F: Field, D: Driver<'dr, F = F>> FromDriver<'dr, '_, D> for Counter<F> {
    type NewDriver = Self;

    fn convert_wire(&mut self, _: &D::Wire) -> Result<u32> {
        self.alloc(|| unreachable!())
    }
}

/// Computes the [`RoutineIdentity`] for a single routine invocation.
///
/// Creates a fresh [`Counter`], maps the caller's `input` gadget into the
/// counter (allocating fresh wires for each input wire), then predicts and
/// executes the routine.
#[cfg(test)]
pub(crate) fn fingerprint_routine<'dr, F, D, Ro>(
    routine: &Ro,
    input: &Bound<'dr, D, Ro::Input>,
) -> Result<RoutineIdentity>
where
    F: Field,
    D: Driver<'dr, F = F>,
    Ro: Routine<F>,
{
    let mut counter = Counter::new();

    // Map input from the caller's driver to Counter wires.
    let new_input = Ro::Input::map_gadget(input, &mut counter)?;

    // Predict (on a wireless emulator) then execute on the counter.
    let mut dummy = Emulator::wireless();
    let dummy_input = Ro::Input::map_gadget(&new_input, &mut dummy)?;
    let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
    routine.execute(&mut counter, new_input, aux)?;

    Ok(RoutineIdentity::Routine(RoutineFingerprint::of::<F, Ro>(
        finalize_u64(&counter.scope.hash),
    )))
}

/// Evaluates the constraint topology of a circuit.
pub fn eval<F: Field, C: Circuit<F>>(circuit: &C) -> Result<CircuitMetrics> {
    let mut collector = Counter::new();
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
