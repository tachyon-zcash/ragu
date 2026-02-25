//! Circuit constraint analysis and metrics collection.
//!
//! This module provides constraint system analysis by simulating circuit
//! execution without computing actual values, counting the number of
//! multiplication and linear constraints a circuit requires.

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes, emulator::Emulator},
    gadgets::{Bound, GadgetKind},
    maybe::Empty,
    routines::Routine,
};
use ragu_primitives::GadgetExt;

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{Circuit, DriverScope};

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
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentRecord {
    /// The number of multiplication constraints in this segment.
    pub num_multiplication_constraints: usize,

    /// The number of linear constraints in this segment, including constraints
    /// on wires of the input gadget and on wires allocated within the segment.
    pub num_linear_constraints: usize,
}

/// Performs full constraint system analysis, capturing basic details about a circuit's topology through simulation.
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

/// Per-segment state that is saved and restored by [`DriverScope`].
struct CounterScope {
    available_b: bool,
    current_segment: usize,
}

struct Counter<F> {
    scope: CounterScope,
    num_linear_constraints: usize,
    num_multiplication_constraints: usize,
    segments: Vec<SegmentRecord>,
    _marker: PhantomData<F>,
}

impl<F: Field> DriverScope<CounterScope> for Counter<F> {
    fn scope(&mut self) -> &mut CounterScope {
        &mut self.scope
    }
}

impl<F: Field> DriverTypes for Counter<F> {
    type MaybeKind = Empty;
    type ImplField = F;
    type ImplWire = ();
    type LCadd = ();
    type LCenforce = ();
}

impl<'dr, F: Field> Driver<'dr> for Counter<F> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if self.scope.available_b {
            self.scope.available_b = false;
            Ok(())
        } else {
            self.scope.available_b = true;
            self.mul(|| unreachable!())?;

            Ok(())
        }
    }

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        self.num_multiplication_constraints += 1;
        self.segments[self.scope.current_segment].num_multiplication_constraints += 1;

        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        self.num_linear_constraints += 1;
        self.segments[self.scope.current_segment].num_linear_constraints += 1;
        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        self.segments.push(SegmentRecord::default());
        let segment_idx = self.segments.len() - 1;
        self.with_scope(
            CounterScope {
                available_b: false,
                current_segment: segment_idx,
            },
            |this| {
                let mut dummy = Emulator::wireless();
                let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
                let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
                let result = routine.execute(this, input, aux)?;

                // Verify internal consistency: current_segment unchanged.
                assert_eq!(
                    this.scope.current_segment, segment_idx,
                    "current_segment must remain stable during routine execution"
                );

                Ok(result)
            },
        )
    }
}

pub fn eval<F: Field, C: Circuit<F>>(circuit: &C) -> Result<CircuitMetrics> {
    let mut collector = Counter {
        scope: CounterScope {
            available_b: false,
            current_segment: 0,
        },
        num_linear_constraints: 0,
        num_multiplication_constraints: 0,
        segments: alloc::vec![SegmentRecord::default()],
        _marker: PhantomData,
    };
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
