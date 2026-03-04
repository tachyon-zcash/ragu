//! Assembly of the $r(X)$ trace polynomial.
//!
//! The [`eval`] function in this module processes witness data for a
//! particular [`Circuit`] and produces raw gate values as a [`Trace`].
//! The [`Trace`] is later assembled into a [`structured::Polynomial`]
//! by the registry.

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, FromDriver, emulator::Emulator},
    gadgets::{Bound, Gadget},
    maybe::{Always, Maybe, MaybeKind},
    routines::{Prediction, Routine},
};
use ragu_primitives::GadgetExt;

use alloc::{boxed::Box, vec, vec::Vec};
use core::marker::PhantomData;

use super::{
    Circuit, DriverScope, Rank, floor_planner::ConstraintSegment, metrics::SegmentRecord, registry,
    structured,
};

/// Deferred `execute()` for a Known-predicted routine.                                                                                                                                                                                            
///                                                                                                            
/// Created when `predict()` returns [`Known`](Prediction::Known), allowing                                                                                                                                                                        
/// the main traversal to continue with the predicted output while deferring                                   
/// the actual witness computation. When invoked, runs `execute()` in a fresh
/// [`Evaluator`] and returns the resulting trace segments.
struct Thunk<'env, F: Field>(
    Box<dyn FnOnce(&mut Vec<Thunk<'env, F>>) -> Result<Vec<AnnotatedSegment<F>>> + Send + 'env>,
);

impl<'env, F: Field> Thunk<'env, F> {
    fn run(self, thunks: &mut Vec<Thunk<'env, F>>) -> Result<Vec<AnnotatedSegment<F>>> {
        (self.0)(thunks)
    }
}

/// A contiguous group of multiplication gates.
///
/// Segment 0 is the root segment and holds the placeholder `ONE` gate
/// at position 0. Routine calls create additional segments (see
/// [`Evaluator::routine`]).
pub(crate) struct Segment<F> {
    pub(crate) a: Vec<F>,
    pub(crate) b: Vec<F>,
    pub(crate) c: Vec<F>,
}

/// A segment paired with the DFS path that produced it, so that segments from
/// independent evaluators can be sorted back into the canonical DFS order
/// expected by the floor planner. This is used during post-processing.
///
/// The path is the sequence of routine-call indices from root to this segment.
/// For example, if the root's second routine call (`routine_counter = 1`)
/// itself makes a first routine call (`routine_counter = 0`), that inner
/// segment has path `[1, 0]`. Lexicographic sort of paths reconstructs DFS
/// visitation order.
struct AnnotatedSegment<F> {
    dfs_path: Vec<usize>,
    segment: Segment<F>,
}

impl<F: Field> AnnotatedSegment<F> {
    fn new(prefix: &[usize]) -> Self {
        let is_root = prefix.is_empty();
        let init = || if is_root { vec![F::ZERO] } else { Vec::new() };
        Self {
            dfs_path: prefix.to_vec(),
            segment: Segment {
                a: init(),
                b: init(),
                c: init(),
            },
        }
    }
}

/// Trace data produced by evaluating a circuit.
///
/// Pass to [`Registry::assemble`](crate::registry::Registry::assemble)
/// to obtain the corresponding [`structured::Polynomial`].
pub struct Trace<F> {
    /// Gate groups in DFS order. Segment 0 is the root segment;
    /// segments 1+ are created by [`Driver::routine`] calls.
    pub(crate) segments: Vec<Segment<F>>,
}

impl<F: Field> Trace<F> {
    /// Assembles this trace into a [`structured::Polynomial`] using
    /// a default [`Key`](registry::Key), without registry
    /// optimizations.
    ///
    /// This is a convenience for tests that need a polynomial from a
    /// trace but don't have (or need) a full
    /// [`Registry`](registry::Registry).
    ///
    /// **Note:** This synthesizes a trivial floor plan from segment lengths with
    /// zero linear constraints. It is only correct for traces produced by
    /// circuits (or stages) that have no linear constraints in any segment.
    pub fn assemble_trivial<R: Rank>(&self) -> Result<structured::Polynomial<F, R>> {
        let segment_records: Vec<SegmentRecord> = self
            .segments
            .iter()
            .map(|seg| SegmentRecord {
                num_multiplication_constraints: seg.a.len(),
                num_linear_constraints: 0,
            })
            .collect();
        let plan = super::floor_planner::floor_plan(&segment_records);
        self.assemble_with_key(&registry::Key::default(), &plan)
    }

    /// Assembles this trace into a [`structured::Polynomial`] using
    /// the provided registry [`Key`](registry::Key).
    ///
    /// Each segment is scattered to the absolute position assigned by
    /// `floor_plan`, so that gate *i* in the resulting polynomial
    /// holds the trace values for the constraint that s(X,Y)
    /// evaluates at monomial position *i*.
    pub(crate) fn assemble_with_key<R: Rank>(
        &self,
        key: &registry::Key<F>,
        floor_plan: &[ConstraintSegment],
    ) -> Result<structured::Polynomial<F, R>> {
        assert_eq!(
            floor_plan.len(),
            self.segments.len(),
            "floor plan and trace must have the same number of segment entries"
        );
        assert_eq!(
            floor_plan[0].multiplication_start, 0,
            "root segment must be placed at the polynomial origin"
        );

        let total_gates = self
            .segments
            .iter()
            .enumerate()
            .map(|(i, seg)| floor_plan[i].multiplication_start + seg.a.len())
            .max()
            .expect("floor plan is never empty (root segment always exists)");
        if total_gates > R::n() {
            return Err(Error::MultiplicationBoundExceeded(R::n()));
        }

        let mut poly = structured::Polynomial::<F, R>::new();
        {
            let view = poly.forward();

            // Pre-allocate zero-filled vectors for random-access scatter.
            view.a.resize(total_gates, F::ZERO);
            view.b.resize(total_gates, F::ZERO);
            view.c.resize(total_gates, F::ZERO);

            // Scatter each segment to its floor-plan position.
            for (seg_idx, seg) in self.segments.iter().enumerate() {
                let segment = &floor_plan[seg_idx];

                // Verify segment size matches floor plan expectation.
                assert_eq!(
                    seg.a.len(),
                    segment.num_multiplication_constraints,
                    "segment {} size must match floor plan",
                    seg_idx
                );

                let offset = segment.multiplication_start;
                view.a[offset..offset + seg.a.len()].copy_from_slice(&seg.a);
                view.b[offset..offset + seg.b.len()].copy_from_slice(&seg.b);
                view.c[offset..offset + seg.c.len()].copy_from_slice(&seg.c);
            }

            // Overwrite segment 0's zeroed ONE gate placeholder with
            // actual key values.
            view.a[0] = key.value();
            view.b[0] = key.inverse();
            view.c[0] = F::ONE;
        }
        Ok(poly)
    }
}

/// Per-routine state that is saved and restored by [`DriverScope`].
struct TraceScope {
    /// Gate index within the current segment, from paired allocation.
    available_b: Option<usize>,

    /// Index of the segment that receives new gates.
    current_segment: usize,

    /// Monotonic counter of `routine()` calls in this scope.
    routine_counter: usize,

    /// The DFS path from root to this evaluator's scope.
    dfs_prefix: Vec<usize>,
}

/// Driver that records multiplication gates into trace segments.
struct Evaluator<'scope, 'env, F: Field> {
    /// Trace segments produced by this evaluator's routine scope.
    segments: Vec<AnnotatedSegment<F>>,
    /// Deferred `execute()` closures for Known-predicted routines.
    thunks: &'scope mut Vec<Thunk<'env, F>>,
    /// Per-routine state saved and restored across routine boundaries.
    state: TraceScope,
}

impl<'scope, 'env, F: Field> Evaluator<'scope, 'env, F> {
    fn new(prefix: Vec<usize>, thunks: &'scope mut Vec<Thunk<'env, F>>) -> Self {
        Self {
            segments: vec![AnnotatedSegment::new(&prefix)],
            thunks,
            state: TraceScope {
                available_b: None,
                current_segment: 0,
                routine_counter: 0,
                dfs_prefix: prefix,
            },
        }
    }
}

impl<F: Field> DriverScope<TraceScope> for Evaluator<'_, '_, F> {
    fn scope(&mut self) -> &mut TraceScope {
        &mut self.state
    }
}

impl<F: Field> DriverTypes for Evaluator<'_, '_, F> {
    type ImplField = F;
    type ImplWire = ();
    type MaybeKind = Always<()>;
    type LCadd = ();
    type LCenforce = ();
}

impl<'scope, 'env, F: Field> Driver<'env> for Evaluator<'scope, 'env, F> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, value: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        // Packs two allocations into one multiplication gate when possible, enabling consecutive
        // allocations to share gates.
        if let Some(index) = self.state.available_b.take() {
            let seg = &mut self.segments[self.state.current_segment].segment;
            let a = seg.a[index];
            let b = value()?;
            seg.b[index] = b.value();
            seg.c[index] = a * b.value();
            Ok(())
        } else {
            let index = self.segments[self.state.current_segment].segment.a.len();
            self.mul(|| Ok((value()?, Coeff::Zero, Coeff::Zero)))?;
            self.state.available_b = Some(index);
            Ok(())
        }
    }

    fn mul(
        &mut self,
        values: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<((), (), ())> {
        let (a, b, c) = values()?;
        let seg = &mut self.segments[self.state.current_segment].segment;
        seg.a.push(a.value());
        seg.b.push(b.value());
        seg.c.push(c.value());

        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'env>(
        &mut self,
        routine: Ro,
        input: Bound<'env, Self, Ro::Input>,
    ) -> Result<Bound<'env, Self, Ro::Output>> {
        let prediction = {
            let mut dummy = Emulator::wireless();
            let input = input.map(&mut dummy)?;
            routine.predict(&mut dummy, &input)?
        };

        let routine_index = self.state.routine_counter;
        self.state.routine_counter += 1;

        let mut child_prefix = self.state.dfs_prefix.clone();
        child_prefix.push(routine_index);

        match prediction {
            Prediction::Known(predicted_output, aux) => {
                let output = predicted_output.map(&mut Lifter::lift())?;
                // Remap the input gadget to a driver-independent representation,
                // then wrap in `Sendable` to satisfy the `Send` bound on the
                // thunk closure.
                let input = input.map(&mut Lifter::lift())?.sendable();

                self.thunks.push(Thunk(Box::new(move |thunks| {
                    let mut eval = Evaluator::new(child_prefix, thunks);
                    input
                        .into_inner()
                        .map(&mut Lifter::lift())
                        .and_then(|input| routine.execute(&mut eval, input, aux))
                        // Discard the output gadget; we already have the predicted output.
                        .map(|_| {
                            assert!(
                                !eval.segments.is_empty(),
                                "deferred routine must produce at least one segment"
                            );
                            eval.segments
                        })
                })));

                Ok(output)
            }
            // Without a predicted output the caller cannot continue, so
            // Unknown routines must be evaluated inline.
            Prediction::Unknown(aux) => {
                self.segments.push(AnnotatedSegment::new(&child_prefix));
                let seg_idx = self.segments.len() - 1;
                self.with_scope(
                    TraceScope {
                        available_b: None,
                        current_segment: seg_idx,
                        routine_counter: 0,
                        dfs_prefix: child_prefix,
                    },
                    |this| {
                        let result = routine.execute(this, input, aux);
                        assert_eq!(
                            this.state.current_segment, seg_idx,
                            "current_segment must remain stable during routine execution"
                        );
                        result
                    },
                )
            }
        }
    }
}

/// [`FromDriver`] adapter that trivially converts `()` wires between any
/// `Driver` and an [`Evaluator`].
///
/// Because every `Evaluator` wire is `()`, conversion is a no-op. The
/// `'scope` and `'env` lifetimes tie the adapter to a particular
/// `Evaluator` so the compiler can verify the remapped gadgets stay valid.
struct Lifter<'scope, 'env, F: Field>(PhantomData<Evaluator<'scope, 'env, F>>);

impl<'scope, 'env, F: Field> Lifter<'scope, 'env, F> {
    fn lift() -> Self {
        Self(PhantomData)
    }
}

impl<'dr, 'scope, 'env, F: Field, D: Driver<'dr, Wire = (), F = F>> FromDriver<'dr, 'env, D>
    for Lifter<'scope, 'env, F>
{
    type NewDriver = Evaluator<'scope, 'env, F>;

    fn convert_wire(&mut self, _: &()) -> Result<()> {
        Ok(())
    }
}

/// Sorts segments by DFS path and strips annotations.
fn finish<F: Field>(mut segments: Vec<AnnotatedSegment<F>>) -> Trace<F> {
    segments.sort_unstable_by(|a, b| a.dfs_path.cmp(&b.dfs_path));

    assert!(
        segments[0].dfs_path.is_empty(),
        "root segment must be present after sorting"
    );

    Trace {
        segments: segments.into_iter().map(|s| s.segment).collect(),
    }
}

/// Computes the trace for a circuit from a witness, producing a [`Trace`]
/// and auxiliary data.
///
/// The returned [`Trace`] can be assembled into a polynomial via
/// [`Registry::assemble`](crate::registry::Registry::assemble).
pub fn eval<'witness, F: Field, C: Circuit<F>>(
    circuit: &C,
    witness: C::Witness<'witness>,
) -> Result<(Trace<F>, C::Aux<'witness>)> {
    let mut thunks = Vec::new();

    let (mut segments, aux) = {
        let mut evaluator = Evaluator::new(Vec::new(), &mut thunks);

        let aux = {
            let (_io, aux) = circuit.witness(&mut evaluator, Always::maybe_just(|| witness))?;
            aux.take()
        };

        Ok((evaluator.segments, aux))
    }?;

    // Flush deferred execute() calls, popping until all nested
    // Known thunks are drained.
    // TODO: thunks are independent and can be evaluated in parallel.
    while let Some(thunk) = thunks.pop() {
        segments.extend(thunk.run(&mut thunks)?);
    }

    Ok((finish(segments), aux))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::SquareCircuit;
    use ragu_pasta::Fp;

    #[test]
    fn test_rx() {
        let circuit = SquareCircuit { times: 10 };
        let witness: Fp = Fp::from(3);
        let (trace, _aux) = eval::<Fp, _>(&circuit, witness).unwrap();
        for seg in &trace.segments {
            for i in 0..seg.a.len() {
                assert_eq!(seg.a[i] * seg.b[i], seg.c[i]);
            }
        }
    }
}
