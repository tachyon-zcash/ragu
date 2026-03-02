//! Assembly of the $r(X)$ trace polynomial.
//!
//! The [`eval`] function in this module processes witness data for a
//! particular [`Circuit`] and produces raw gate values as a [`Trace`].
//! The [`Trace`] is later assembled into a [`structured::Polynomial`]
//! by the registry.

use alloc::{boxed::Box, vec, vec::Vec};
use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverTypes, FromDriver, emulator::Emulator},
    gadgets::{Bound, GadgetKind},
    maybe::{Always, Maybe, MaybeKind},
    routines::{Prediction, Routine},
};
use ragu_primitives::GadgetExt;

use super::{
    Circuit, DriverScope, Rank, floor_planner::ConstraintSegment, metrics::SegmentRecord, registry,
    structured,
};

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

/// A deferred execute() call that will be processed after circuit traversal.
/// The closure takes the evaluator mutably and fills in the segment at the captured index.
type PendingExecute<'a, F> = Box<dyn FnOnce(&mut Evaluator<'a, F>) -> Result<()> + 'a>;

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
    /// Pre-allocates all `num_segments` segments. Segment 0 starts with a
    /// zeroed placeholder for the ONE gate; segments 1+ are empty.
    pub(crate) fn new(num_segments: usize) -> Self {
        let mut segments = Vec::with_capacity(num_segments);
        // Segment 0: zeroed placeholder for the ONE gate.
        segments.push(Segment {
            a: vec![F::ZERO],
            b: vec![F::ZERO],
            c: vec![F::ZERO],
        });
        for _ in 1..num_segments {
            segments.push(Segment {
                a: Vec::new(),
                b: Vec::new(),
                c: Vec::new(),
            });
        }
        Self { segments }
    }
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
#[derive(Default)]
struct TraceScope {
    /// Gate index within the current segment, from paired allocation.
    available_b: Option<usize>,
    /// Index of the segment that receives new gates.
    current_segment: usize,
}

struct Evaluator<'a, F: Field> {
    trace: &'a mut Trace<F>,
    state: TraceScope,
    /// Deferred execute() calls to be processed after circuit traversal.
    pending: Vec<PendingExecute<'a, F>>,
    /// Per-segment subtree sizes from metrics, used to skip past Known subtrees.
    subtree_sizes: &'a [usize],
    /// DFS counter for the next routine segment (0 is root, routines start at 1).
    next_routine: usize,
}

impl<F: Field> DriverScope<TraceScope> for Evaluator<'_, F> {
    fn scope(&mut self) -> &mut TraceScope {
        &mut self.state
    }
}

impl<F: Field> DriverTypes for Evaluator<'_, F> {
    type ImplField = F;
    type ImplWire = ();
    type MaybeKind = Always<()>;
    type LCadd = ();
    type LCenforce = ();
}

/// Maps predicted outputs from the wireless emulator back to the Evaluator.
impl<'dr, 'a, F: Field>
    FromDriver<'dr, 'a, Emulator<ragu_core::drivers::emulator::Wireless<Always<()>, F>>>
    for Evaluator<'a, F>
{
    type NewDriver = Self;

    fn convert_wire(&mut self, _wire: &()) -> Result<()> {
        Ok(())
    }
}

impl<'a, F: Field> Driver<'a> for Evaluator<'a, F> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, value: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        // Packs two allocations into one multiplication gate when possible, enabling consecutive
        // allocations to share gates.
        if let Some(index) = self.state.available_b.take() {
            let seg = &mut self.trace.segments[self.state.current_segment];
            let a = seg.a[index];
            let b = value()?;
            seg.b[index] = b.value();
            seg.c[index] = a * b.value();
            Ok(())
        } else {
            let index = self.trace.segments[self.state.current_segment].a.len();
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
        let seg = &mut self.trace.segments[self.state.current_segment];
        seg.a.push(a.value());
        seg.b.push(b.value());
        seg.c.push(c.value());

        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'a>(
        &mut self,
        routine: Ro,
        input: Bound<'a, Self, Ro::Input>,
    ) -> Result<Bound<'a, Self, Ro::Output>> {
        let seg = self.next_routine;
        self.next_routine += 1;
        self.with_scope(
            TraceScope {
                available_b: None,
                current_segment: seg,
            },
            |this| {
                let mut dummy = Emulator::wireless();
                let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
                match routine.predict(&mut dummy, &dummy_input)? {
                    Prediction::Known(predicted_output, aux) => {
                        let output = Ro::Output::map_gadget(&predicted_output, this)?;
                        // Skip past the entire subtree — children will be filled during flush.
                        let child_start = this.next_routine;
                        this.next_routine += this.subtree_sizes[seg] - 1;
                        let subtree_sizes = this.subtree_sizes;
                        this.pending
                            .push(Box::new(move |dr: &mut Evaluator<'a, F>| {
                                let saved = dr.next_routine;
                                dr.next_routine = child_start;
                                dr.with_scope(
                                    TraceScope {
                                        available_b: None,
                                        current_segment: seg,
                                    },
                                    |dr| {
                                        dr.subtree_sizes = subtree_sizes;
                                        routine.execute(dr, input, aux).map(|_| ())
                                    },
                                )?;
                                dr.next_routine = saved;
                                Ok(())
                            }));
                        Ok(output)
                    }
                    Prediction::Unknown(aux) => routine.execute(this, input, aux),
                }
            },
        )
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
    metrics: &super::metrics::CircuitMetrics,
) -> Result<(Trace<F>, C::Aux<'witness>)> {
    let mut trace = Trace::new(metrics.segments.len());
    let aux = {
        let mut dr = Evaluator {
            trace: &mut trace,
            state: TraceScope::default(),
            pending: Vec::new(),
            subtree_sizes: &metrics.subtree_sizes,
            next_routine: 1,
        };
        let (io, aux) = circuit.witness(&mut dr, Always::maybe_just(|| witness))?;
        io.write(&mut dr, &mut ())?;

        // Flush deferred execute() calls, looping until all nested
        // Known thunks are drained.
        loop {
            let pending = core::mem::take(&mut dr.pending);
            if pending.is_empty() {
                break;
            }
            for thunk in pending {
                thunk(&mut dr)?;
            }
        }

        aux.take()
    };
    Ok((trace, aux))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{metrics, tests::SquareCircuit};
    use ragu_core::{drivers::DriverValue, gadgets::Kind};
    use ragu_pasta::Fp;
    use ragu_primitives::Element;

    /// Computes metrics then evaluates the circuit.
    fn eval_with_metrics<'w, C: Circuit<Fp>>(
        circuit: &C,
        witness: C::Witness<'w>,
    ) -> Result<(Trace<Fp>, C::Aux<'w>)> {
        let m = metrics::eval(circuit)?;
        eval(circuit, witness, &m)
    }

    #[test]
    fn test_rx() {
        let circuit = SquareCircuit { times: 10 };
        let witness: Fp = Fp::from(3);
        let (trace, _aux) = eval_with_metrics(&circuit, witness).unwrap();
        for seg in &trace.segments {
            for i in 0..seg.a.len() {
                assert_eq!(seg.a[i] * seg.b[i], seg.c[i]);
            }
        }
    }

    /// Squares its input. Returns Unknown. 1 mul gate.
    #[derive(Clone)]
    struct InnerRoutine;

    impl Routine<Fp> for InnerRoutine {
        type Input = Kind![Fp; Element<'_, _>];
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            input.square(dr)
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

    /// Returns Known. Nests InnerRoutine in execute, then squares the result.
    #[derive(Clone)]
    struct OuterRoutine;

    impl Routine<Fp> for OuterRoutine {
        type Input = Kind![Fp; Element<'_, _>];
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            let inner_result = dr.routine(InnerRoutine, input)?;
            inner_result.square(dr)
        }

        fn predict<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            let output = Element::alloc(
                dr,
                D::with(|| {
                    let v = *input.value().snag();
                    Ok(v.square().square())
                })?,
            )?;
            Ok(Prediction::Known(output, D::just(|| ())))
        }
    }

    /// Squares its input twice. Returns Unknown. 2 mul gates.
    #[derive(Clone)]
    struct SiblingRoutine;

    impl Routine<Fp> for SiblingRoutine {
        type Input = Kind![Fp; Element<'_, _>];
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            let a = input.square(dr)?;
            a.square(dr)
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

    /// Calls OuterRoutine (Known, deferred) then SiblingRoutine (Unknown, inline).
    struct NestedRoutineCircuit;

    impl Circuit<Fp> for NestedRoutineCircuit {
        type Instance<'instance> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        type Witness<'witness> = Fp;
        type Aux<'witness> = ();

        fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Self::Instance<'instance>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, instance)
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<(
            Bound<'dr, D, Self::Output>,
            DriverValue<D, Self::Aux<'witness>>,
        )> {
            let a = Element::alloc(dr, witness)?;
            let _b = dr.routine(OuterRoutine, a.clone())?;
            let c = dr.routine(SiblingRoutine, a)?;
            Ok((c, D::just(|| ())))
        }
    }

    /// Nested routine calls from a deferred Known routine should produce
    /// segments in canonical DFS order, not at the end of the trace.
    ///
    /// Correct: [root(0), outer(1), inner(2), sibling(3)]
    /// Bug:     [root(0), outer(1), sibling(2), inner(3)]
    #[test]
    fn test_nested_known_routine_dfs_order() {
        let circuit = NestedRoutineCircuit;
        let witness = Fp::from(3);
        let (trace, _) = eval_with_metrics(&circuit, witness).unwrap();

        assert_eq!(trace.segments.len(), 4);

        for (seg_idx, seg) in trace.segments.iter().enumerate() {
            for i in 0..seg.a.len() {
                assert_eq!(
                    seg.a[i] * seg.b[i],
                    seg.c[i],
                    "gate constraint violated in segment {seg_idx} at position {i}"
                );
            }
        }

        assert_eq!(trace.segments[2].a.len(), 1, "segment 2 should be inner");
        assert_eq!(trace.segments[3].a.len(), 2, "segment 3 should be sibling");
    }

    /// Returns Known. Squares its input in execute. 1 mul gate.
    #[derive(Clone)]
    struct KnownInner;

    impl Routine<Fp> for KnownInner {
        type Input = Kind![Fp; Element<'_, _>];
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            input.square(dr)
        }

        fn predict<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            let output = Element::alloc(
                dr,
                D::with(|| {
                    let v = *input.value().snag();
                    Ok(v.square())
                })?,
            )?;
            Ok(Prediction::Known(output, D::just(|| ())))
        }
    }

    /// Returns Known. Nests KnownInner in execute, then squares the result.
    #[derive(Clone)]
    struct KnownOuter;

    impl Routine<Fp> for KnownOuter {
        type Input = Kind![Fp; Element<'_, _>];
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            let inner_result = dr.routine(KnownInner, input)?;
            inner_result.square(dr)
        }

        fn predict<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            let output = Element::alloc(
                dr,
                D::with(|| {
                    let v = *input.value().snag();
                    Ok(v.square().square())
                })?,
            )?;
            Ok(Prediction::Known(output, D::just(|| ())))
        }
    }

    /// Calls KnownOuter which nests KnownInner — both return Known.
    struct KnownNestingCircuit;

    impl Circuit<Fp> for KnownNestingCircuit {
        type Instance<'instance> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        type Witness<'witness> = Fp;
        type Aux<'witness> = ();

        fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Self::Instance<'instance>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, instance)
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<(
            Bound<'dr, D, Self::Output>,
            DriverValue<D, Self::Aux<'witness>>,
        )> {
            let a = Element::alloc(dr, witness)?;
            let b = dr.routine(KnownOuter, a)?;
            Ok((b, D::just(|| ())))
        }
    }

    /// A Known routine nesting another Known routine must flush both.
    /// The inner Known thunk is pushed to `pending` during the outer's
    /// deferred execute, but `core::mem::take` already drained the vec
    /// so the inner's execute is silently dropped.
    #[test]
    fn test_nested_known_known_flush() {
        let circuit = KnownNestingCircuit;
        let witness = Fp::from(3);
        let (trace, _) = eval_with_metrics(&circuit, witness).unwrap();

        assert_eq!(trace.segments.len(), 3);

        for (seg_idx, seg) in trace.segments.iter().enumerate() {
            for i in 0..seg.a.len() {
                assert_eq!(
                    seg.a[i] * seg.b[i],
                    seg.c[i],
                    "gate constraint violated in segment {seg_idx} at position {i}"
                );
            }
        }

        assert_eq!(
            trace.segments[2].a.len(),
            1,
            "inner Known execute was dropped"
        );
    }

    /// Returns Known. Nests KnownOuter (which nests KnownInner) then squares.
    #[derive(Clone)]
    struct KnownOutermost;

    impl Routine<Fp> for KnownOutermost {
        type Input = Kind![Fp; Element<'_, _>];
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            let result = dr.routine(KnownOuter, input)?;
            result.square(dr)
        }

        fn predict<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            let output = Element::alloc(
                dr,
                D::with(|| {
                    let v = *input.value().snag();
                    // KnownInner: v^2, KnownOuter: v^4, KnownOutermost: v^8
                    Ok(v.square().square().square())
                })?,
            )?;
            Ok(Prediction::Known(output, D::just(|| ())))
        }
    }

    /// Three levels of Known nesting: outermost → outer → inner.
    /// A fix that only does one extra flush pass will miss depth-3.
    #[test]
    fn test_three_level_known_nesting() {
        struct ThreeLevelCircuit;

        impl Circuit<Fp> for ThreeLevelCircuit {
            type Instance<'instance> = Fp;
            type Output = Kind![Fp; Element<'_, _>];
            type Witness<'witness> = Fp;
            type Aux<'witness> = ();

            fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                instance: DriverValue<D, Self::Instance<'instance>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Element::alloc(dr, instance)
            }

            fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'witness>>,
            ) -> Result<(
                Bound<'dr, D, Self::Output>,
                DriverValue<D, Self::Aux<'witness>>,
            )> {
                let a = Element::alloc(dr, witness)?;
                let b = dr.routine(KnownOutermost, a)?;
                Ok((b, D::just(|| ())))
            }
        }

        let (trace, _) = eval_with_metrics(&ThreeLevelCircuit, Fp::from(3)).unwrap();

        // 4 segments: root, outermost, outer, inner
        assert_eq!(trace.segments.len(), 4);

        // Every non-root segment should have 1 gate (each routine squares once).
        for i in 1..4 {
            assert_eq!(
                trace.segments[i].a.len(),
                1,
                "segment {i} should have 1 gate"
            );
        }
    }

    /// Two Known siblings that each nest a Known child.
    /// Tests flush across multiple parents' deferred children.
    #[test]
    fn test_multiple_known_siblings_with_known_children() {
        struct MultiKnownSiblingCircuit;

        impl Circuit<Fp> for MultiKnownSiblingCircuit {
            type Instance<'instance> = Fp;
            type Output = Kind![Fp; Element<'_, _>];
            type Witness<'witness> = Fp;
            type Aux<'witness> = ();

            fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                instance: DriverValue<D, Self::Instance<'instance>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Element::alloc(dr, instance)
            }

            fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'witness>>,
            ) -> Result<(
                Bound<'dr, D, Self::Output>,
                DriverValue<D, Self::Aux<'witness>>,
            )> {
                let a = Element::alloc(dr, witness)?;
                let _b = dr.routine(KnownOuter, a.clone())?;
                let c = dr.routine(KnownOuter, a)?;
                Ok((c, D::just(|| ())))
            }
        }

        let (trace, _) = eval_with_metrics(&MultiKnownSiblingCircuit, Fp::from(3)).unwrap();

        // 5 segments: root, outer1, inner1, outer2, inner2
        assert_eq!(trace.segments.len(), 5);

        // Every non-root segment should have 1 gate.
        for i in 1..5 {
            assert_eq!(
                trace.segments[i].a.len(),
                1,
                "segment {i} should have 1 gate"
            );
        }
    }

    /// Returns Known. Nests an Unknown child and a Known child in execute.
    #[derive(Clone)]
    struct MixedParent;

    impl Routine<Fp> for MixedParent {
        type Input = Kind![Fp; Element<'_, _>];
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            let a = dr.routine(InnerRoutine, input.clone())?;
            let b = dr.routine(KnownInner, input)?;
            a.mul(dr, &b)
        }

        fn predict<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            let output = Element::alloc(
                dr,
                D::with(|| {
                    let v = *input.value().snag();
                    Ok(v.square() * v.square())
                })?,
            )?;
            Ok(Prediction::Known(output, D::just(|| ())))
        }
    }

    /// Known routine nesting both an Unknown and a Known child.
    /// Combines DFS ordering bug (Unknown child) with flush bug (Known child).
    #[test]
    fn test_known_with_mixed_children() {
        struct MixedNestingCircuit;

        impl Circuit<Fp> for MixedNestingCircuit {
            type Instance<'instance> = Fp;
            type Output = Kind![Fp; Element<'_, _>];
            type Witness<'witness> = Fp;
            type Aux<'witness> = ();

            fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                instance: DriverValue<D, Self::Instance<'instance>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Element::alloc(dr, instance)
            }

            fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'witness>>,
            ) -> Result<(
                Bound<'dr, D, Self::Output>,
                DriverValue<D, Self::Aux<'witness>>,
            )> {
                let a = Element::alloc(dr, witness)?;
                let b = dr.routine(MixedParent, a)?;
                Ok((b, D::just(|| ())))
            }
        }

        let (trace, _) = eval_with_metrics(&MixedNestingCircuit, Fp::from(3)).unwrap();

        // 4 segments: root, mixed parent, unknown child, known child
        assert_eq!(trace.segments.len(), 4);

        // Parent has 1 gate (mul), each child has 1 gate (square).
        for i in 1..4 {
            assert_eq!(
                trace.segments[i].a.len(),
                1,
                "segment {i} should have 1 gate"
            );
        }
    }

    /// Flat interleaving of Unknown and Known siblings (no nesting).
    /// Should pass on current code — baseline that flat deferral works.
    #[test]
    fn test_flat_interleaving() {
        struct FlatInterleavingCircuit;

        impl Circuit<Fp> for FlatInterleavingCircuit {
            type Instance<'instance> = Fp;
            type Output = Kind![Fp; Element<'_, _>];
            type Witness<'witness> = Fp;
            type Aux<'witness> = ();

            fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                instance: DriverValue<D, Self::Instance<'instance>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Element::alloc(dr, instance)
            }

            fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'witness>>,
            ) -> Result<(
                Bound<'dr, D, Self::Output>,
                DriverValue<D, Self::Aux<'witness>>,
            )> {
                let a = Element::alloc(dr, witness)?;
                let _ = dr.routine(InnerRoutine, a.clone())?;
                let _ = dr.routine(KnownInner, a.clone())?;
                let _ = dr.routine(InnerRoutine, a.clone())?;
                let d = dr.routine(KnownInner, a)?;
                Ok((d, D::just(|| ())))
            }
        }

        let (trace, _) = eval_with_metrics(&FlatInterleavingCircuit, Fp::from(3)).unwrap();

        // 5 segments: root + 4 flat routines
        assert_eq!(trace.segments.len(), 5);

        // Each routine squares once = 1 gate per segment.
        for i in 1..5 {
            assert_eq!(
                trace.segments[i].a.len(),
                1,
                "segment {i} should have 1 gate"
            );
        }
    }

    /// Known routine whose execute produces zero gates.
    #[test]
    fn test_known_empty_execute() {
        #[derive(Clone)]
        struct KnownEmpty;

        impl Routine<Fp> for KnownEmpty {
            type Input = Kind![Fp; Element<'_, _>];
            type Output = Kind![Fp; Element<'_, _>];
            type Aux<'dr> = ();

            fn execute<'dr, D: Driver<'dr, F = Fp>>(
                &self,
                _dr: &mut D,
                input: Bound<'dr, D, Self::Input>,
                _aux: DriverValue<D, Self::Aux<'dr>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Ok(input)
            }

            fn predict<'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                input: &Bound<'dr, D, Self::Input>,
            ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
            {
                let output = Element::alloc(
                    dr,
                    D::with(|| {
                        let v = *input.value().snag();
                        Ok(v * Fp::ONE)
                    })?,
                )?;
                Ok(Prediction::Known(output, D::just(|| ())))
            }
        }

        struct EmptyKnownCircuit;

        impl Circuit<Fp> for EmptyKnownCircuit {
            type Instance<'instance> = Fp;
            type Output = Kind![Fp; Element<'_, _>];
            type Witness<'witness> = Fp;
            type Aux<'witness> = ();

            fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                instance: DriverValue<D, Self::Instance<'instance>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Element::alloc(dr, instance)
            }

            fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'witness>>,
            ) -> Result<(
                Bound<'dr, D, Self::Output>,
                DriverValue<D, Self::Aux<'witness>>,
            )> {
                let a = Element::alloc(dr, witness)?;
                let b = dr.routine(KnownEmpty, a)?;
                Ok((b, D::just(|| ())))
            }
        }

        let (trace, _) = eval_with_metrics(&EmptyKnownCircuit, Fp::from(3)).unwrap();

        assert_eq!(trace.segments.len(), 2);
        assert_eq!(trace.segments[1].a.len(), 0, "empty execute = 0 gates");
    }

    /// Error from a deferred Known execute must propagate out of eval.
    #[test]
    fn test_deferred_execute_error_propagation() {
        #[derive(Clone)]
        struct KnownFailing;

        impl Routine<Fp> for KnownFailing {
            type Input = Kind![Fp; Element<'_, _>];
            type Output = Kind![Fp; Element<'_, _>];
            type Aux<'dr> = ();

            fn execute<'dr, D: Driver<'dr, F = Fp>>(
                &self,
                _dr: &mut D,
                _input: Bound<'dr, D, Self::Input>,
                _aux: DriverValue<D, Self::Aux<'dr>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Err(Error::InvalidWitness("intentional test failure".into()))
            }

            fn predict<'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                input: &Bound<'dr, D, Self::Input>,
            ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
            {
                let output = Element::alloc(
                    dr,
                    D::with(|| {
                        let v = *input.value().snag();
                        Ok(v * Fp::ONE)
                    })?,
                )?;
                Ok(Prediction::Known(output, D::just(|| ())))
            }
        }

        struct FailingKnownCircuit;

        impl Circuit<Fp> for FailingKnownCircuit {
            type Instance<'instance> = Fp;
            type Output = Kind![Fp; Element<'_, _>];
            type Witness<'witness> = Fp;
            type Aux<'witness> = ();

            fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                instance: DriverValue<D, Self::Instance<'instance>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Element::alloc(dr, instance)
            }

            fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'witness>>,
            ) -> Result<(
                Bound<'dr, D, Self::Output>,
                DriverValue<D, Self::Aux<'witness>>,
            )> {
                let a = Element::alloc(dr, witness)?;
                let b = dr.routine(KnownFailing, a)?;
                Ok((b, D::just(|| ())))
            }
        }

        let result = eval_with_metrics(&FailingKnownCircuit, Fp::from(3));
        assert!(result.is_err());
    }
}
