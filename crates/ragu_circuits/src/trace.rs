//! Assembly of the $r(X)$ trace polynomial.
//!
//! The [`eval`] function in this module processes witness data for a
//! particular [`Circuit`] and produces raw gate values as a [`Trace`].
//! The [`Trace`] is later assembled into a [`sparse::Polynomial`]
//! by the registry.

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Error, Result,
    convert::{CloneWires, StripWires, WireMap},
    drivers::{Driver, DriverTypes, emulator::Emulator},
    gadgets::Bound,
    maybe::{Always, Maybe, MaybeKind},
    routines::{Prediction, Routine},
};
use ragu_primitives::GadgetExt;

use alloc::{vec, vec::Vec};
#[cfg(feature = "multicore")]
use std::sync::mpsc;

use super::{Circuit, DriverScope, Rank, floor_planner::ConstraintSegment, sparse};
use crate::WithAux;

/// A contiguous group of multiplication gates.
///
/// Segment 0 is the root segment and holds the placeholder `ONE` gate
/// at position 0. Routine calls create additional segments (see
/// [`Evaluator::routine`]).
pub(crate) struct Segment<F> {
    pub(crate) a: Vec<F>,
    pub(crate) b: Vec<F>,
    pub(crate) c: Vec<F>,
    pub(crate) d: Vec<F>,
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
                d: init(),
            },
        }
    }
}

/// Trace data produced by evaluating a circuit.
///
/// Pass to [`Registry::assemble`](crate::registry::Registry::assemble)
/// to obtain the corresponding [`sparse::Polynomial`].
pub struct Trace<F> {
    /// Gate groups in DFS order. Segment 0 is the root segment;
    /// segments 1+ are created by [`Driver::routine`] calls.
    pub(crate) segments: Vec<Segment<F>>,
}

impl<F: Field> Trace<F> {
    /// Assembles this trace into a [`sparse::Polynomial`] using
    /// the provided floor plan.
    ///
    /// Each segment is scattered to the absolute position assigned by
    /// `floor_plan`, so that gate *i* in the resulting polynomial
    /// holds the trace values for the constraint that s(X,Y)
    /// evaluates at monomial position *i*.
    pub(crate) fn assemble<R: Rank>(
        &self,
        floor_plan: &[ConstraintSegment],
        alpha: F,
    ) -> Result<sparse::Polynomial<F, R>> {
        assert_eq!(
            floor_plan.len(),
            self.segments.len(),
            "floor plan and trace must have the same number of segment entries"
        );
        assert_eq!(
            floor_plan[0].gate_start, 0,
            "root segment must be placed at the polynomial origin"
        );

        let total_gates = self
            .segments
            .iter()
            .enumerate()
            .map(|(i, seg)| floor_plan[i].gate_start + seg.a.len())
            .max()
            .expect("floor plan is never empty (root segment always exists)");
        if total_gates > R::n() {
            return Err(Error::GateBoundExceeded { limit: R::n() });
        }

        let mut view = sparse::View::trace();

        // Pre-allocate zero-filled vectors for random-access scatter.
        view.a.resize(total_gates, F::ZERO);
        view.b.resize(total_gates, F::ZERO);
        view.c.resize(total_gates, F::ZERO);
        view.d.resize(total_gates, F::ZERO);

        // Scatter each segment to its floor-plan position.
        for (seg_idx, seg) in self.segments.iter().enumerate() {
            let segment = &floor_plan[seg_idx];

            // Verify segment size matches floor plan expectation.
            assert_eq!(
                seg.a.len(),
                segment.num_gates,
                "segment {} size must match floor plan",
                seg_idx
            );

            let offset = segment.gate_start;
            view.a[offset..offset + seg.a.len()].copy_from_slice(&seg.a);
            view.b[offset..offset + seg.b.len()].copy_from_slice(&seg.b);
            view.c[offset..offset + seg.c.len()].copy_from_slice(&seg.c);
            view.d[offset..offset + seg.d.len()].copy_from_slice(&seg.d);
        }

        // Overwrite segment 0's zeroed SYSTEM gate placeholder:
        // a[0] = c[0] = 0 (already zero), b[0] = 1 (ONE wire),
        // d[0] = alpha (prevents point-at-infinity commitments).
        view.b[0] = F::ONE;
        view.d[0] = alpha;

        Ok(view.build())
    }
}

/// Per-routine state that is saved and restored by [`DriverScope`].
struct TraceScope {
    /// Gate index within the current segment, from paired allocation.
    available_d: Option<usize>,

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
    /// Rayon scope for spawning Known-predicted routine evaluations.
    scope: &'scope maybe_rayon::Scope<'env>,
    /// Channel for sending completed segments back to the root collector.
    #[cfg(feature = "multicore")]
    tx: mpsc::Sender<Result<Vec<AnnotatedSegment<F>>>>,
    /// Deferred Known-predicted routine segments collected inline.
    #[cfg(not(feature = "multicore"))]
    deferred: Vec<AnnotatedSegment<F>>,
    /// Per-routine state saved and restored by [`DriverScope`].
    state: TraceScope,
}

impl<'scope, 'env, F: Field> Evaluator<'scope, 'env, F> {
    #[cfg(feature = "multicore")]
    fn new(
        prefix: Vec<usize>,
        scope: &'scope maybe_rayon::Scope<'env>,
        tx: mpsc::Sender<Result<Vec<AnnotatedSegment<F>>>>,
    ) -> Self {
        Self {
            segments: vec![AnnotatedSegment::new(&prefix)],
            scope,
            tx,
            state: TraceScope {
                available_d: None,
                current_segment: 0,
                routine_counter: 0,
                dfs_prefix: prefix,
            },
        }
    }

    #[cfg(not(feature = "multicore"))]
    fn new(prefix: Vec<usize>, scope: &'scope maybe_rayon::Scope<'env>) -> Self {
        Self {
            segments: vec![AnnotatedSegment::new(&prefix)],
            scope,
            deferred: Vec::new(),
            state: TraceScope {
                available_d: None,
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

    fn gate(
        &mut self,
        values: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<((), (), (), ())> {
        let (a, b, c, d) = values()?;
        let seg = &mut self.segments[self.state.current_segment].segment;
        seg.a.push(a.value());
        seg.b.push(b.value());
        seg.c.push(c.value());
        seg.d.push(d.value());

        Ok(((), (), (), ()))
    }
}

impl<'scope, 'env, F: Field> Driver<'env> for Evaluator<'scope, 'env, F> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, value: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        // Packs two allocations into one gate with layout (0, b, 0, d),
        // which costs less in multiexp than two separate gates.
        if let Some(index) = self.state.available_d.take() {
            let seg = &mut self.segments[self.state.current_segment].segment;
            seg.d[index] = value()?.value();
            Ok(())
        } else {
            let seg = &mut self.segments[self.state.current_segment].segment;
            let index = seg.a.len();
            seg.a.push(F::ZERO);
            seg.b.push(value()?.value());
            seg.c.push(F::ZERO);
            seg.d.push(F::ZERO);
            self.state.available_d = Some(index);
            Ok(())
        }
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
        let prediction = Emulator::predict(&routine, &input)?;

        let routine_index = self.state.routine_counter;
        self.state.routine_counter += 1;

        let mut child_prefix = self.state.dfs_prefix.clone();
        child_prefix.push(routine_index);

        match prediction {
            Prediction::Known(predicted_output, aux) => {
                // Deferred `execute()` for a Known-predicted routine.
                //
                // Created when `predict()` returns [`Known`](Prediction::Known),
                // allowing the main traversal to continue with the predicted
                // output while deferring the actual witness computation.
                let output = CloneWires::remap(&predicted_output)?;
                let input = StripWires::remap(&input)?.sendable();

                #[cfg(feature = "multicore")]
                {
                    // Spawn the deferred routine in a parallel task and send
                    // the resulting trace segments back through the channel.
                    let tx = self.tx.clone();
                    self.scope.spawn(move |s| {
                        let mut eval = Evaluator::new(child_prefix, s, tx.clone());
                        tx.send(
                            CloneWires::remap(&input.into_inner())
                                .and_then(|input| routine.execute(&mut eval, input, aux))
                                .map(|_| {
                                    assert!(
                                        !eval.segments.is_empty(),
                                        "deferred routine must produce at least one segment"
                                    );
                                    eval.segments
                                }),
                        )
                        .expect("receiver alive");
                    });
                }

                #[cfg(not(feature = "multicore"))]
                {
                    // Without multicore, evaluate inline and collect segments.
                    let mut eval = Evaluator::new(child_prefix, self.scope);
                    CloneWires::remap(&input.into_inner())
                        .and_then(|input| routine.execute(&mut eval, input, aux))?;
                    assert!(
                        !eval.segments.is_empty(),
                        "deferred routine must produce at least one segment"
                    );
                    self.deferred.extend(eval.segments);
                    self.deferred.extend(eval.deferred);
                }

                Ok(output)
            }
            // Without a predicted output the caller cannot continue, so
            // Unknown routines must be evaluated inline.
            Prediction::Unknown(aux) => {
                self.segments.push(AnnotatedSegment::new(&child_prefix));
                let seg_idx = self.segments.len() - 1;
                self.with_scope(
                    TraceScope {
                        available_d: None,
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
) -> Result<WithAux<Trace<F>, C::Aux<'witness>>> {
    #[cfg(feature = "multicore")]
    {
        let (tx, rx) = mpsc::channel();

        let (mut segments, aux) = maybe_rayon::scope(|s| {
            let mut evaluator = Evaluator::new(Vec::new(), s, tx);

            let aux = {
                let cw = circuit.witness(&mut evaluator, Always::maybe_just(|| witness))?;
                cw.output.write(&mut evaluator, &mut ())?;
                cw.aux.take()
            };

            Ok((evaluator.segments, aux))
        })?;

        // Collect segments from spawned Known-predicted routines.
        for batch in rx {
            segments.extend(batch?);
        }

        Ok(WithAux::new(finish(segments), aux))
    }

    #[cfg(not(feature = "multicore"))]
    {
        let (segments, aux) = maybe_rayon::scope(|s| {
            let mut evaluator = Evaluator::new(Vec::new(), s);

            let aux = {
                let cw = circuit.witness(&mut evaluator, Always::maybe_just(|| witness))?;
                cw.output.write(&mut evaluator, &mut ())?;
                cw.aux.take()
            };

            let mut segments = evaluator.segments;
            segments.extend(evaluator.deferred);
            Ok((segments, aux))
        })?;

        Ok(WithAux::new(finish(segments), aux))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::SquareCircuit;
    use ragu_core::gadgets::Kind;
    use ragu_pasta::Fp;
    use ragu_primitives::Element;

    #[test]
    fn test_trace() {
        let circuit = SquareCircuit { times: 10 };
        let witness: Fp = Fp::from(3);
        let trace = eval::<Fp, _>(&circuit, witness).unwrap().into_output();
        for seg in &trace.segments {
            for i in 0..seg.a.len() {
                assert_eq!(seg.a[i] * seg.b[i], seg.c[i]);
            }
        }
    }

    /// Gadget whose [`Write`](ragu_primitives::io::Write) impl calls `dr.mul()`
    /// and `dr.enforce_zero()` during serialization, proving that `io.write()`
    /// in [`eval`] threads the driver to `write_gadget`.
    #[derive(ragu_core::gadgets::Gadget)]
    struct MulOnWrite<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        element: Element<'dr, D>,
    }

    impl<F: ff::Field> ragu_primitives::io::Write<F> for Kind![F; @MulOnWrite<'_, _>] {
        fn write_gadget<'dr, D: Driver<'dr, F = F>, B: ragu_primitives::io::Buffer<'dr, D>>(
            _this: &MulOnWrite<'dr, D>,
            dr: &mut D,
            _buf: &mut B,
        ) -> Result<()> {
            // These calls synthesize constraints during serialization.
            // If io.write() were removed from trace::eval, they would be lost.
            dr.mul(|| Ok((Coeff::One, Coeff::One, Coeff::One)))?;
            dr.enforce_zero(|lc| lc)?;
            Ok(())
        }
    }

    struct MulOnWriteCircuit;

    impl crate::Circuit<Fp> for MulOnWriteCircuit {
        type Instance<'instance> = Fp;
        type Output = Kind![Fp; MulOnWrite<'_, _>];
        type Witness<'witness> = Fp;
        type Aux<'witness> = ();

        fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: ragu_core::drivers::DriverValue<D, Self::Instance<'instance>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            let element = Element::alloc(dr, instance)?;
            Ok(MulOnWrite { element })
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: ragu_core::drivers::DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<
            WithAux<
                Bound<'dr, D, Self::Output>,
                ragu_core::drivers::DriverValue<D, Self::Aux<'witness>>,
            >,
        > {
            let element = Element::alloc(dr, witness)?;
            Ok(WithAux::new(MulOnWrite { element }, D::unit()))
        }
    }

    #[test]
    fn test_write_gadget_synthesizes_into_trace() {
        let circuit = MulOnWriteCircuit;
        let witness = Fp::from(42u64);
        let trace = eval::<Fp, _>(&circuit, witness).unwrap().into_output();

        let root_gates = trace.segments[0].a.len();
        assert_eq!(
            root_gates, 3,
            "write_gadget's dr.mul() must produce a trace gate"
        );
    }
}
