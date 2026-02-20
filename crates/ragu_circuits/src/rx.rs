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
    drivers::{Driver, DriverTypes, emulator::Emulator},
    gadgets::{Bound, GadgetKind},
    maybe::{Always, Maybe, MaybeKind},
    routines::Routine,
};
use ragu_primitives::GadgetExt;

use alloc::{vec, vec::Vec};

use super::{
    Circuit, DriverScope, Rank, floor_planner::RoutineSlot, metrics::RoutineRecord, registry,
    structured,
};

/// A contiguous group of multiplication gates.
///
/// Segment 0 is the root segment and holds the placeholder `ONE` gate at
/// position 0. Routine calls create additional segments (see
/// [`Evaluator::routine`]).
pub(crate) struct Segment<F> {
    pub(crate) a: Vec<F>,
    pub(crate) b: Vec<F>,
    pub(crate) c: Vec<F>,
}

/// Trace data produced by evaluating a circuit.
///
/// Pass to [`Registry::assemble`](crate::registry::Registry::assemble)
/// to obtain the corresponding [`structured::Polynomial`].
pub struct Trace<F> {
    /// Per-routine gate groups. Segment 0 is the root; segments 1+ are
    /// created by [`Driver::routine`] calls.
    pub(crate) segments: Vec<Segment<F>>,
}

impl<F: Field> Trace<F> {
    pub(crate) fn new() -> Self {
        // Segment 0 starts with a zeroed placeholder for the ONE gate.
        // assemble_with_key overwrites position 0 with the actual key values.
        Self {
            segments: vec![Segment {
                a: vec![F::ZERO],
                b: vec![F::ZERO],
                c: vec![F::ZERO],
            }],
        }
    }

    fn push_segment(&mut self) {
        self.segments.push(Segment {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
        });
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
    /// circuits (or stages) that have no linear constraints in any routine.
    pub fn assemble_trivial<R: Rank>(&self) -> Result<structured::Polynomial<F, R>> {
        let records: Vec<RoutineRecord> = self
            .segments
            .iter()
            .map(|seg| RoutineRecord {
                num_multiplication_constraints: seg.a.len(),
                num_linear_constraints: 0,
            })
            .collect();
        let plan = super::floor_planner::floor_plan(&records);
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
        floor_plan: &[RoutineSlot],
    ) -> Result<structured::Polynomial<F, R>> {
        assert_eq!(
            floor_plan.len(),
            self.segments.len(),
            "floor plan and trace must have the same number of routine entries"
        );
        assert_eq!(
            floor_plan[0].multiplication_start, 0,
            "root routine must be placed at the polynomial origin"
        );

        let total_gates = self
            .segments
            .iter()
            .enumerate()
            .map(|(i, seg)| floor_plan[i].multiplication_start + seg.a.len())
            .max()
            .expect("floor plan is never empty (root record always exists)");
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
                let slot = &floor_plan[seg_idx];

                // Verify segment size matches floor plan expectation.
                assert_eq!(
                    seg.a.len(),
                    slot.num_multiplication_constraints,
                    "segment {} size must match floor plan",
                    seg_idx
                );

                let offset = slot.multiplication_start;
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
struct EvalState {
    /// Gate index within the current segment, from paired allocation.
    available_b: Option<usize>,
    /// Index of the segment that receives new gates.
    current_segment: usize,
}

struct Evaluator<'a, F: Field> {
    trace: &'a mut Trace<F>,
    state: EvalState,
}

impl<F: Field> DriverScope<EvalState> for Evaluator<'_, F> {
    fn scope(&mut self) -> &mut EvalState {
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
        self.trace.push_segment();
        let seg = self.trace.segments.len() - 1;
        self.with_scope(
            EvalState {
                available_b: None,
                current_segment: seg,
            },
            |this| {
                let mut dummy = Emulator::wireless();
                let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
                let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
                routine.execute(this, input, aux)
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
) -> Result<(Trace<F>, C::Aux<'witness>)> {
    let mut trace = Trace::new();
    let aux = {
        let mut dr = Evaluator {
            trace: &mut trace,
            state: EvalState::default(),
        };
        let (io, aux) = circuit.witness(&mut dr, Always::maybe_just(|| witness))?;
        io.write(&mut dr, &mut ())?;

        aux.take()
    };
    Ok((trace, aux))
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
