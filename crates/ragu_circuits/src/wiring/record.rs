//! Position-free recording of a routine's contribution to $s(x, y)$.
//!
//! A routine's constraints reference four classes of wires (see the book's
//! routines page): wires it allocates itself, the caller's input gadget
//! wires, nested routines' output wires, and `ONE`. Evaluated at a fixed
//! $(x, y)$, its contribution decomposes as
//!
//! $$
//! y^{\ell} \Big( x^{m} g_{+} + x^{-m} g_{-} + g_{1} + \sum_j h_j w_j \Big)
//! $$
//!
//! where $(m, \ell)$ is the segment's placement, $w_j$ are the input wire
//! values, and $g_{+}, g_{-}, g_{1}, h_j$ depend only on the routine's
//! structure. The [`Recorder`] driver computes those scalars by running the
//! routine in a *relative frame*: its own wires carry monomials as if the
//! segment started at offset $0$, split by whether they scale with $x^{+1}$
//! ($a$ and $d$ wires) or $x^{-1}$ ($b$ and $c$ wires) per gate; input wires
//! are symbolic. Nested routines run in the same frame at their DFS-relative
//! offsets, so a recording covers the whole subtree.
//!
//! A [`Recorded`] routine can then be replayed at any placement with any
//! inputs, which is what makes it reusable within and across circuits.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_core::{
    Coeff, Result,
    convert::WireMap,
    drivers::{
        Driver, DriverTypes, LinearExpression,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, GadgetKind as _},
    maybe::Empty,
    routines::Routine,
};
use udon::field::Field;

use crate::floor_planner::ConstraintSegment;

/// A wire inside a recorded routine, as a linear form over the
/// position-free basis.
#[derive(Clone, Debug)]
pub(crate) struct Form<F> {
    /// Coefficient of the $x^{+m}$ family ($a$ and $d$ wires).
    plus: F,
    /// Coefficient of the $x^{-m}$ family ($b$ and $c$ wires).
    minus: F,
    /// Coefficient of the `ONE` wire.
    one: F,
    /// Coefficients of the input gadget's wires, sorted by input index.
    interface: Vec<(usize, F)>,
}

impl<F: Field> Form<F> {
    /// The `ONE` wire.
    const ONE_WIRE: Self = Self {
        plus: F::ZERO,
        minus: F::ZERO,
        one: F::ONE,
        interface: Vec::new(),
    };

    fn zero() -> Self {
        Self {
            plus: F::ZERO,
            minus: F::ZERO,
            one: F::ZERO,
            interface: Vec::new(),
        }
    }

    fn plus(value: F) -> Self {
        Self {
            plus: value,
            minus: F::ZERO,
            one: F::ZERO,
            interface: Vec::new(),
        }
    }

    fn minus(value: F) -> Self {
        Self {
            plus: F::ZERO,
            minus: value,
            one: F::ZERO,
            interface: Vec::new(),
        }
    }

    fn interface(index: usize) -> Self {
        Self {
            plus: F::ZERO,
            minus: F::ZERO,
            one: F::ZERO,
            interface: alloc::vec![(index, F::ONE)],
        }
    }

    fn scaled(mut self, s: F) -> Self {
        self.plus *= s;
        self.minus *= s;
        self.one *= s;
        for (_, v) in &mut self.interface {
            *v *= s;
        }
        self
    }

    /// `self += s * other`.
    fn add_scaled(&mut self, other: &Self, s: F) {
        self.plus += other.plus * s;
        self.minus += other.minus * s;
        self.one += other.one * s;
        for &(index, v) in &other.interface {
            match self.interface.binary_search_by_key(&index, |(i, _)| *i) {
                Ok(pos) => self.interface[pos].1 += v * s,
                Err(pos) => self.interface.insert(pos, (index, v * s)),
            }
        }
    }

    /// Evaluates the form at a placement with gate offset $m$ (`xm` $= x^m$,
    /// `xm_inv` $= x^{-m}$) and the given input wire values.
    pub(crate) fn evaluate(&self, xm: F, xm_inv: F, inputs: &[F]) -> F {
        let mut value = self.plus * xm + self.minus * xm_inv + self.one;
        for &(index, v) in &self.interface {
            value += v * inputs[index];
        }
        value
    }
}

/// Accumulator for linear combinations of [`Form`] wires.
pub(crate) struct FormSum<F: Field> {
    form: Form<F>,
    gain: Coeff<F>,
}

impl<F: Field> Default for FormSum<F> {
    fn default() -> Self {
        Self {
            form: Form::zero(),
            gain: Coeff::One,
        }
    }
}

impl<F: Field> LinearExpression<Form<F>, F> for FormSum<F> {
    fn add_term(mut self, wire: &Form<F>, coeff: Coeff<F>) -> Self {
        let coeff = coeff * self.gain;
        if !coeff.is_zero() {
            self.form.add_scaled(wire, coeff.value());
        }
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain = self.gain * coeff;
        self
    }
}

/// Horner accumulator over a routine's constraints, one scalar per basis
/// element. The input coefficients are dense: one slot per input wire.
#[derive(Clone, Debug)]
pub(crate) struct Pieces<F> {
    plus: F,
    minus: F,
    one: F,
    interface: Vec<F>,
}

impl<F: Field> Pieces<F> {
    fn zero(num_inputs: usize) -> Self {
        Self {
            plus: F::ZERO,
            minus: F::ZERO,
            one: F::ZERO,
            interface: alloc::vec![F::ZERO; num_inputs],
        }
    }

    /// One Horner step: `self = self * y + form`.
    fn step(&mut self, y: F, form: &Form<F>) {
        self.plus = self.plus * y + form.plus;
        self.minus = self.minus * y + form.minus;
        self.one = self.one * y + form.one;
        for v in &mut self.interface {
            *v *= y;
        }
        for &(index, v) in &form.interface {
            self.interface[index] += v;
        }
    }

    /// `self += s * other`.
    fn add_scaled(&mut self, other: &Self, s: F) {
        self.plus += other.plus * s;
        self.minus += other.minus * s;
        self.one += other.one * s;
        for (a, b) in self.interface.iter_mut().zip(&other.interface) {
            *a += *b * s;
        }
    }

    /// Evaluates the contribution at a placement with gate offset $m$,
    /// before the $y^{\ell}$ factor.
    pub(crate) fn evaluate(&self, xm: F, xm_inv: F, inputs: &[F]) -> F {
        debug_assert_eq!(self.interface.len(), inputs.len());
        let mut value = self.plus * xm + self.minus * xm_inv + self.one;
        for (h, w) in self.interface.iter().zip(inputs) {
            value += *h * *w;
        }
        value
    }
}

/// A routine's recorded, position-free contribution and output wires.
#[derive(Clone, Debug)]
pub(crate) struct Recorded<F> {
    /// Contribution of the routine and its nested sub-routines, relative to
    /// the routine's own placement.
    pub(crate) pieces: Pieces<F>,
    /// Output gadget wires as forms, in gadget traversal order.
    pub(crate) outputs: Vec<Form<F>>,
    /// Number of DFS segments spanned by the routine and its sub-routines.
    pub(crate) num_segments: usize,
}

/// Evaluation-point data the recorder shares with the `sxy` evaluator.
#[derive(Clone, Copy)]
pub(crate) struct Params<F> {
    pub(crate) x: F,
    pub(crate) x_inv: F,
    pub(crate) y: F,
    /// $x^{2n}$: starting $a$-wire monomial.
    pub(crate) base_a_x: F,
    /// $x^{2n-1}$: starting $b$-wire monomial.
    pub(crate) base_b_x: F,
    /// $x^{4n-1}$: starting $c$-wire monomial.
    pub(crate) base_c_x: F,
    /// $x^{-2n}$: converts an $a$-wire monomial into the $d$-wire one.
    pub(crate) a_to_d: F,
}

/// Per-routine state of the recorder, mirroring the `sxy` evaluator's scope
/// but in the relative frame.
struct Scope<F> {
    current_a: F,
    current_b: F,
    current_c: F,
    gates: usize,
    constraints: usize,
    /// Horner accumulator over this scope's own constraints.
    acc: Pieces<F>,
    /// Positioned contributions of nested routines.
    sum: Pieces<F>,
}

/// A [`Driver`] that evaluates one top-level routine in the relative frame
/// described in the [module documentation](self).
pub(crate) struct Recorder<'fp, F> {
    scope: Scope<F>,
    params: Params<F>,
    /// The circuit's floor plan; nested segments are placed relative to
    /// `origin`.
    floor_plan: &'fp [ConstraintSegment],
    /// Placement of the recorded routine's own segment.
    origin: (usize, usize),
    /// Index into `floor_plan` of the segment being executed.
    current_routine: usize,
    num_inputs: usize,
}

impl<F: Field> DriverTypes for Recorder<'_, F> {
    type MaybeKind = Empty;
    type LCadd = FormSum<F>;
    type LCenforce = FormSum<F>;
    type ImplField = F;
    type ImplWire = Form<F>;
    type Extra = Form<F>;

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Form<F>, Form<F>, Form<F>, Form<F>)> {
        self.scope.gates += 1;

        let a = Form::plus(self.scope.current_a);
        let b = Form::minus(self.scope.current_b);
        let c = Form::minus(self.scope.current_c);

        self.scope.current_a *= self.params.x;
        self.scope.current_b *= self.params.x_inv;
        self.scope.current_c *= self.params.x_inv;

        Ok((a.clone(), b, c, a))
    }

    fn assign_extra(&mut self, a: Form<F>, _: impl Fn() -> Result<Coeff<F>>) -> Result<Form<F>> {
        Ok(a.scaled(self.params.a_to_d))
    }
}

impl<'dr, F: Field> Driver<'dr> for Recorder<'_, F> {
    type F = F;
    type Wire = Form<F>;

    const ONE: Self::Wire = Form::ONE_WIRE;

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        lc(FormSum::default()).form
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        self.scope.constraints += 1;
        let form = lc(FormSum::default()).form;
        self.scope.acc.step(self.params.y, &form);
        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        self.current_routine += 1;
        let seg = &self.floor_plan[self.current_routine];
        let gate_start = seg.gate_start - self.origin.0;
        let constraint_start = seg.constraint_start - self.origin.1;

        let x_pow = self.params.x.pow_u64(gate_start as u64);
        let x_inv_pow = self.params.x_inv.pow_u64(gate_start as u64);
        let init_scope = Scope {
            current_a: self.params.base_a_x * x_pow,
            current_b: self.params.base_b_x * x_inv_pow,
            current_c: self.params.base_c_x * x_inv_pow,
            gates: gate_start,
            constraints: constraint_start,
            acc: Pieces::zero(self.num_inputs),
            sum: Pieces::zero(self.num_inputs),
        };

        let saved = core::mem::replace(&mut self.scope, init_scope);
        let exec_result = {
            let aux = Emulator::predict(&routine, &input)?.into_aux();
            routine.execute(self, input, aux)
        };

        assert_eq!(
            self.scope.gates,
            gate_start + seg.num_gates,
            "routine gate count must match floor plan"
        );
        assert_eq!(
            self.scope.constraints,
            constraint_start + seg.num_constraints,
            "routine constraint count must match floor plan"
        );

        // Fold the child as `sum += y^l * acc + sum_child`, with `l` relative
        // to the recorded routine's origin.
        let y_pow = self.params.y.pow_u64(constraint_start as u64);
        let child = core::mem::replace(&mut self.scope, saved);
        self.scope.sum.add_scaled(&child.acc, y_pow);
        self.scope.sum.add_scaled(&child.sum, F::ONE);

        exec_result
    }
}

/// Maps a caller's wires onto interface basis elements, remembering their
/// values in input order.
struct InterfaceMap<'fp, F, Src> {
    inputs: Vec<F>,
    _marker: PhantomData<(&'fp (), Src)>,
}

impl<'fp, F: Field, Src: DriverTypes<ImplField = F, ImplWire = F>> WireMap<F>
    for InterfaceMap<'fp, F, Src>
{
    type Src = Src;
    type Dst = Recorder<'fp, F>;

    fn convert_wire(&mut self, wire: &F) -> Result<Form<F>> {
        let index = self.inputs.len();
        self.inputs.push(*wire);
        Ok(Form::interface(index))
    }
}

/// Collects a gadget's wires as forms.
struct FormExtractor<'fp, F> {
    forms: Vec<Form<F>>,
    _marker: PhantomData<&'fp ()>,
}

impl<'fp, F: Field> WireMap<F> for FormExtractor<'fp, F> {
    type Src = Recorder<'fp, F>;
    type Dst = Emulator<Wireless<Empty, F>>;

    fn convert_wire(&mut self, wire: &Form<F>) -> Result<()> {
        self.forms.push(wire.clone());
        Ok(())
    }
}

/// Records the top-level routine whose segment is `floor_plan[index]`,
/// returning its position-free contribution and the values of its input
/// wires as seen by the caller.
pub(crate) fn record<'src, 'fp, F, Src, Ro>(
    routine: &Ro,
    input: &Bound<'src, Src, Ro::Input>,
    params: Params<F>,
    floor_plan: &'fp [ConstraintSegment],
    index: usize,
) -> Result<(Recorded<F>, Vec<F>)>
where
    F: Field,
    Src: Driver<'src, F = F, Wire = F, MaybeKind = Empty>,
    Ro: Routine<F>,
{
    let seg = &floor_plan[index];

    let mut interface = InterfaceMap::<'fp, F, Src> {
        inputs: Vec::new(),
        _marker: PhantomData,
    };
    let recorder_input = Ro::Input::map_gadget(input, &mut interface)?;
    let inputs = interface.inputs;
    let num_inputs = inputs.len();

    let mut recorder = Recorder {
        scope: Scope {
            current_a: params.base_a_x,
            current_b: params.base_b_x,
            current_c: params.base_c_x,
            gates: 0,
            constraints: 0,
            acc: Pieces::zero(num_inputs),
            sum: Pieces::zero(num_inputs),
        },
        params,
        floor_plan,
        origin: (seg.gate_start, seg.constraint_start),
        current_routine: index,
        num_inputs,
    };

    let aux = Emulator::predict(routine, input)?.into_aux();
    let output = routine.execute(&mut recorder, recorder_input, aux)?;

    assert_eq!(
        recorder.scope.gates, seg.num_gates,
        "routine gate count must match floor plan"
    );
    assert_eq!(
        recorder.scope.constraints, seg.num_constraints,
        "routine constraint count must match floor plan"
    );

    let mut extractor = FormExtractor::<'fp, F> {
        forms: Vec::new(),
        _marker: PhantomData,
    };
    Ro::Output::map_gadget(&output, &mut extractor)?;

    let mut pieces = recorder.scope.acc;
    pieces.add_scaled(&recorder.scope.sum, F::ONE);

    Ok((
        Recorded {
            pieces,
            outputs: extractor.forms,
            num_segments: recorder.current_routine - index + 1,
        },
        inputs,
    ))
}
