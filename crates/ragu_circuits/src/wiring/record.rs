//! Position-free recording of a routine's contribution to $s(X, Y)$.
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
//! One run of the recorder produces every view the wiring evaluators need,
//! since a memo cache only ever lives for one fixed evaluation point:
//!
//! - `sxy`: the Horner-folded [`Pieces`];
//! - `sx`: every constraint's [`Form`] in emission order, per segment, since
//!   $s(x, Y)$ has one coefficient per constraint;
//! - `sy`: one scalar per wire, $\sum_k c_k y^{\text{power}(k)}$ with powers
//!   relative to the block, since $s(X, y)$ has one coefficient per wire.
//!
//! A [`Recorded`] routine can then be replayed at any placement with any
//! inputs, which is what makes it reusable within and across circuits.

use alloc::{collections::BTreeMap, vec::Vec};
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

/// A wire allocated inside a recorded block, by relative gate index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum WireRef {
    /// The $a$ wire of relative gate `i`.
    A(usize),
    /// The $b$ wire of relative gate `i`.
    B(usize),
    /// The $c$ wire of relative gate `i`.
    C(usize),
    /// The $d$ wire of relative gate `i`.
    D(usize),
}

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
    /// Coefficients of the block's own wires, sorted by wire.
    positional: Vec<(WireRef, F)>,
}

impl<F: Field> Form<F> {
    /// The `ONE` wire.
    const ONE_WIRE: Self = Self {
        plus: F::ZERO,
        minus: F::ZERO,
        one: F::ONE,
        interface: Vec::new(),
        positional: Vec::new(),
    };

    fn zero() -> Self {
        Self {
            plus: F::ZERO,
            minus: F::ZERO,
            one: F::ZERO,
            interface: Vec::new(),
            positional: Vec::new(),
        }
    }

    /// A wire of the $x^{+m}$ family with monomial `value`.
    fn plus(wire: WireRef, value: F) -> Self {
        Self {
            plus: value,
            positional: alloc::vec![(wire, F::ONE)],
            ..Self::zero()
        }
    }

    /// A wire of the $x^{-m}$ family with monomial `value`.
    fn minus(wire: WireRef, value: F) -> Self {
        Self {
            minus: value,
            positional: alloc::vec![(wire, F::ONE)],
            ..Self::zero()
        }
    }

    fn interface(index: usize) -> Self {
        Self {
            interface: alloc::vec![(index, F::ONE)],
            ..Self::zero()
        }
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
        for &(wire, v) in &other.positional {
            match self.positional.binary_search_by_key(&wire, |(w, _)| *w) {
                Ok(pos) => self.positional[pos].1 += v * s,
                Err(pos) => self.positional.insert(pos, (wire, v * s)),
            }
        }
    }

    /// Evaluates the form at a placement with gate offset $m$ (`xm` $= x^m$,
    /// `xm_inv` $= x^{-m}$) and the given input wire values.
    pub(crate) fn evaluate(&self, xm: F, xm_inv: F, inputs: &[F]) -> F {
        self.evaluate_internal(xm, xm_inv) + self.evaluate_interface(inputs)
    }

    /// The part of the form that depends only on the placement: the block's
    /// own wires and `ONE`.
    pub(crate) fn evaluate_internal(&self, xm: F, xm_inv: F) -> F {
        self.plus * xm + self.minus * xm_inv + self.one
    }

    /// The part of the form that depends on the caller's input wires.
    pub(crate) fn evaluate_interface(&self, inputs: &[F]) -> F {
        let mut value = F::ZERO;
        for &(index, v) in &self.interface {
            value += v * inputs[index];
        }
        value
    }

    /// The form's terms by wire identity: the block's own wires, then the
    /// `ONE` wire if referenced, then input wires by index. Used to rebuild
    /// a wire handle at a placement.
    pub(crate) fn terms(&self) -> impl Iterator<Item = (Term, F)> + '_ {
        let own = self.positional.iter().map(|&(w, v)| (Term::Wire(w), v));
        let one = (self.one != F::ZERO).then_some((Term::One, self.one));
        let inputs = self.interface.iter().map(|&(j, v)| (Term::Input(j), v));
        own.chain(one).chain(inputs)
    }
}

/// A term of a [`Form`] by wire identity.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Term {
    /// One of the block's own wires.
    Wire(WireRef),
    /// The `ONE` wire.
    One,
    /// The caller's `j`-th input wire.
    Input(usize),
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

/// The constraint forms of one segment of a recorded block.
#[derive(Clone, Debug)]
pub(crate) struct SegmentForms<F> {
    /// Constraint offset relative to the block's origin.
    pub(crate) constraint_start: usize,
    /// One form per constraint, in emission order.
    pub(crate) forms: Vec<Form<F>>,
}

/// Per-wire coefficients of $s(X, y)$ for a recorded block, with $Y$-powers
/// relative to the block's constraint offset.
#[derive(Clone, Debug)]
pub(crate) struct WireSums<F> {
    /// The block's own wires.
    pub(crate) own: Vec<(WireRef, F)>,
    /// The `ONE` wire.
    pub(crate) one: F,
    /// The input wires, by index.
    pub(crate) inputs: Vec<F>,
}

/// A routine's recorded, position-free contribution and output wires.
#[derive(Clone, Debug)]
pub(crate) struct Recorded<F> {
    /// Contribution of the routine and its nested sub-routines, relative to
    /// the routine's own placement (`sxy` view).
    pub(crate) pieces: Pieces<F>,
    /// Every segment's constraints (`sx` view).
    pub(crate) constraints: Vec<SegmentForms<F>>,
    /// Per-wire coefficients (`sy` view).
    pub(crate) wires: WireSums<F>,
    /// Output gadget wires as forms, in gadget traversal order.
    pub(crate) outputs: Vec<Form<F>>,
    /// Number of DFS segments spanned by the routine and its sub-routines.
    pub(crate) num_segments: usize,
}

/// Evaluation-point data the recorder shares with the wiring evaluators.
/// An evaluator that fixes only one variable passes zero for the other; the
/// corresponding view of the recording is then unused.
#[derive(Clone, Copy)]
pub(crate) struct Params<F> {
    pub(crate) x: F,
    pub(crate) x_inv: F,
    pub(crate) y: F,
    pub(crate) y_inv: F,
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
    /// $y$-power of the next constraint, relative to the block.
    current_y: F,
    gates: usize,
    constraints: usize,
    /// Constraint offset of this scope relative to the block's origin.
    constraint_start: usize,
    /// Horner accumulator over this scope's own constraints.
    acc: Pieces<F>,
    /// Positioned contributions of nested routines.
    sum: Pieces<F>,
    /// Constraint forms of this scope, in emission order.
    forms: Vec<Form<F>>,
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
    /// Constraint forms of every finished nested segment.
    segments: Vec<SegmentForms<F>>,
    /// Per-wire $s(X, y)$ coefficients of the whole block.
    own_wires: BTreeMap<WireRef, F>,
    one_wire: F,
    input_wires: Vec<F>,
}

impl<F: Field> Recorder<'_, F> {
    /// $y$-power of the first constraint of a segment with `num_constraints`
    /// constraints starting at `constraint_start` (relative): constraints are
    /// emitted from the highest power down.
    fn first_power(&self, constraint_start: usize, num_constraints: usize) -> F {
        if num_constraints == 0 {
            F::ZERO
        } else {
            self.params
                .y
                .pow_u64((constraint_start + num_constraints - 1) as u64)
        }
    }
}

impl<F: Field> DriverTypes for Recorder<'_, F> {
    type MaybeKind = Empty;
    type LCadd = FormSum<F>;
    type LCenforce = FormSum<F>;
    type ImplField = F;
    type ImplWire = Form<F>;
    /// Relative gate index and the $a$-wire monomial of that gate.
    type Extra = (usize, F);

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Form<F>, Form<F>, Form<F>, (usize, F))> {
        let index = self.scope.gates;
        self.scope.gates += 1;

        let a_monomial = self.scope.current_a;
        let a = Form::plus(WireRef::A(index), a_monomial);
        let b = Form::minus(WireRef::B(index), self.scope.current_b);
        let c = Form::minus(WireRef::C(index), self.scope.current_c);

        self.scope.current_a *= self.params.x;
        self.scope.current_b *= self.params.x_inv;
        self.scope.current_c *= self.params.x_inv;

        Ok((a, b, c, (index, a_monomial)))
    }

    fn assign_extra(
        &mut self,
        (index, a_monomial): (usize, F),
        _: impl Fn() -> Result<Coeff<F>>,
    ) -> Result<Form<F>> {
        Ok(Form::plus(
            WireRef::D(index),
            a_monomial * self.params.a_to_d,
        ))
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

        // sxy view: Horner over this scope.
        self.scope.acc.step(self.params.y, &form);

        // sy view: this constraint's power times each wire's coefficient.
        let power = self.scope.current_y;
        for &(wire, v) in &form.positional {
            *self.own_wires.entry(wire).or_insert(F::ZERO) += v * power;
        }
        self.one_wire += form.one * power;
        for &(index, v) in &form.interface {
            self.input_wires[index] += v * power;
        }
        self.scope.current_y *= self.params.y_inv;

        // sx view: the form itself.
        self.scope.forms.push(form);
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
            current_y: self.first_power(constraint_start, seg.num_constraints),
            gates: gate_start,
            constraints: constraint_start,
            constraint_start,
            acc: Pieces::zero(self.num_inputs),
            sum: Pieces::zero(self.num_inputs),
            forms: Vec::with_capacity(seg.num_constraints),
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
        self.segments.push(SegmentForms {
            constraint_start: child.constraint_start,
            forms: child.forms,
        });

        exec_result
    }
}

/// Maps a caller's wires onto interface basis elements, remembering a
/// caller-chosen projection of each in input order.
struct InterfaceMap<'fp, F, Src, V, Conv> {
    inputs: Vec<V>,
    conv: Conv,
    _marker: PhantomData<(&'fp (), F, Src)>,
}

impl<'fp, F, Src, V, Conv> WireMap<F> for InterfaceMap<'fp, F, Src, V, Conv>
where
    F: Field,
    Src: DriverTypes<ImplField = F>,
    Conv: Fn(&Src::ImplWire) -> V,
{
    type Src = Src;
    type Dst = Recorder<'fp, F>;

    fn convert_wire(&mut self, wire: &Src::ImplWire) -> Result<Form<F>> {
        let index = self.inputs.len();
        self.inputs.push((self.conv)(wire));
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
/// returning its position-free contribution and `conv` applied to each of
/// its input wires, in input order.
pub(crate) fn record<'src, 'fp, F, Src, Ro, V>(
    routine: &Ro,
    input: &Bound<'src, Src, Ro::Input>,
    params: Params<F>,
    floor_plan: &'fp [ConstraintSegment],
    index: usize,
    conv: impl Fn(&Src::ImplWire) -> V,
) -> Result<(Recorded<F>, Vec<V>)>
where
    F: Field,
    Src: Driver<'src, F = F, MaybeKind = Empty>,
    Ro: Routine<F>,
{
    let seg = &floor_plan[index];

    let mut interface = InterfaceMap::<'fp, F, Src, V, _> {
        inputs: Vec::new(),
        conv,
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
            current_y: F::ZERO,
            gates: 0,
            constraints: 0,
            constraint_start: 0,
            acc: Pieces::zero(num_inputs),
            sum: Pieces::zero(num_inputs),
            forms: Vec::with_capacity(seg.num_constraints),
        },
        params,
        floor_plan,
        origin: (seg.gate_start, seg.constraint_start),
        current_routine: index,
        num_inputs,
        segments: Vec::new(),
        own_wires: BTreeMap::new(),
        one_wire: F::ZERO,
        input_wires: alloc::vec![F::ZERO; num_inputs],
    };
    recorder.scope.current_y = recorder.first_power(0, seg.num_constraints);

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

    let num_segments = recorder.current_routine - index + 1;
    let Scope {
        acc, sum, forms, ..
    } = recorder.scope;
    let mut pieces = acc;
    pieces.add_scaled(&sum, F::ONE);
    let mut constraints = recorder.segments;
    constraints.push(SegmentForms {
        constraint_start: 0,
        forms,
    });

    Ok((
        Recorded {
            pieces,
            constraints,
            wires: WireSums {
                own: recorder.own_wires.into_iter().collect(),
                one: recorder.one_wire,
                inputs: recorder.input_wires,
            },
            outputs: extractor.forms,
            num_segments,
        },
        inputs,
    ))
}
