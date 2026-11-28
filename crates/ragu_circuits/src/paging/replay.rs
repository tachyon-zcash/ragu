//! What a page runs: the steps that a plan compiles for a page and for the
//! routines it calls, and the replay of those steps on a driver.
//!
//! The pager writes the steps, and nothing of them is trusted. The replay
//! is part of what a page's soundness rests on: it gives each name of a
//! step its wire, refuses a name that the page does not hold, and calls a
//! routine through [`Driver::routine`].
//!
//! "Replay" here is of a recording: every gate is allocated and every
//! constraint is enforced again, on the driver the page is run on. It is
//! not the replay the book describes for a driver that memoizes routines,
//! which skips a routine's body on a cache hit and adds what it kept of
//! it. A [`Replayed`] routine is one such a driver could memoize, as it
//! could the routine of the circuit.

use alloc::{sync::Arc, vec::Vec};

use ragu_core::{
    Coeff, Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Gadget, Kind, WireStream},
    maybe::Maybe,
    routines::{Prediction, Routine},
};
use udon::field::Field;

use super::{ONE, VIRTUAL, diverged};

/// The wires a step names, each with its coefficient.
pub(super) type Terms<F> = Vec<(u32, Coeff<F>)>;

/// One thing a page does, or a routine it calls: one call to the
/// [`Driver`] method its variant is named after ([`Gates`](Self::Gates)
/// is so many calls to `Driver::gate`).
///
/// A step names wires of what runs it. For a page: [`ONE`]; the $a$ and
/// $d$ wires of a gate of the stages or of the carry stage, and the wires
/// of a gate of the page's own that a step before it allocated, each
/// `4 * gate + kind` with the gate counted as the page's steps allocate
/// them, after the SYSTEM gate and the stages'; and a virtual wire that a
/// step before it made, by [`VIRTUAL`] and its place among those the steps
/// make. For a routine ([`Body`]) likewise, without the stages: its own
/// gates are counted from one, and its inputs are its first virtual wires.
///
/// The gates a routine allocates are not the caller's to name: the caller
/// names the routine's outputs, which are virtual wires of the caller's.
#[derive(Clone, Debug)]
pub(super) enum Step<F: Field> {
    /// Allocates this many gates of the page's own, or of the routine's,
    /// the next ones.
    Gates(usize),
    /// Makes a virtual wire of the terms. For a page, it is what a
    /// virtual wire of the circuit's has of the page's wires, or of the
    /// page's own gates' among them, or a wire a routine takes.
    Add(Terms<F>),
    /// Enforces that the terms sum to zero.
    EnforceZero(Terms<F>),
    /// Calls a routine on the wires named, as a routine of the driver's,
    /// and makes a virtual wire of each wire of its output.
    Routine(Arc<Body<F>>, Vec<u32>),
}

/// A routine the circuit calls, as the page that holds it calls it: what
/// the routine allocates and enforces, taken off a walk of the circuit and
/// apart from where the circuit calls it.
///
/// A page calls it through [`Driver::routine`], so that the routine is a
/// segment of the page as it is of the circuit: the same gates, the same
/// constraints and the same calls within, in the same order, over the same
/// inputs.
#[derive(Clone, Debug)]
pub(super) struct Body<F: Field> {
    /// The wires of its input.
    inputs: usize,
    /// What it does, in order.
    steps: Vec<Step<F>>,
    /// The wires of its output, each named as a step names a wire.
    outputs: Vec<u32>,
    /// The gates it allocates, those of the routines it calls included.
    gates: usize,
    /// The constraints it enforces, likewise.
    constraints: usize,
}

impl<F: Field> Body<F> {
    /// A routine that takes `inputs` wires, runs `steps` and gives
    /// `outputs`.
    pub(super) fn new(inputs: usize, steps: Vec<Step<F>>, outputs: Vec<u32>) -> Self {
        let (gates, constraints) = counts(&steps);
        Body {
            inputs,
            steps,
            outputs,
            gates,
            constraints,
        }
    }
}

#[cfg(test)]
impl<F: Field> Body<F> {
    /// The routine with its steps as `change` leaves them, for a test: it
    /// is counted anew, as the pager's are.
    pub(super) fn changed(&self, change: impl FnOnce(&mut Vec<Step<F>>)) -> Self {
        let mut steps = self.steps.clone();
        change(&mut steps);
        Body::new(self.inputs, steps, self.outputs.clone())
    }
}

/// The gates `steps` allocate and the constraints they enforce, those of
/// the routines they call included.
fn counts<F: Field>(steps: &[Step<F>]) -> (usize, usize) {
    steps
        .iter()
        .fold((0, 0), |(gates, constraints), step| match step {
            Step::Gates(own) => (gates + own, constraints),
            Step::Add(_) => (gates, constraints),
            Step::EnforceZero(_) => (gates, constraints + 1),
            Step::Routine(body, _) => (gates + body.gates, constraints + body.constraints),
        })
}

/// What one page allocates and enforces, taken off the plan and a walk of
/// the circuit: the page replays it on any driver, and walks no part of the
/// circuit that another page holds.
#[derive(Clone, Debug)]
pub(super) struct Program<F: Field> {
    /// What the page does, in order. Its first step allocates the gates
    /// of its own that no routine it calls allocates.
    pub(super) steps: Vec<Step<F>>,
    /// The virtual wires the steps make, counted: the next one a step
    /// makes is named by this.
    pub(super) virtuals: u32,
    /// The wires of the public output, on the last page: each a virtual
    /// wire over the page's wires, made after its steps.
    pub(super) outputs: Vec<Terms<F>>,
}

impl<F: Field> Program<F> {
    /// A page that allocates `own` gates outside any routine, and does
    /// nothing yet.
    pub(super) fn new(own: usize) -> Self {
        Program {
            steps: alloc::vec![Step::Gates(own)],
            virtuals: 0,
            outputs: Vec::new(),
        }
    }

    /// Makes a virtual wire of `terms`, and gives its name.
    pub(super) fn add(&mut self, terms: Terms<F>) -> u32 {
        self.steps.push(Step::Add(terms));
        self.virtuals += 1;
        VIRTUAL | (self.virtuals - 1)
    }

    /// Enforces that `terms` sum to zero.
    pub(super) fn enforce_zero(&mut self, terms: Terms<F>) {
        self.steps.push(Step::EnforceZero(terms));
    }

    /// Calls a routine on the wires `inputs` name, and gives the wire that
    /// names the first wire of its output: the others follow it.
    pub(super) fn routine(&mut self, body: Arc<Body<F>>, inputs: Vec<u32>) -> u32 {
        let first = self.virtuals;
        self.virtuals += u32::try_from(body.outputs.len()).expect("outputs fit a wire");
        self.steps.push(Step::Routine(body, inputs));
        VIRTUAL | first
    }

    /// The gates of its own the page allocates, past the carry stage:
    /// those of the routines it calls included.
    pub(super) fn gates(&self) -> usize {
        counts(&self.steps).0
    }

    /// The constraints the page enforces, before those of its output:
    /// those of the routines it calls included.
    pub(super) fn constraints(&self) -> usize {
        counts(&self.steps).1
    }
}

#[cfg(test)]
impl<F: Field> Program<F> {
    /// The gates the page's first step allocates, for a test to change.
    pub(super) fn own_mut(&mut self) -> &mut usize {
        match &mut self.steps[0] {
            Step::Gates(gates) => gates,
            _ => panic!("a page allocates its gates first"),
        }
    }

    /// The place among the steps of each constraint the page enforces.
    pub(super) fn enforced(&self) -> Vec<usize> {
        (0..self.steps.len())
            .filter(|&step| matches!(self.steps[step], Step::EnforceZero(_)))
            .collect()
    }

    /// The page's `index`-th constraint.
    pub(super) fn constraint(&mut self, index: usize) -> &mut Terms<F> {
        let step = self.enforced()[index];
        match &mut self.steps[step] {
            Step::EnforceZero(terms) => terms,
            _ => unreachable!("a constraint"),
        }
    }

    /// Takes the page's `index`-th constraint off it.
    pub(super) fn drop_constraint(&mut self, index: usize) -> Terms<F> {
        let step = self.enforced()[index];
        match self.steps.remove(step) {
            Step::EnforceZero(terms) => terms,
            _ => unreachable!("a constraint"),
        }
    }

    /// The first virtual wire the page makes.
    pub(super) fn first_add(&mut self) -> &mut Terms<F> {
        self.steps
            .iter_mut()
            .find_map(|step| match step {
                Step::Add(terms) => Some(terms),
                _ => None,
            })
            .expect("the page makes a combination")
    }
}

/// The wires the steps of a page, or of a routine it calls, have names
/// for: what the replay keeps for one of them, as a driver keeps a scope
/// for each routine.
struct Scope<'a, W> {
    one: W,
    /// The wires of the stages' and the carry stage's gates, two a gate,
    /// which the page's stage builder reserved. A routine has none.
    reserved: &'a [W],
    /// The wires of the gates of its own that the steps allocated so far.
    gates: Vec<[W; 4]>,
    /// The virtual wires the steps made so far: for a routine, after its
    /// inputs.
    virtuals: Vec<W>,
}

impl<W: Clone> Scope<'_, W> {
    /// The wire `name` names, if the steps hold it by now: `ONE`, the $a$
    /// or the $d$ wire of a reserved gate, which hold a stage's values, a
    /// wire of a gate of their own, or a virtual wire a step made.
    fn wire(&self, name: u32) -> Option<&W> {
        if name & VIRTUAL != 0 {
            return self.virtuals.get((name ^ VIRTUAL) as usize);
        }
        // The page's own gates start past the reserved ones.
        let first = self.reserved.len() / 2 + 1;
        match (name / 4) as usize {
            0 => (name == ONE).then_some(&self.one),
            gate if gate < first => matches!(name % 4, 0 | 3)
                .then(|| &self.reserved[2 * (gate - 1) + usize::from(name % 4 == 3)]),
            gate => Some(&self.gates.get(gate - first)?[(name % 4) as usize]),
        }
    }

    /// Refuses terms that name a wire the page does not hold by now. A
    /// program that names one is not one a plan of a circuit over stages
    /// compiles, and nothing of the plan is trusted.
    fn holds<F: Field>(&self, terms: &[(u32, Coeff<F>)]) -> Result<()> {
        if terms.iter().all(|&(name, _)| self.wire(name).is_some()) {
            Ok(())
        } else {
            Err(diverged("a page names a wire it does not hold"))
        }
    }

    /// The linear combination of `terms`, which the page [holds].
    ///
    /// [holds]: Self::holds
    fn combine<F: Field, L: LinearExpression<W, F>>(&self, lc: L, terms: &[(u32, Coeff<F>)]) -> L {
        terms.iter().fold(lc, |lc, &(name, coeff)| {
            lc.add_term(self.wire(name).expect("the page holds the wire"), coeff)
        })
    }
}

/// The input gadget of a [`Replayed`] routine: the wires of the input of
/// the routine it replays, in the order that routine's input gadget gives
/// them, and with a witness the values of the gates the routine allocates.
///
/// The circuit's routines take gadgets of their own types, which a page
/// does not have: it replays a recording and does not run the circuit's
/// code. A routine's fingerprint is of the wires it takes and gives and of
/// what it emits, and not of their types, so the wires in the same order
/// are the same input to every driver. Their number is the routine's, and
/// is known only once the circuit is cut, so they are a [`WireStream`]. It
/// is the one stream this gadget holds, and its length is the recording's:
/// no witness changes it.
#[derive(Gadget)]
struct InputWires<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    wires: WireStream<'dr, D>,
    #[ragu(value)]
    values: DriverValue<D, Arc<[[D::F; 4]]>>,
}

/// A routine the circuit calls, as a routine of the page that holds it: it
/// replays the routine's recorded [`Body`] on any driver.
///
/// It is the same routine to a driver as the one the circuit calls: it
/// takes the same wires, allocates the same gates, enforces the same
/// constraints and calls the same routines, in the same order, and gives
/// the same wires. Its output is not predicted.
struct Replayed<F: Field>(Arc<Body<F>>);

impl<F: Field> Clone for Replayed<F> {
    fn clone(&self) -> Self {
        Replayed(self.0.clone())
    }
}

impl<F: Field> Routine<F> for Replayed<F> {
    type Input = Kind![F; InputWires<'_, _>];
    type Output = Kind![F; WireStream<'_, _>];
    type Aux<'dr> = Arc<[[F; 4]]>;

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let body = &*self.0;
        if input.wires.len() != body.inputs {
            return Err(diverged("a routine is given other wires than it takes"));
        }
        let mut scope = Scope {
            one: D::ONE,
            reserved: &[],
            gates: Vec::new(),
            virtuals: input.wires.into_iter().collect(),
        };
        let values = aux.as_ref().map(|values| &values[..]);
        run(&body.steps, dr, &mut scope, &values, &mut 0)?;
        body.outputs
            .iter()
            .map(|&name| {
                let wire = scope.wire(name).cloned();
                wire.ok_or_else(|| diverged("a routine gives a wire it does not hold"))
            })
            .collect()
    }

    fn predict<'dr, D: Driver<'dr, F = F, Wire = ()>>(
        &self,
        _: &mut D,
        input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::just(|| {
            input.values.as_ref().take().clone()
        })))
    }
}

/// Runs `steps` on `dr`, over the wires of `scope`, which takes what they
/// allocate and make. `values` are those of the gates the steps allocate,
/// those of the routines they call included, in order, and `next` the
/// first that the steps have yet to allocate.
fn run<'dr, D: Driver<'dr>>(
    steps: &[Step<D::F>],
    dr: &mut D,
    scope: &mut Scope<'_, D::Wire>,
    values: &DriverValue<D, &[[D::F; 4]]>,
    next: &mut usize,
) -> Result<()> {
    for step in steps {
        match step {
            Step::Gates(gates) => {
                for _ in 0..*gates {
                    let gate = *next;
                    *next += 1;
                    let value = |kind: usize| {
                        values
                            .snag()
                            .get(gate)
                            .map(|values| Coeff::Arbitrary(values[kind]))
                            .ok_or_else(|| {
                                diverged("a page was given too few of its gates' values")
                            })
                    };
                    let (a, b, c, extra) = dr.gate(|| Ok((value(0)?, value(1)?, value(2)?)))?;
                    let d = dr.assign_extra(extra, || value(3))?;
                    scope.gates.push([a, b, c, d]);
                }
            }
            Step::Add(terms) => {
                scope.holds(terms)?;
                let wire = dr.add(|lc| scope.combine(lc, terms));
                scope.virtuals.push(wire);
            }
            Step::EnforceZero(terms) => {
                scope.holds(terms)?;
                dr.enforce_zero(|lc| scope.combine(lc, terms))?;
            }
            Step::Routine(body, inputs) => {
                let wires = inputs
                    .iter()
                    .map(|&name| scope.wire(name).cloned())
                    .collect::<Option<WireStream<'dr, D>>>()
                    .ok_or_else(|| diverged("a page names a wire it does not hold"))?;
                // The routine's gates are the next ones: it is given their
                // values, and allocates them as a segment of its own.
                let gates = *next..*next + body.gates;
                *next = gates.end;
                let values =
                    D::try_just(|| {
                        values.snag().get(gates).map(Arc::from).ok_or_else(|| {
                            diverged("a page was given too few of its gates' values")
                        })
                    })?;
                let output = dr.routine(Replayed(body.clone()), InputWires { wires, values })?;
                scope.virtuals.extend(output);
            }
        }
    }
    Ok(())
}

impl<F: Field> Program<F> {
    /// Runs the page's steps on `dr`: allocates the page's own gates, with
    /// `values`, makes its virtual wires, enforces its constraints and
    /// calls the routines it holds.
    /// `reserved` are the wires of the stages' and the carry stage's gates,
    /// two a gate, which the page's stage builder reserved. Gives the wires
    /// of the public output, which only the last page has.
    pub(super) fn replay<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        reserved: &[D::Wire],
        values: &DriverValue<D, &[[F; 4]]>,
    ) -> Result<Vec<D::Wire>> {
        let mut scope = Scope {
            one: D::ONE,
            reserved,
            gates: Vec::new(),
            virtuals: Vec::with_capacity(self.virtuals as usize),
        };
        run(&self.steps, dr, &mut scope, values, &mut 0)?;
        self.outputs
            .iter()
            .map(|terms| {
                scope.holds(terms)?;
                Ok(dr.add(|lc| scope.combine(lc, terms)))
            })
            .collect()
    }
}
