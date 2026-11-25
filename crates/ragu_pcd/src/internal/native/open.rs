//! The opening program: what [`compute_v`] computes, as a list of steps a
//! profile can spread over several circuits.
//!
//! [`compute_v`] recomputes the claimed batch evaluation $v$ in one
//! circuit: it folds the evaluations of every claim into $a(xz)$ and
//! $b(x)$, accumulates the quotient of every opening into $f(u)$, and
//! weighs every evaluation at $u$ into $v$. Each of the three takes a step
//! per polynomial of the children's proofs, so the circuit grows with the
//! proofs, and a profile whose proofs carry many polynomials has a
//! `compute_v` past the rank's gate budget.
//!
//! Such a profile ([`Chunking`](crate::profile::Chunking)) runs the same
//! computation as a *program*: the list of [`Op`]s that [`program`] lays
//! out, over a [`State`] of six running values. The
//! [`open`](super::circuits::open) circuits each run a contiguous window of
//! the program ([`Schedule`]), from the state the window before left to the
//! state the next takes up, which the [`carry`](super::stages::open) stage
//! holds between them. The program is the computation `compute_v` makes, in
//! the same order, so the value it ends in is the same $v$:
//!
//! 1. **The fold.** The claims' evaluations in [`claims::build`] order,
//!    laid out over the grid as
//!    [`revdot::randomized`](crate::internal::revdot::randomized) lays them
//!    out: each group's claims weighed by the first layer's interpolation
//!    weights, then the group, with the fold randomizer's evaluation at its
//!    last node, weighed by the second layer's.
//! 2. **The quotients.** The openings in the prover's order: the static
//!    prefix, every rx polynomial of each child at $xz$, the registry at
//!    every internal circuit's $\omega^j$, then the online openings.
//! 3. **The evaluations.** $f(u)$ and then every evaluation at $u$, in the
//!    order the eval stage writes them.
//!
//! # Inputs
//!
//! A step reads evaluations the `query` and `eval` stages hold, named by
//! [`Input`]. The circuits that run the program cannot reserve those
//! stages, which hold every evaluation of the proofs: each circuit reads
//! copies of the inputs its window takes, in a polynomial of the
//! [`band`](super::stages::open) stage of its own, and a
//! [`open_loading`](super::circuits::open_loading) bonding holds every
//! copy to the stage wire it copies. The copies are committed with the
//! circuits' polynomials; what they copy is fixed in the transcript, by the
//! stages.
//!
//! [`compute_v`]: super::circuits::compute_v

use alloc::{collections::BTreeMap, vec, vec::Vec};

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, vec::Len};

use super::{
    FOLD_GROUP_SIZE, InternalCircuitIndex, NumFoldGroups, RxComponent, RxIndex,
    claims::{self, Processor},
    online::NUM_ONLINE_FP_QUERIES,
    pcs::{STATIC_F_QUERIES, StaticFQuery},
};
use crate::{
    internal::{
        Side,
        inverter::Inverter,
        revdot::{self, Source},
    },
    profile::{
        Profile,
        online::stages::{Nested, PhaseCoordinatesLen, Present},
    },
};

/// A value of the `query` stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryValue {
    /// The registry's evaluation at an internal circuit's $\omega^j$.
    Fixed(InternalCircuitIndex),
    /// A child's rx polynomial at $xz$.
    Rx(Side, RxIndex),
    /// A child's $a$ at $xz$.
    AAtXz(Side),
    /// A child's $b$ at $x$.
    BAtX(Side),
    /// A child's `registry_xy` at the step's $w$.
    ChildRegistryXyAtW(Side),
    /// The step's `registry_wy` at a child's $x$.
    RegistryWyAtChildX(Side),
    /// $m(w, x, y)$.
    RegistryWxy,
    /// The step's `registry_xy` at its own circuit id.
    RegistryXyAtCircuitId,
    /// The step's own application rx at $xz$.
    ApplicationAtXz,
    /// The step's own application stage rx at $xz$.
    ApplicationStageAtXz,
    /// The step's fold randomizer $a_r$ at $xz$.
    RandomizerAAtXz,
    /// The step's fold randomizer $b_r$ at $x$.
    RandomizerBAtX,
    /// A coordinate of the nested online query-stage commitment.
    OnlineStage(usize),
    /// A coordinate of a nested online auxiliary.
    OnlineAuxiliary(usize),
}

/// A value of the `eval` stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvalValue {
    /// A child's rx polynomial at $u$.
    Rx(Side, RxIndex),
    /// A child's $a$ at $u$.
    A(Side),
    /// A child's $b$ at $u$.
    B(Side),
    /// A child's `registry_xy` at $u$.
    RegistryXy(Side),
    /// A child's $p$ at $u$.
    P(Side),
    /// The step's `registry_wx0` at $u$.
    RegistryWx0,
    /// The step's `registry_wx1` at $u$.
    RegistryWx1,
    /// The step's own application rx at $u$.
    Application,
    /// The step's own application stage rx at $u$.
    ApplicationStage,
    /// The step's `registry_wy` at $u$.
    RegistryWy,
    /// The step's $a$ at $u$.
    OwnA,
    /// The step's $b$ at $u$.
    OwnB,
    /// The step's `registry_xy` at $u$.
    OwnRegistryXy,
    /// The step's fold randomizer $a_r$ at $u$.
    RandomizerA,
    /// The step's fold randomizer $b_r$ at $u$.
    RandomizerB,
    /// The step's batch randomizer at $u$.
    Mask,
    /// An online slot's polynomial at $u$.
    Online(usize),
    /// A coordinate of the nested online eval-stage commitment.
    OnlineStage(usize),
}

/// A value of the `query` or `eval` stage that a step of the program
/// reads, or that `compute_v` exports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Input {
    /// A value of the `query` stage.
    Query(QueryValue),
    /// A value of the `eval` stage.
    Eval(EvalValue),
}

/// The eval stage's evaluations in the order it writes them: the order
/// they are weighed into $v$.
pub fn evaluations<P: Profile>() -> Vec<EvalValue> {
    let mut order = Vec::new();
    for side in [Side::Left, Side::Right] {
        order.extend(
            RxIndex::all::<P>()
                .into_iter()
                .map(|id| EvalValue::Rx(side, id)),
        );
        order.extend([
            EvalValue::A(side),
            EvalValue::B(side),
            EvalValue::RegistryXy(side),
            EvalValue::P(side),
        ]);
    }
    order.extend([
        EvalValue::RegistryWx0,
        EvalValue::RegistryWx1,
        EvalValue::Application,
        EvalValue::ApplicationStage,
        EvalValue::RegistryWy,
        EvalValue::OwnA,
        EvalValue::OwnB,
        EvalValue::OwnRegistryXy,
        EvalValue::RandomizerA,
        EvalValue::RandomizerB,
        EvalValue::Mask,
    ]);
    order.extend((0..NUM_ONLINE_FP_QUERIES).map(EvalValue::Online));
    order
}

/// The value an opening claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Term {
    /// A value a stage holds.
    Input(Input),
    /// A child's batch evaluation $v$, from the preamble.
    ChildV(Side),
    /// The value of an online opening, from the preamble.
    OnlineY(usize),
    /// The folded $a(xz)$ the program computed.
    FoldA,
    /// The folded $b(x)$ the program computed.
    FoldB,
}

/// The point of an opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    /// A child's $u$.
    ChildU(Side),
    /// A child's $y$.
    ChildY(Side),
    /// A child's $x$.
    ChildX(Side),
    /// The step's $w$.
    W,
    /// The step's $x$.
    X,
    /// The step's $y$.
    Y,
    /// The step's $xz$.
    Xz,
    /// The step's own circuit id.
    CircuitId,
    /// An internal circuit's $\omega^j$.
    Internal(InternalCircuitIndex),
    /// The point of an online opening.
    Online(usize),
}

/// An opening: a polynomial's evaluation at $u$, the value it claims at a
/// point, and the point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quotient {
    /// The polynomial at $u$.
    pub evaluated: EvalValue,
    /// The claimed value at the point.
    pub value: Term,
    /// The point.
    pub at: Point,
}

/// A claim of the fold, by the evaluations it takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claim {
    /// A child's accumulator: $a$ at $xz$ and $b$ at $x$.
    Raw { a: Input, b: Input },
    /// A circuit's claim: $a$ is the sum of its polynomials at $xz$, and
    /// $b$ that sum with the registry's evaluation for the circuit and
    /// $t(xz)$.
    Circuit { sy: Input, rxs: Vec<Input> },
    /// A bonding's claim: $a$ is the fold, with $z$, of each slot's sum,
    /// and $b$ the registry's evaluation for the bonding.
    Bonding { sy: Input, slots: Vec<Vec<Input>> },
}

/// A step of the program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// A claim's evaluations join its group at node `node`.
    Claim { node: usize, claim: Claim },
    /// A group but the last closes: the fold randomizer joins it at its
    /// last node, and the group joins the fold.
    Group(usize),
    /// The last group, which holds the randomizer's $a$ side alone.
    LastGroup,
    /// An opening's quotient joins $f(u)$.
    Quotient(Quotient),
    /// $f(u)$ is complete and starts $v$.
    FinishF,
    /// An evaluation at $u$ joins $v$.
    Evaluation(EvalValue),
    /// $v$ is complete.
    FinishV,
}

impl Op {
    /// An estimate of the gates the step takes, for sharing the program
    /// between the circuits that run it.
    fn cost(&self) -> usize {
        match self {
            Op::Claim { claim, .. } => {
                2 + match claim {
                    Claim::Bonding { slots, .. } => slots.len(),
                    _ => 0,
                }
            }
            Op::Group(_) => 4,
            Op::LastGroup => 2,
            // An opening at an internal circuit's point inverts for itself.
            Op::Quotient(quotient) => match quotient.at {
                Point::Internal(_) => 5,
                _ => 2,
            },
            Op::Evaluation(_) => 1,
            Op::FinishF | Op::FinishV => 32,
        }
    }

    /// The stage values the step reads, in the order it reads them.
    fn inputs(&self, mut read: impl FnMut(Input)) {
        let randomizer_a = Input::Query(QueryValue::RandomizerAAtXz);
        let randomizer_b = Input::Query(QueryValue::RandomizerBAtX);
        match self {
            Op::Claim { claim, .. } => match claim {
                Claim::Raw { a, b } => {
                    read(*a);
                    read(*b);
                }
                Claim::Circuit { sy, rxs } => {
                    rxs.iter().copied().for_each(&mut read);
                    read(*sy);
                }
                Claim::Bonding { sy, slots } => {
                    slots.iter().flatten().copied().for_each(&mut read);
                    read(*sy);
                }
            },
            Op::Group(_) => {
                read(randomizer_a);
                read(randomizer_b);
            }
            Op::LastGroup => read(randomizer_a),
            Op::Quotient(quotient) => {
                read(Input::Eval(quotient.evaluated));
                if let Term::Input(input) = quotient.value {
                    read(input);
                }
            }
            Op::Evaluation(value) => read(Input::Eval(*value)),
            Op::FinishF | Op::FinishV => {}
        }
    }
}

/// The claims' evaluations by name, for [`claims::build`] to lay out.
struct Keys;

impl Source for Keys {
    type RxComponent = RxComponent;
    type Rx = Input;
    type AppCircuitId = Input;

    fn rx(&self, component: RxComponent) -> impl Iterator<Item = Input> {
        [Side::Left, Side::Right].into_iter().map(move |side| {
            Input::Query(match component {
                RxComponent::AbA => QueryValue::AAtXz(side),
                RxComponent::AbB => QueryValue::BAtX(side),
                RxComponent::Rx(index) => QueryValue::Rx(side, index),
            })
        })
    }

    fn applications(&self) -> impl Iterator<Item = (Input, [Input; 2])> {
        core::iter::once((
            Input::Query(QueryValue::RegistryXyAtCircuitId),
            [
                Input::Query(QueryValue::ApplicationAtXz),
                Input::Query(QueryValue::ApplicationStageAtXz),
            ],
        ))
    }
}

/// Records the claims [`claims::build`] emits, in its order.
struct Recorder {
    claims: Vec<Claim>,
}

impl<P: Profile> Processor<P, Input, Input> for Recorder {
    fn raw_claim(&mut self, a: Input, b: Input) {
        self.claims.push(Claim::Raw { a, b });
    }

    fn circuit_claim(&mut self, sy: Input, rxs: impl Iterator<Item = Input>) {
        self.claims.push(Claim::Circuit {
            sy,
            rxs: rxs.collect(),
        });
    }

    fn internal_circuit_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = Input>,
    ) {
        self.claims.push(Claim::Circuit {
            sy: Input::Query(QueryValue::Fixed(id)),
            rxs: rxs.collect(),
        });
    }

    fn grouped_bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Input>>,
    ) -> Result<()> {
        self.claims.push(Claim::Bonding {
            sy: Input::Query(QueryValue::Fixed(id)),
            slots: groups.map(Iterator::collect).collect(),
        });
        Ok(())
    }
}

/// The static prefix of the openings, as `compute_v` reads it.
fn static_quotient(query: &StaticFQuery) -> Quotient {
    use EvalValue as E;
    use QueryValue as Q;
    use Side::{Left, Right};
    let stage = |value: QueryValue| Term::Input(Input::Query(value));
    let (evaluated, value, at) = match query {
        StaticFQuery::LeftP => (E::P(Left), Term::ChildV(Left), Point::ChildU(Left)),
        StaticFQuery::RightP => (E::P(Right), Term::ChildV(Right), Point::ChildU(Right)),
        StaticFQuery::LeftRegistryXyAtW => (
            E::RegistryXy(Left),
            stage(Q::ChildRegistryXyAtW(Left)),
            Point::W,
        ),
        StaticFQuery::RightRegistryXyAtW => (
            E::RegistryXy(Right),
            stage(Q::ChildRegistryXyAtW(Right)),
            Point::W,
        ),
        StaticFQuery::RegistryWx0AtLeftY => (
            E::RegistryWx0,
            stage(Q::ChildRegistryXyAtW(Left)),
            Point::ChildY(Left),
        ),
        StaticFQuery::RegistryWx1AtRightY => (
            E::RegistryWx1,
            stage(Q::ChildRegistryXyAtW(Right)),
            Point::ChildY(Right),
        ),
        StaticFQuery::RegistryWx0AtY => (
            E::RegistryWx0,
            stage(Q::RegistryWyAtChildX(Left)),
            Point::Y,
        ),
        StaticFQuery::RegistryWx1AtY => (
            E::RegistryWx1,
            stage(Q::RegistryWyAtChildX(Right)),
            Point::Y,
        ),
        StaticFQuery::RegistryWyAtLeftX => (
            E::RegistryWy,
            stage(Q::RegistryWyAtChildX(Left)),
            Point::ChildX(Left),
        ),
        StaticFQuery::RegistryWyAtRightX => (
            E::RegistryWy,
            stage(Q::RegistryWyAtChildX(Right)),
            Point::ChildX(Right),
        ),
        StaticFQuery::RegistryWyAtX => (E::RegistryWy, stage(Q::RegistryWxy), Point::X),
        StaticFQuery::RegistryXyAtW => (E::OwnRegistryXy, stage(Q::RegistryWxy), Point::W),
        StaticFQuery::RegistryXyAtCircuitId => (
            E::OwnRegistryXy,
            stage(Q::RegistryXyAtCircuitId),
            Point::CircuitId,
        ),
        StaticFQuery::LeftAbAAtXz => (E::A(Left), stage(Q::AAtXz(Left)), Point::Xz),
        StaticFQuery::LeftAbBAtX => (E::B(Left), stage(Q::BAtX(Left)), Point::X),
        StaticFQuery::RightAbAAtXz => (E::A(Right), stage(Q::AAtXz(Right)), Point::Xz),
        StaticFQuery::RightAbBAtX => (E::B(Right), stage(Q::BAtX(Right)), Point::X),
        StaticFQuery::CurrentAAtXz => (E::OwnA, Term::FoldA, Point::Xz),
        StaticFQuery::CurrentBAtX => (E::OwnB, Term::FoldB, Point::X),
        StaticFQuery::CurrentApplicationAtXz => {
            (E::Application, stage(Q::ApplicationAtXz), Point::Xz)
        }
        StaticFQuery::CurrentApplicationStageAtXz => (
            E::ApplicationStage,
            stage(Q::ApplicationStageAtXz),
            Point::Xz,
        ),
        StaticFQuery::RandomizerAAtXz => (E::RandomizerA, stage(Q::RandomizerAAtXz), Point::Xz),
        StaticFQuery::RandomizerBAtX => (E::RandomizerB, stage(Q::RandomizerBAtX), Point::X),
    };
    Quotient {
        evaluated,
        value,
        at,
    }
}

/// The program of profile `P`: every step `compute_v` makes, in its order.
pub fn program<P: Profile>() -> Vec<Op> {
    let mut ops = Vec::new();

    // The fold: the claims over the grid, a group at a time.
    let mut recorder = Recorder { claims: Vec::new() };
    claims::build::<P, _, _>(&Keys, &mut recorder).expect("recording a claim cannot fail");
    let groups = NumFoldGroups::<P>::len();
    let claims_per_group = FOLD_GROUP_SIZE - 1;
    assert!(
        recorder.claims.len() <= (groups - 1) * claims_per_group,
        "the fold's grid does not hold every claim"
    );
    let mut claims = recorder.claims.into_iter();
    for group in 0..groups - 1 {
        for node in 0..claims_per_group {
            match claims.next() {
                Some(claim) => ops.push(Op::Claim { node, claim }),
                None => break,
            }
        }
        ops.push(Op::Group(group));
    }
    ops.push(Op::LastGroup);

    // The quotients, in the prover's order.
    ops.extend(
        STATIC_F_QUERIES
            .iter()
            .map(|query| Op::Quotient(static_quotient(query))),
    );
    for side in [Side::Left, Side::Right] {
        ops.extend(RxIndex::all::<P>().into_iter().map(|id| {
            Op::Quotient(Quotient {
                evaluated: EvalValue::Rx(side, id),
                value: Term::Input(Input::Query(QueryValue::Rx(side, id))),
                at: Point::Xz,
            })
        }));
    }
    ops.extend(InternalCircuitIndex::all::<P>().into_iter().map(|id| {
        Op::Quotient(Quotient {
            evaluated: EvalValue::OwnRegistryXy,
            value: Term::Input(Input::Query(QueryValue::Fixed(id))),
            at: Point::Internal(id),
        })
    }));
    ops.extend((0..NUM_ONLINE_FP_QUERIES).map(|slot| {
        Op::Quotient(Quotient {
            evaluated: EvalValue::Online(slot),
            value: Term::OnlineY(slot),
            at: Point::Online(slot),
        })
    }));
    ops.push(Op::FinishF);

    // The evaluations at u.
    ops.extend(evaluations::<P>().into_iter().map(Op::Evaluation));
    ops.push(Op::FinishV);
    ops
}

/// The program's running values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State<T> {
    /// The $a$ side of the group being filled.
    pub group_a: T,
    /// The $b$ side of the group being filled.
    pub group_b: T,
    /// The folded $a(xz)$ so far.
    pub a: T,
    /// The folded $b(x)$ so far.
    pub b: T,
    /// $f(u)$ so far.
    pub f: T,
    /// $v$ so far.
    pub v: T,
}

/// The values of a [`State`].
const STATE_LEN: usize = 6;

impl<T> State<T> {
    /// The values of a state.
    pub const LEN: usize = STATE_LEN;

    /// The state's values, in the order [`from_values`](Self::from_values)
    /// takes them.
    pub fn values(&self) -> [&T; STATE_LEN] {
        [
            &self.group_a,
            &self.group_b,
            &self.a,
            &self.b,
            &self.f,
            &self.v,
        ]
    }

    /// Maps every value.
    pub fn map<U>(&self, mut f: impl FnMut(&T) -> U) -> State<U> {
        State {
            group_a: f(&self.group_a),
            group_b: f(&self.group_b),
            a: f(&self.a),
            b: f(&self.b),
            f: f(&self.f),
            v: f(&self.v),
        }
    }
}

impl<T: Clone> State<T> {
    /// The state of `values`.
    ///
    /// # Panics
    ///
    /// Panics if `values` are not a state's [`LEN`](Self::LEN).
    pub fn from_values(values: &[T]) -> Self {
        assert_eq!(values.len(), Self::LEN);
        State {
            group_a: values[0].clone(),
            group_b: values[1].clone(),
            a: values[2].clone(),
            b: values[3].clone(),
            f: values[4].clone(),
            v: values[5].clone(),
        }
    }

    /// The state every value of which is `value`.
    pub fn filled(value: T) -> Self {
        State {
            group_a: value.clone(),
            group_b: value.clone(),
            a: value.clone(),
            b: value.clone(),
            f: value.clone(),
            v: value,
        }
    }
}

/// How profile `P` shares its program between the
/// [`open`](super::circuits::open) circuits, and the copies each reads.
#[derive(Clone, Debug)]
pub struct Schedule {
    ops: Vec<Op>,
    /// The first step of every chunk, then the program's length.
    cuts: Vec<usize>,
    /// The inputs each band holds copies of, in slot order: one per chunk,
    /// then `compute_v`'s own.
    bands: Vec<Vec<Input>>,
}

impl Schedule {
    /// The schedule of profile `P`: its program shared between its chunks
    /// in equal parts of the steps' estimated cost.
    ///
    /// # Panics
    ///
    /// Panics if the profile's `compute_v` runs the program whole.
    pub fn of<P: Profile>() -> Self {
        let chunks = super::opening_chunks::<P>();
        assert!(chunks > 0, "a program run whole has no schedule");
        let ops = program::<P>();
        let total: usize = ops.iter().map(Op::cost).sum();

        let mut cuts = vec![0];
        let mut running = 0;
        for (index, op) in ops.iter().enumerate() {
            running += op.cost();
            while cuts.len() < chunks && running * chunks >= cuts.len() * total {
                cuts.push(index + 1);
            }
        }
        cuts.resize(chunks, ops.len());
        cuts.push(ops.len());

        let mut bands: Vec<Vec<Input>> = cuts
            .windows(2)
            .map(|window| {
                let mut slots = BTreeMap::new();
                let mut band = Vec::new();
                for op in &ops[window[0]..window[1]] {
                    op.inputs(|input| {
                        slots.entry(input).or_insert_with(|| {
                            band.push(input);
                            band.len() - 1
                        });
                    });
                }
                band
            })
            .collect();
        // What `compute_v` exports off the two stages.
        bands.push(
            (0..Present::<P, Nested, 2>::len())
                .map(|i| Input::Query(QueryValue::OnlineStage(i)))
                .chain(
                    (0..PhaseCoordinatesLen::<P, Nested, 3>::len())
                        .map(|i| Input::Query(QueryValue::OnlineAuxiliary(i))),
                )
                .chain(
                    (0..Present::<P, Nested, 2>::len())
                        .map(|i| Input::Eval(EvalValue::OnlineStage(i))),
                )
                .collect(),
        );
        Schedule { ops, cuts, bands }
    }

    /// The number of chunks.
    pub fn chunks(&self) -> usize {
        self.cuts.len() - 1
    }

    /// The steps chunk `chunk` runs.
    pub fn window(&self, chunk: usize) -> &[Op] {
        &self.ops[self.cuts[chunk]..self.cuts[chunk + 1]]
    }

    /// The inputs band `band` holds copies of, in slot order: a chunk's by
    /// its index, and `compute_v`'s own after the chunks'.
    pub fn band(&self, band: usize) -> &[Input] {
        &self.bands[band]
    }

    /// The most inputs any band holds.
    pub fn widest_band(&self) -> usize {
        self.bands.iter().map(Vec::len).max().unwrap_or(0)
    }

    /// The slot of every input of band `band`.
    pub fn slots(&self, band: usize) -> BTreeMap<Input, usize> {
        self.bands[band]
            .iter()
            .enumerate()
            .map(|(slot, &input)| (input, slot))
            .collect()
    }
}

/// The values every step of the program may take beside its inputs: the
/// step's challenges, and what `compute_v` stages for the chunks.
pub struct Shared<'a, 'dr, D: Driver<'dr>> {
    /// $\alpha$.
    pub alpha: &'a Element<'dr, D>,
    /// $u$.
    pub u: &'a Element<'dr, D>,
    /// $z$.
    pub z: &'a Element<'dr, D>,
    /// $\mu$.
    pub mu: &'a Element<'dr, D>,
    /// The effective $\beta$.
    pub beta: &'a Element<'dr, D>,
    /// $t(xz)$.
    pub txz: &'a Element<'dr, D>,
    /// The second layer's interpolation weights, one per group.
    pub outer: &'a [Element<'dr, D>],
    /// The online helper's two sums, for a profile with a native online
    /// batch.
    pub online_fold: &'a [Element<'dr, D>],
}

/// Where a run of the program reads its values.
pub trait Values<'dr, D: Driver<'dr>> {
    /// A stage value.
    fn input(&self, input: Input) -> Element<'dr, D>;
    /// A child's batch evaluation $v$.
    fn child_v(&self, side: Side) -> Element<'dr, D>;
    /// The value of an online opening.
    fn online_y(&self, slot: usize) -> Element<'dr, D>;
    /// The point of an opening.
    fn point(&self, dr: &mut D, point: Point) -> Result<Element<'dr, D>>;
}

/// Runs `ops` from `state` and returns the state they end in.
///
/// # Errors
///
/// Propagates the driver's errors.
pub fn run<'dr, D: Driver<'dr>, P: Profile, V: Values<'dr, D>>(
    dr: &mut D,
    ops: &[Op],
    mut state: State<Element<'dr, D>>,
    shared: &Shared<'_, 'dr, D>,
    values: &V,
) -> Result<State<Element<'dr, D>>> {
    // The inverse of u minus each point the window opens at.
    let mut points: Vec<Point> = Vec::new();
    for op in ops {
        if let Op::Quotient(quotient) = op
            && !points.contains(&quotient.at)
        {
            points.push(quotient.at);
        }
    }
    let inverses = if points.is_empty() {
        Vec::new()
    } else {
        let mut inverter = Inverter::with_base(shared.u.clone());
        for &point in &points {
            let point = values.point(dr, point)?;
            inverter.add(dr, &point)?;
        }
        inverter.invert(dr)?
    };

    // The first layer's weights and the randomizer's share of a group, for
    // a window that folds.
    let folds = ops
        .iter()
        .any(|op| matches!(op, Op::Claim { .. } | Op::Group(_) | Op::LastGroup));
    let inner = if folds {
        revdot::basis_weights(dr, shared.mu, FOLD_GROUP_SIZE)?
    } else {
        Vec::new()
    };
    let randomizers = if ops.iter().any(|op| matches!(op, Op::Group(_))) {
        let last = &inner[FOLD_GROUP_SIZE - 1];
        Some((
            values
                .input(Input::Query(QueryValue::RandomizerAAtXz))
                .mul(dr, last)?,
            values
                .input(Input::Query(QueryValue::RandomizerBAtX))
                .mul(dr, last)?,
        ))
    } else {
        None
    };

    for op in ops {
        match op {
            Op::Claim { node, claim } => {
                let (a, b) = match claim {
                    Claim::Raw { a, b } => (values.input(*a), values.input(*b)),
                    Claim::Circuit { sy, rxs } => {
                        let sum = Element::sum(dr, rxs.iter().map(|&rx| values.input(rx)));
                        let b = sum.add(dr, &values.input(*sy)).add(dr, shared.txz);
                        (sum, b)
                    }
                    Claim::Bonding { sy, slots } => {
                        let sums: Vec<_> = slots
                            .iter()
                            .map(|slot| Element::sum(dr, slot.iter().map(|&rx| values.input(rx))))
                            .collect();
                        (Element::fold(dr, &sums, shared.z)?, values.input(*sy))
                    }
                };
                let weight = &inner[*node];
                let (a, b) = (a.mul(dr, weight)?, b.mul(dr, weight)?);
                state.group_a = state.group_a.add(dr, &a);
                state.group_b = state.group_b.add(dr, &b);
            }
            Op::Group(group) => {
                let (randomizer_a, randomizer_b) = randomizers
                    .as_ref()
                    .expect("a window that closes a group has the randomizer's share");
                let weight = &shared.outer[*group];
                let group_a = state.group_a.add(dr, randomizer_a).mul(dr, weight)?;
                let group_b = state.group_b.add(dr, randomizer_b).mul(dr, weight)?;
                state.a = state.a.add(dr, &group_a);
                state.b = state.b.add(dr, &group_b);
                state.group_a = Element::zero(dr);
                state.group_b = Element::zero(dr);
            }
            Op::LastGroup => {
                let last = shared
                    .outer
                    .last()
                    .expect("the fold has at least one group");
                let randomizer = values
                    .input(Input::Query(QueryValue::RandomizerAAtXz))
                    .mul(dr, &inner[0])?
                    .mul(dr, last)?;
                state.a = state.a.add(dr, &randomizer);
            }
            Op::Quotient(quotient) => {
                let evaluated = values.input(Input::Eval(quotient.evaluated));
                let value = match quotient.value {
                    Term::Input(input) => values.input(input),
                    Term::ChildV(side) => values.child_v(side),
                    Term::OnlineY(slot) => values.online_y(slot),
                    Term::FoldA => state.a.clone(),
                    Term::FoldB => state.b.clone(),
                };
                let inverse = &inverses[points
                    .iter()
                    .position(|point| *point == quotient.at)
                    .expect("every point of the window was inverted")];
                let term = evaluated.sub(dr, &value).mul(dr, inverse)?;
                state.f = state.f.mul(dr, shared.alpha)?.add(dr, &term);
            }
            Op::FinishF => {
                let mut fu = state.f.clone();
                if !P::NATIVE_ONLINE.is_empty() {
                    fu = crate::profile::online::circuit::mul_pow(
                        dr,
                        &fu,
                        shared.alpha,
                        P::NATIVE_ONLINE.openings.len(),
                    )?
                    .add(dr, &shared.online_fold[0]);
                }
                state.v = fu;
            }
            Op::Evaluation(value) => {
                let value = values.input(Input::Eval(*value));
                state.v = state.v.mul(dr, shared.beta)?.add(dr, &value);
            }
            Op::FinishV => {
                if !P::NATIVE_ONLINE.is_empty() {
                    state.v = crate::profile::online::circuit::mul_pow(
                        dr,
                        &state.v,
                        shared.beta,
                        P::NATIVE_ONLINE.polynomials.len(),
                    )?
                    .add(dr, &shared.online_fold[1]);
                }
            }
        }
    }
    Ok(state)
}

/// The polynomials the claim of the circuit in `compute_v`'s place sums:
/// its own, the binding stage's when it reads the nested online input
/// stage's commitment there, the preamble's, the carry stage's and its own
/// band's.
pub fn base_claim<P: Profile>() -> Vec<RxIndex> {
    let mut loaded = vec![RxIndex::ComputeV];
    if !P::NESTED_ONLINE.is_empty() {
        loaded.push(RxIndex::PointsBinding);
    }
    loaded.extend([
        RxIndex::Preamble,
        super::open_carry_rx::<P>(),
        super::open_band_rx::<P>(super::opening_chunks::<P>()),
    ]);
    loaded
}

/// The polynomials the claim of chunk `chunk` sums: its own, the
/// preamble's, the carry stage's and its band's.
pub fn chunk_claim<P: Profile>(chunk: usize) -> Vec<RxIndex> {
    vec![
        RxIndex::ExtensionCircuit(super::open_chunk::<P>(chunk)),
        RxIndex::Preamble,
        super::open_carry_rx::<P>(),
        super::open_band_rx::<P>(chunk),
    ]
}

/// The polynomials each proof's slot of band `band`'s loading claim sums:
/// the band's and the two stages it copies.
pub fn loading_claim<P: Profile>(band: usize) -> Vec<RxIndex> {
    vec![
        super::open_band_rx::<P>(band),
        RxIndex::Query,
        RxIndex::Eval,
    ]
}

/// The polynomials the band stage's final mask covers: the circuit's in
/// `compute_v`'s place and every chunk's.
pub fn final_claim<P: Profile>() -> Vec<RxIndex> {
    core::iter::once(RxIndex::ComputeV)
        .chain(
            (0..super::opening_chunks::<P>())
                .map(|chunk| RxIndex::ExtensionCircuit(super::open_chunk::<P>(chunk))),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Standard, testing::Chunked};

    /// The program holds every claim, every opening and every evaluation
    /// once, in `compute_v`'s order.
    #[test]
    fn the_program_is_compute_v_s_work() {
        fn check<P: Profile>() {
            let ops = program::<P>();
            let groups = NumFoldGroups::<P>::len();
            let claims = ops
                .iter()
                .filter(|op| matches!(op, Op::Claim { .. }))
                .count();
            assert_eq!(claims, super::super::num_claims::<P>());
            let closed: Vec<_> = ops
                .iter()
                .filter_map(|op| match op {
                    Op::Group(group) => Some(*group),
                    _ => None,
                })
                .collect();
            assert_eq!(closed, (0..groups - 1).collect::<Vec<_>>());

            let quotients = ops
                .iter()
                .filter(|op| matches!(op, Op::Quotient(_)))
                .count();
            assert_eq!(
                quotients,
                STATIC_F_QUERIES.len()
                    + 2 * RxIndex::num::<P>()
                    + InternalCircuitIndex::num::<P>()
                    + NUM_ONLINE_FP_QUERIES
            );
            let evaluated = ops
                .iter()
                .filter(|op| matches!(op, Op::Evaluation(_)))
                .count();
            assert_eq!(evaluated, evaluations::<P>().len());
            assert_eq!(evaluated, 2 * (RxIndex::num::<P>() + 4) + 11 + NUM_ONLINE_FP_QUERIES);

            // The three parts follow one another.
            let finish_f = ops.iter().position(|op| *op == Op::FinishF).unwrap();
            let last_group = ops.iter().position(|op| *op == Op::LastGroup).unwrap();
            assert!(last_group < finish_f);
            assert_eq!(ops.last(), Some(&Op::FinishV));
            assert!(
                ops[..=last_group]
                    .iter()
                    .all(|op| matches!(op, Op::Claim { .. } | Op::Group(_) | Op::LastGroup))
            );
            assert!(
                ops[last_group + 1..finish_f]
                    .iter()
                    .all(|op| matches!(op, Op::Quotient(_)))
            );
        }
        check::<Standard>();
        check::<Chunked>();
    }

    /// A schedule's windows partition the program in order, and each band
    /// holds every input of its window once.
    #[test]
    fn a_schedule_partitions_the_program() {
        type P = Chunked;
        let schedule = Schedule::of::<P>();
        let chunks = super::super::opening_chunks::<P>();
        assert_eq!(schedule.chunks(), chunks);
        let ops = program::<P>();
        let mut rejoined = Vec::new();
        for chunk in 0..chunks {
            let window = schedule.window(chunk);
            assert!(!window.is_empty(), "chunk {chunk} runs no step");
            rejoined.extend(window.iter().cloned());

            let band = schedule.band(chunk);
            let slots = schedule.slots(chunk);
            assert_eq!(slots.len(), band.len(), "an input is copied once");
            for op in window {
                op.inputs(|input| assert!(slots.contains_key(&input)));
            }
        }
        assert_eq!(rejoined, ops);
        assert!(schedule.widest_band() <= super::super::OpenBandLen::<P>::len());
    }
}
