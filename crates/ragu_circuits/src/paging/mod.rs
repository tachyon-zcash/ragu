//! Paging: one circuit proven as several.
//!
//! An *unpaged circuit* is a multi-stage circuit that is written once,
//! whole, and needs more gates than a polynomial holds ([`Pageable`]). It
//! loads its stages, allocates gates of its own, enforces linear
//! constraints over the stages' wires and its own, and returns its public
//! output. Paging cuts it into *paged circuits*, or *pages*: ordinary
//! multi-stage circuits ([`PagedCircuit`], and [`LastPagedCircuit`] for
//! the one that returns the public output) that each hold some of its
//! gates and enforce some of its constraints. A page has its own trace polynomial,
//! wiring polynomial and revdot claim, and nothing downstream needs to
//! know it is a piece of something larger.
//!
//! Every page loads the stages the unpaged circuit loads, and then one
//! more: the *carry stage* ([`CarryStage`]), the memory the pages share. A
//! value that one page holds and another reads is copied to a slot of it.
//!
//! The *pager* (the `pager` module) chooses the page of each gate and of
//! each constraint, and with them what the carry stage holds. It places
//! the circuit's gates in an order, that in which the circuit allocates
//! them or one that puts a gate allocated long before its use beside the
//! gates it feeds, and gives each page a run of them. It first minimizes
//! wire crossings. If every placement exceeds the carry capacity, it
//! retries counting each wire at the boundary of its exporting page.
//! If carry still exceeds capacity, it shifts the grid by half a stretch
//! and tries that score once more. Each pass chooses the placement using
//! the actual number of slots. It gives the same
//! pages each time it runs on a circuit, and none of its choices is
//! trusted: [`Pages::check`] holds its pages to the unpaged circuit (see
//! [Invariants](#invariants)).
//!
//! The pager runs twice on a circuit. A *census pass*, offline, cuts the
//! circuit to find how many pages it takes and how many values its pages
//! carry; the two numbers are then written in code. *Registration-time
//! paging* cuts the circuit again with those numbers, each time a registry
//! is built, checks the pages and registers them. So the cut itself is
//! written nowhere.
//!
//! # Layout
//!
//! A page's polynomial holds, in gate order ([`Layout`]):
//!
//! ```text
//! gate 0   | the circuit's stages | carry stage   | the page's own gates
//! SYSTEM   | the same gates as    | same gates    | up to the last gate a
//!          | in the circuit       | on every page | polynomial holds
//! ```
//!
//! The circuit's stages are polynomials of their own, each holding its
//! values at fixed gates, one stage after another ([`Stages::spans`]).
//! Every page loads every one of them, where the circuit has them. The
//! carry stage is one more stage, which paging adds after the circuit's
//! last and every page loads. A page is a multi-stage
//! circuit whose last stage it is, so a page's own gates start where it
//! ends.
//!
//! The carry stage's size is the unpaged circuit's to state
//! ([`Pageable::Carry`]): a circuit that carries more values between its
//! pages than the stage holds is not cut.
//!
//! # Carrying
//!
//! A constraint is *homed* on the last page it names a wire of. What it
//! names on an earlier page is a linear combination of that page's wires:
//! that page holds a slot of the carry stage equal to the combination, and
//! the home page reads the slot in its place. Every page loads the same
//! carry polynomial, so the two agree. A stage's wires are on every page
//! and are never carried, and a constraint that names the wires of stages
//! alone is homed on the page the circuit's gates had reached. A plan,
//! made by walking the circuit once on a driver that follows every wire
//! back to its gates, fixes each constraint's home and slots.
//!
//! # Replaying
//!
//! The plan is then compiled into what each page allocates and enforces:
//! its gates, the linear combinations the circuit makes as far as they are
//! of the page's wires, and its constraints over them. A page is a circuit
//! that replays that, on any driver, without walking the circuit it is a
//! page of; its witness is the values of its gates, which one walk of the
//! circuit gives every page ([`Pages::capture`]). The last page alone
//! walks the circuit, on a driver that only counts what it emits, for the
//! public output's shape and its witness. A page is one flat run of gates
//! and constraints: a routine the circuit calls is not a routine of the
//! page yet. No cut falls within one, though: its gates are on one page,
//! together and in the order the circuit allocates them, which
//! [`Pages::check`] holds the pages to.
//!
//! The `ONE` wire is on every page and is never carried.
//!
//! # Not yet
//!
//! - TODO(#503): a page does not call the routines the circuit calls. It
//!   holds each one whole and replays its gates and constraints as part of
//!   its own, so a page is one segment and a routine on a page has no
//!   segment or fingerprint of its own. Calling them as routines is left
//!   for when a floor planner or an evaluator reads segments.
//! - TODO: the last page walks the circuit each time it is synthesized, on
//!   a driver that only counts, to build the public output's gadget. A
//!   page that carried the output as the elements the circuit writes would
//!   not, and every page would then be of one type.
//!
//! # Invariants
//!
//! [`Pages::check`] holds the pager's pages to these, where the unpaged
//! circuit is registered:
//!
//! - **Gates once.** Each gate of the unpaged circuit's own is on exactly
//!   one page.
//! - **Constraints once.** Each linear constraint of the unpaged circuit
//!   is on exactly one page. Where it names wires that page does not hold,
//!   the page names carry slots in their place.
//! - **Carry slots are copies.** A slot that is read has a writer: a page
//!   that enforces the slot equal to a linear combination of wires it
//!   holds. The check replaces each slot with what its writer holds it to
//!   and compares the pages' constraints with the unpaged circuit's, form
//!   for form. A constraint that names a slot without a writer is then
//!   none of the unpaged circuit's.
//! - **Outputs once.** The public output is written once, in the unpaged
//!   circuit's order, on one page: the last. Every other page has an empty
//!   output, so its $k(Y)$ is constant.
//! - **Preserve routines.** The gates of a routine the unpaged circuit
//!   calls are on one page, together and in the order the circuit
//!   allocates them.
//! - **Deterministic pager.** [`Pages::cut`] refuses an unpaged circuit
//!   that does not cut into the pages it is told, over the carry stage its
//!   type states ([`Pageable::Carry`]).
//!
//! Two more are for whoever builds the revdot claims:
//!
//! - **Every page's revdot claim is checked.**
//! - **Same stage ancestry.** A page's revdot claim is on the sum of the
//!   page's own polynomial, the polynomials of the unpaged circuit's
//!   stages and the carry polynomial: the same stage polynomials for every
//!   page. A page is a multi-stage circuit whose last stage is the carry
//!   stage ([`Carry`]). So the carry stage's stage mask holds the carry
//!   polynomial to the stage's gates ([`Pages::carry_mask`]), and its
//!   final mask holds a page's own polynomial off the gates of every stage
//!   ([`Pages::page_mask`]), as any multi-stage circuit's is held.
//!
//! The order of the gates and of the constraints is not held, and neither
//! is the page that returns the output: those are the pager's to choose.
//!
//! # Cutting
//!
//! A circuit is cut when it is registered, in every process that builds
//! the registry: the cuts are not stored. They are a function of the
//! unpaged circuit, of the number of its pages, of its carry stage's size,
//! of the gates a polynomial holds and of the pager. Each page is a
//! registered circuit, so a change to the pager that moves a cut changes
//! the registry as a change to the circuit would, and a proof made before
//! it no longer verifies. [`Pages::check`] does not tell the two cuts
//! apart: the pages are the circuit's either way.
//!
//! A circuit is taken to emit the same gates and constraints on every
//! walk, whatever its witness, as any circuit is. One whose walk with a
//! witness allocates or enforces other counts than the walk it was cut
//! from is refused where it shows: its pages are given no values to trace
//! ([`Pages::capture`]). One that keeps the counts and changes what it
//! enforces is not told apart, but its pages are still the relation the
//! check held to the circuit: a proof of it may fail to verify, and none
//! verifies what the pages do not hold.
//!
//! # The code
//!
//! The `pager` module is the pager: it chooses the cuts and compiles them.
//! Nothing in it is trusted, since [`Pages::check`] holds its pages to the
//! unpaged circuit. What the check rests on is the rest. The `record`
//! module walks a circuit for the gates and constraints it emits; the
//! `check` module compares that recording of the unpaged circuit with
//! those of its pages; and the `page` module is what is registered and
//! proven: the pages. This module holds what they share: the carry stage,
//! the stages, the layout, and the plan between them.

use alloc::{format, string::String, sync::Arc, vec::Vec};
use core::{marker::PhantomData, ops::Range};

use ragu_core::{
    Coeff, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    vec::{FixedVec, Len},
};
use udon::field::Field;

use crate::{
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, Stage},
};

mod check;
mod page;
mod pager;
mod record;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-utils"))]
pub use self::pager::reads;
pub use self::{
    page::{LastPagedCircuit, PagedCircuit},
    pager::size,
};

/// The flag of a planning wire that names a linear combination rather than
/// the wire of a gate.
const DERIVED: u32 = 1 << 31;

/// The planning `ONE` wire: the $d$ wire of the SYSTEM gate.
const ONE: u32 = 3;

fn refuse<T>(what: String) -> Result<T> {
    Err(Error::Initialization(what.into()))
}

/// An unpaged circuit: a multi-stage circuit that can be cut into pages.
pub trait Pageable<F: Field, R: Rank>: MultiStageCircuit<F, R> {
    /// The values the circuit's carry stage holds: at least as many as
    /// the circuit's pages pass to one another. A census pass finds how
    /// many they pass. The size is stated and not found where the circuit
    /// is cut, since it sizes a stage every page loads.
    type Carry: Len;
}

/// The carry stage of a circuit in pages: the values its pages pass to one
/// another, after `Parent`, the circuit's last stage.
///
/// Each value is a slot. A page that has the wires a slot stands for holds
/// the slot to them, and the pages that read them read the slot.
pub struct CarryStage<F, R, Parent, L>(PhantomData<fn() -> (F, R, Parent, L)>);

impl<F, R, Parent, L> Default for CarryStage<F, R, Parent, L> {
    fn default() -> Self {
        CarryStage(PhantomData)
    }
}

impl<F: Field, R: Rank, Parent: Stage<F, R>, L: Len> Stage<F, R> for CarryStage<F, R, Parent, L> {
    type Parent = Parent;
    type Witness<'source> = &'source [F];
    type OutputKind = Kind![F; FixedVec<Element<'_, _>, L>];

    fn values() -> usize {
        L::len()
    }

    /// Allocates the slots, with the values given and zero past them.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, &'source [F]>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        FixedVec::try_from_fn(|slot| {
            let value = witness
                .as_ref()
                .map(|values| values.get(slot).copied().unwrap_or(F::ZERO));
            Element::alloc(dr, &mut (), value)
        })
    }
}

/// The carry stage of circuit `S`.
pub type Carry<F, R, S> =
    CarryStage<F, R, <S as MultiStageCircuit<F, R>>::Last, <S as Pageable<F, R>>::Carry>;

/// What a circuit is cut over: its stages, as its pages see them, the
/// values its carry stage holds, and the pages it is cut into.
///
/// The circuit reserves its stages one after another from the SYSTEM gate,
/// and every page loads every one of them at the same gates, then the
/// carry stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stages {
    /// Each stage's gates in a polynomial, in the order the circuit
    /// reserves the stages: each starts where the one before it ends.
    pub spans: Vec<Range<usize>>,
    /// The values the carry stage holds.
    pub carry: usize,
    /// The pages the circuit is cut into.
    pub pages: usize,
}

impl Stages {
    /// A pageable circuit's stages, where their polynomials hold them, and
    /// its carry stage's size, for one page.
    pub fn of<F: Field, R: Rank, S: Pageable<F, R>>() -> Self {
        Stages {
            spans: <S::Last as Stage<F, R>>::gate_ranges(),
            carry: S::Carry::len(),
            pages: 1,
        }
    }

    /// The same stages, for `pages` pages.
    pub fn pages(mut self, pages: usize) -> Self {
        self.pages = pages;
        self
    }

    /// The pages.
    pub fn num_pages(&self) -> usize {
        self.pages
    }

    /// The first gate of the circuit's own in the circuit's polynomial,
    /// and the carry stage's first gate in a page's: past the SYSTEM gate
    /// and every stage's gates.
    pub fn own_start(&self) -> usize {
        1 + self.spans.iter().map(Range::len).sum::<usize>()
    }

    /// The carry stage's gates in a page's polynomial: two values a gate,
    /// after the circuit's stages.
    pub fn carry_gates(&self) -> Range<usize> {
        let start = self.own_start();
        start..start + self.carry.div_ceil(2)
    }

    /// The stage of a gate, and the gate's place in it.
    #[cfg(any(test, feature = "test-utils"))]
    fn stage_of(&self, gate: usize) -> Option<(usize, usize)> {
        self.spans
            .iter()
            .enumerate()
            .find(|(_, span)| span.contains(&gate))
            .map(|(stage, span)| (stage, gate - span.start))
    }

    /// Refuses a circuit without a page, and stages that do not follow one
    /// another from the SYSTEM gate.
    fn check(&self) -> Result<()> {
        if self.pages == 0 {
            return refuse("a circuit takes a page".into());
        }
        let mut next = 1;
        for (stage, span) in self.spans.iter().enumerate() {
            if span.start != next || span.end < span.start {
                return refuse(format!(
                    "stage {stage} holds gates {span:?}, which do not start at gate {next}, \
                     where the stage before it ends"
                ));
            }
            next = span.end;
        }
        Ok(())
    }
}

/// Where a paged circuit's gates sit in its pages' polynomials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The first gate of the circuit's own, counted over the unpaged
    /// circuit: past the SYSTEM gate and every stage's gates (see
    /// [`Stages::own_start`]).
    pub own_start: usize,
    /// The carry stage's gates, the same in every page's polynomial:
    /// after the circuit's stages, where the circuit's own gates start in
    /// its own polynomial. It holds two values per gate.
    pub carry: Range<usize>,
    /// The gates a page's polynomial holds: a page's own gates end before
    /// this one.
    pub limit: usize,
    /// For each page, the first gate of the circuit's own it holds, counted
    /// from [`own_start`](Self::own_start) in the order the plan places
    /// the gates in: the order the circuit allocates them in, or one that
    /// puts a gate allocated long before it is used beside the gates it
    /// feeds. A page ends where the next starts, and the last holds the
    /// rest. A page's polynomial holds them from the gate the carry stage
    /// ends at.
    pub starts: Vec<usize>,
}

impl Layout {
    /// Where the pages of `plan` lie over `stages`: the carry stage after
    /// the stages, and each page's run of the circuit's gates after the
    /// page before it.
    fn of<F: Field>(stages: &Stages, plan: &Plan<F>) -> Self {
        let mut next = stages.own_start();
        let starts = plan
            .held
            .iter()
            .map(|held| {
                let start = next;
                next = next.saturating_add(held.len());
                start
            })
            .collect();
        Layout {
            own_start: stages.own_start(),
            carry: stages.carry_gates(),
            limit: plan.limit,
            starts,
        }
    }

    /// The pages.
    pub fn num_pages(&self) -> usize {
        self.starts.len()
    }

    /// The gates of the circuit's own that a page's polynomial has room
    /// for.
    pub fn room(&self) -> usize {
        self.window().len()
    }

    /// The gates of a page's polynomial that hold the page's own: from
    /// past the carry stage on, the same on every page.
    pub fn window(&self) -> Range<usize> {
        self.carry.end..self.limit.max(self.carry.end)
    }

    /// The page of the gate at place `place` among the circuit's own, in
    /// the order they are placed in, from [`own_start`](Self::own_start).
    fn page_of(&self, place: usize) -> Option<usize> {
        (place >= self.own_start)
            .then(|| self.starts.partition_point(|&start| start <= place))
            .and_then(|pages| pages.checked_sub(1))
    }
}

/// One page of a [`PagingReport`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageReport {
    /// The circuit's own gates on the page.
    pub gates: usize,
    /// The constraints homed on the page, the public output's wires
    /// included.
    pub constraints: usize,
    /// The distinct wires of other pages that its constraints name.
    pub imported_wires: usize,
    /// The distinct carry slots its constraints read.
    pub imported_slots: usize,
    /// The distinct wires it holds slots to for other pages.
    pub exported_wires: usize,
    /// The distinct stage wires its constraints name.
    pub stage_wires: usize,
    /// The distinct gates of the stages those wires are at, counted over
    /// the unpaged circuit, in order.
    pub stage_gates: Vec<usize>,
}

/// How a circuit spreads over pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PagingReport {
    /// The circuit's gates, the SYSTEM gate and the stages' included.
    pub num_gates: usize,
    /// The circuit's constraints and its public output's wires.
    pub num_constraints: usize,
    /// The pages, in order.
    pub pages: Vec<PageReport>,
    /// The constraints that name wires off their home page.
    pub cross_constraints: usize,
    /// The distinct wires a constraint names off its home page.
    pub carried_wires: usize,
    /// The carry slots: the distinct linear combinations of one page's
    /// wires a constraint homed elsewhere names, up to scaling.
    pub slots: usize,
    /// For each boundary between two pages, the distinct carried wires of
    /// the circuit's own that are allocated before it and named after it.
    pub cuts: Vec<usize>,
}

/// What the pager hands over, and all it hands over: what each page holds
/// and runs. Nothing of it is trusted, and [`Pages::check`] holds it to
/// the circuit. Where the stages and the carry stage lie, where a gate of
/// the circuit's is placed and how many gates the circuit has are not the
/// pager's to say: they follow from the circuit's type and from `held`.
#[derive(Clone, Debug)]
struct Plan<F: Field> {
    /// The gates a page's polynomial holds: a page's own gates end before
    /// this one.
    limit: usize,
    /// For each page, the gates of the circuit's own it holds, counted
    /// over the unpaged circuit, in the order of the page's polynomial.
    held: Vec<Vec<u32>>,
    /// Each slot's combination, over wires named `4 * gate + kind` with
    /// the gate counted over the unpaged circuit.
    slots: Vec<Vec<(u32, F)>>,
    /// What each page allocates and enforces.
    programs: Vec<Program<F>>,
    /// The linear combinations and the constraints the circuit makes: with
    /// its gates, what a walk of it is counted against.
    sums: usize,
    constraints: usize,
}

/// What one page allocates and enforces, taken off the plan and a walk of
/// the circuit: the page replays it on any driver, and walks no part of the
/// circuit that another page holds.
#[derive(Clone, Debug)]
struct Program<F: Field> {
    /// The gates of its own the page allocates, past the carry stage.
    own: usize,
    /// The linear combinations it makes, in order, each over its wires and
    /// the combinations before it: what the circuit's own combinations
    /// have of the page's wires, or of the page's own gates' among them. A
    /// wire is named `4 * gate + kind` with the gate counted in the page's
    /// polynomial, [`ONE`], or [`DERIVED`] with a combination's index.
    sums: Vec<Vec<(u32, Coeff<F>)>>,
    /// Its constraints, over the same wires.
    constraints: Vec<Vec<(u32, Coeff<F>)>>,
    /// The wires of the public output, on the last page: each a
    /// combination of the same wires.
    outputs: Vec<Vec<(u32, Coeff<F>)>>,
}

impl<F: Field> Plan<F> {
    fn pages(&self) -> usize {
        self.held.len()
    }

    /// The gates of the circuit's own the pages hold between them.
    fn own(&self) -> usize {
        self.held.iter().map(Vec::len).sum()
    }
}

fn diverged(what: &str) -> Error {
    Error::Initialization(format!("a paged circuit diverged from its plan: {what}").into())
}

/// The paged circuits of one unpaged circuit: the circuit, and the plan
/// the pager cut it by.
pub struct Pages<F: Field, R: Rank, S: Pageable<F, R>> {
    circuit: Arc<MultiStage<F, R, S>>,
    plan: Arc<Plan<F>>,
    report: PagingReport,
    /// What the circuit is cut over, as its type says, and where its
    /// pages' gates then lie: neither is the plan's to say.
    stages: Stages,
    layout: Layout,
}

impl<F: Field, R: Rank, S: Pageable<F, R>> Pages<F, R, S> {
    /// `circuit` in the pages of `plan`, over the stages its type states.
    fn over(circuit: Arc<MultiStage<F, R, S>>, plan: Arc<Plan<F>>, report: PagingReport) -> Self {
        let stages = Stages::of::<F, R, S>().pages(plan.pages());
        let layout = Layout::of(&stages, &plan);
        Pages {
            circuit,
            plan,
            report,
            stages,
            layout,
        }
    }

    /// The gates the circuit allocates, the SYSTEM gate included, as the
    /// pages hold them.
    fn num_gates(&self) -> usize {
        self.stages.own_start() + self.plan.own()
    }
}

/// Pages that [`Pages::check`] held to their unpaged circuit: the only
/// ones that hand out circuits to register.
///
/// The pager, and whatever kept its plan, is not trusted. A registry
/// takes a page only through this type, so no page is registered that the
/// check did not hold to the circuit.
pub struct Checked<F: Field, R: Rank, S: Pageable<F, R>>(Pages<F, R, S>);

/// The pages a circuit was cut into, apart from the circuit: what
/// [`Pages::planned`] takes to page the same circuit again without cutting
/// it again.
#[derive(Clone, Debug)]
pub struct Planned<F: Field> {
    plan: Arc<Plan<F>>,
    report: PagingReport,
    /// Where the pages lay for the circuit they were cut from, to report:
    /// [`Pages::planned`] derives them again for the circuit it is given.
    stages: Stages,
    layout: Layout,
}

/// What one walk of a circuit with a witness gives its pages
/// ([`Pages::capture`]).
#[derive(Clone, Debug)]
pub struct Captured<F> {
    /// For each page before the last, the values of the gates it holds, in
    /// the order of its polynomial: the page's witness.
    pub pages: Vec<Vec<[F; 4]>>,
    /// The carry stage's values: its witness.
    pub carry: Vec<F>,
}
