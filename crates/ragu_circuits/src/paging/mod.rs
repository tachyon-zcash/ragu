//! Experimental paging: one circuit laid out over several trace polynomials.
//!
//! A circuit that needs more gates than a polynomial holds is cut into
//! *pages*: its gates are placed in an order, that in which it allocates
//! them or one that puts a gate allocated long before its use beside the
//! gates it feeds, and each page takes a run of them. Which order, and
//! where the runs end, is the planner's choice and is not trusted (see
//! [The code](#the-code)). Each page is an ordinary
//! [`Circuit`](crate::Circuit) ([`Page`], and [`LastPage`] for the one
//! that carries the public output): it has its own trace polynomial,
//! wiring polynomial and claim, and nothing downstream needs to know it is
//! a piece of something larger.
//!
//! # Layout
//!
//! A page's polynomial holds, in gate order ([`Layout`]):
//!
//! ```text
//! gate 0   | the circuit's stages      | the page's own gates | carry stage
//! SYSTEM   | up to the page's first    | up to the carry      | same gates
//!          | own gate                  | stage                | on every page
//! ```
//!
//! The circuit's stages are polynomials of their own, each holding its
//! values at fixed gates ([`Stages::spans`]). Every page loads every stage,
//! and its own gates start past them. The *carry stage* is one more such
//! polynomial, which paging adds and every page loads, at the same gates
//! past every page's own.
//!
//! # Carrying
//!
//! A constraint is *homed* on the last page it names a wire of. What it
//! names on an earlier page is a linear combination of that page's wires:
//! the page holds a slot of the carry stage equal to that combination, and
//! the home page reads the slot in its place. Every page loads the same
//! carry polynomial, so the two agree. A constraint that names the wires
//! of stages alone is homed on the page the circuit's gates had reached.
//! A plan, made by walking the
//! circuit once on a driver that follows every wire back to its gates,
//! fixes each constraint's home and slots.
//!
//! # Replaying
//!
//! The plan is then compiled into what each page allocates and enforces:
//! its gates, the linear combinations the circuit makes as far as they are
//! of the page's wires, and its constraints over them. A page is a circuit
//! that replays that, on any driver, without walking the circuit it is a
//! page of; its witness is the values of its gates, which one walk of the
//! circuit gives every page ([`Paged::capture`]). The last page alone
//! walks the circuit, on a driver that only counts what it emits, for the
//! public output's shape and its witness. A page is one flat run of gates
//! and constraints: a routine the circuit calls is not a routine of the
//! page, though no cut falls within one, so its gates are on one page,
//! together and in the order the circuit allocates them.
//!
//! The `ONE` wire is on every page and is never carried.
//!
//! # What soundness rests on
//!
//! - every page's claim is checked, on the sum of its own polynomial, the
//!   carry polynomial and the polynomials of the circuit's stages;
//! - the carry polynomial is the same one in the sum of every page, and
//!   is zero off its own wires ([`Paged::carry_mask`]);
//! - a page's own polynomial is zero off the gates between the stages and
//!   its carry stage ([`Paged::own_mask`]), which are apart from
//!   both. A page may hold fewer gates than those: the rest are gates no
//!   constraint of its names, as a circuit's are past its last;
//! - the stages share no gate, and are those the circuit was cut over,
//!   which [`Paged::check`] holds the plan to and the caller lays where the
//!   stages' polynomials hold them;
//! - the plan carries every combination a constraint names off its home
//!   page, which [`Paged::check`] holds against the unpaged circuit.
//!
//! # Cutting
//!
//! A circuit is cut when it is registered, in every process that builds
//! the registry: the cuts are not stored. They are a function of the
//! circuit, of the stages its pages are told to load, of the gates a
//! polynomial holds and of the planner. Each page is a registered circuit,
//! so a change to the planner that moves a cut changes the registry as a
//! change to the circuit would, and a proof made before it no longer
//! verifies. [`Paged::check`] does not tell the two cuts apart: the pages
//! are the circuit's either way.
//!
//! A circuit is taken to emit the same gates and constraints on every
//! walk, whatever its witness, as any circuit is. One whose walk with a
//! witness allocates or enforces other counts than the walk it was cut
//! from is refused where it shows: its pages are given no values to trace
//! ([`Paged::capture`]). One that keeps the counts and changes what it
//! enforces is not told apart, but its pages are still the relation the
//! check held to the circuit: a proof of it may fail to verify, and none
//! verifies what the pages do not hold.
//!
//! # The code
//!
//! The `plan` module chooses the cuts and compiles them; nothing in it is
//! trusted, since [`Paged::check`] holds its pages to the circuit. What
//! the check rests on is the rest. The `record` module walks a circuit for
//! the gates and constraints it emits; the `check` module compares that
//! recording of the circuit with those of its pages; and the `page` module
//! is what is registered and proven: the pages, and their carry stage's
//! polynomial and mask. This module holds what they share: the stages,
//! the layout, and the plan between them.

use alloc::{collections::BTreeMap, format, string::String, sync::Arc, vec::Vec};
use core::ops::Range;

use ragu_core::{Coeff, Error, Result};
use udon::field::Field;

use crate::{
    polynomials::Rank,
    staging::{MultiStageCircuit, Stage},
};

mod check;
mod page;
mod plan;
mod record;
#[cfg(test)]
mod tests;

pub use self::{
    page::{LastPage, Page},
    plan::{reads, size},
};

/// The flag of a planning wire that names a linear combination rather than
/// the wire of a gate.
const DERIVED: u32 = 1 << 31;

/// The planning `ONE` wire: the $d$ wire of the SYSTEM gate.
const ONE: u32 = 3;

fn refuse<T>(what: String) -> Result<T> {
    Err(Error::Initialization(what.into()))
}

/// A circuit's stages, as its pages see them: every page loads every one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stages {
    /// Each stage's gates in a polynomial, in the order the circuit
    /// reserves the stages, one after another.
    pub spans: Vec<Range<usize>>,
    /// The pages.
    pages: usize,
}

impl Stages {
    /// One span over every gate before `own_start`, loaded by one page: a
    /// circuit whose stages follow one another from the SYSTEM gate.
    pub fn whole(own_start: usize) -> Self {
        let spans: Vec<_> = Some(1..own_start)
            .filter(|span| !span.is_empty())
            .into_iter()
            .collect();
        Self::over(spans)
    }

    /// A multi-stage circuit's stages, where their polynomials hold them,
    /// loaded by one page.
    pub fn of<F: Field, R: Rank, S: MultiStageCircuit<F, R>>() -> Self {
        Self::over(<S::Last as Stage<F, R>>::gate_ranges())
    }

    /// Stages at `spans`, loaded by one page.
    fn over(spans: Vec<Range<usize>>) -> Self {
        Stages { spans, pages: 1 }
    }

    /// The gates of the circuit's own a page has room for before a carry
    /// stage that starts at gate `carry`, if the stages end before that.
    fn room(&self, carry: usize) -> Option<usize> {
        carry.checked_sub(self.first())
    }

    /// The same stages, over `pages` pages.
    pub fn pages(mut self, pages: usize) -> Self {
        self.pages = pages;
        self
    }

    /// The pages.
    pub fn num_pages(&self) -> usize {
        self.pages
    }

    /// The first gate of the circuit's own, counted over the whole circuit.
    pub fn own_start(&self) -> usize {
        1 + self.spans.iter().map(Range::len).sum::<usize>()
    }

    /// The first gate of stage `stage`, counted over the whole circuit.
    fn start(&self, stage: usize) -> usize {
        1 + self.spans[..stage].iter().map(Range::len).sum::<usize>()
    }

    /// The stage of a gate counted over the whole circuit, and the gate's
    /// place in it.
    fn stage_of(&self, gate: usize) -> Option<(usize, usize)> {
        let mut start = 1;
        for (stage, span) in self.spans.iter().enumerate() {
            if gate < start {
                return None;
            }
            if gate < start + span.len() {
                return Some((stage, gate - start));
            }
            start += span.len();
        }
        None
    }

    /// The first gate of a page's polynomial that can hold a gate of the
    /// circuit's own: past every stage.
    pub fn first(&self) -> usize {
        self.spans
            .iter()
            .map(|span| span.end)
            .max()
            .unwrap_or(1)
            .max(1)
    }

    /// Refuses stages a page cannot load together, or no page.
    fn check(&self) -> Result<()> {
        if self.pages == 0 {
            return refuse("a circuit takes a page".into());
        }
        if self.spans.iter().any(|span| span.start == 0) {
            return refuse("a stage holds the SYSTEM gate".into());
        }
        for (stage, span) in self.spans.iter().enumerate() {
            for (other, earlier) in self.spans[..stage].iter().enumerate() {
                if span.start < earlier.end
                    && earlier.start < span.end
                    && !span.is_empty()
                    && !earlier.is_empty()
                {
                    return refuse(format!("stages {other} and {stage} share gates"));
                }
            }
        }
        Ok(())
    }
}

/// Where a paged circuit's gates sit in its pages' polynomials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The first gate of the circuit's own, counted over the whole circuit:
    /// past the SYSTEM gate and every stage's gates (see
    /// [`Stages::own_start`]).
    pub own_start: usize,
    /// For each page, the first gate of the circuit's own it holds, counted
    /// from [`own_start`](Self::own_start) in the order the plan places
    /// the gates in: the order the circuit allocates them in, or one that
    /// puts a gate allocated long before it is used beside the gates it
    /// feeds. A page ends where the next starts, and the last holds the
    /// rest.
    pub starts: Vec<usize>,
    /// For each page, the gate of its polynomial that holds that gate: past
    /// every stage (see [`Stages::first`]).
    pub firsts: Vec<usize>,
    /// The carry stage's gates, the same in every page's polynomial and
    /// past every page's own. It holds two values per gate.
    pub carry: Range<usize>,
}

impl Layout {
    /// The pages.
    pub fn num_pages(&self) -> usize {
        self.starts.len()
    }

    /// The gates of the circuit's own that page `page`'s polynomial has
    /// room for.
    pub fn room(&self, page: usize) -> usize {
        self.window(page).len()
    }

    /// The gates of its polynomial that hold page `page`'s own: from past
    /// the stages to the carry stage.
    pub fn window(&self, page: usize) -> Range<usize> {
        let first = self.firsts[page];
        first..self.carry.start.max(first)
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
    /// The distinct wires of other pages and of stages it does not load
    /// that its constraints name.
    pub imported_wires: usize,
    /// The distinct carry slots its constraints read.
    pub imported_slots: usize,
    /// The distinct wires it holds slots to for other pages.
    pub exported_wires: usize,
    /// The distinct stage wires its constraints name.
    pub stage_wires: usize,
    /// The distinct gates of the stages those wires are at, counted over
    /// the whole circuit, in order.
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
    /// The carry slots: the distinct linear combinations of one page's or
    /// one stage's wires a constraint homed elsewhere names, up to scaling.
    pub slots: usize,
    /// For each boundary between two pages, the distinct carried wires of
    /// the circuit's own that are allocated before it and named after it.
    pub cuts: Vec<usize>,
}

/// A carry slot a constraint reads off its home page.
#[derive(Clone, Debug)]
struct Link<F> {
    /// The page whose wires the slot combines, which holds the slot to
    /// them.
    exporter: u32,
    slot: u32,
    /// The constraint names `scale` times the slot's combination.
    scale: F,
    /// Whether this constraint is the first to name the slot: the one its
    /// exporter holds the slot to.
    defines: bool,
}

/// Each constraint's home page and carry slots, fixed by one walk of the
/// circuit, and what each page replays of it.
#[derive(Clone, Debug)]
struct Plan<F: Field> {
    layout: Layout,
    stages: Stages,
    /// The gates the circuit allocates, the SYSTEM gate included.
    num_gates: usize,
    /// The home page of each constraint, in emission order.
    homes: Vec<u32>,
    /// The slots of the constraints that read any, by constraint.
    links: BTreeMap<u32, Vec<Link<F>>>,
    /// The slots of each wire of the public output, in traversal order;
    /// their home is the last page.
    outputs: Vec<Vec<Link<F>>>,
    /// Each slot's combination, over wires named `4 * gate + kind` with
    /// the gate counted over the whole circuit.
    slots: Vec<Vec<(u32, F)>>,
    /// For each gate of the circuit's own, in the order it allocates them,
    /// the page that holds it and the gate's index in that page's
    /// polynomial.
    places: Vec<(u32, u32)>,
    /// For each page, the gates of the circuit's own it holds, counted
    /// over the whole circuit, in the order of the page's polynomial.
    held: Vec<Vec<u32>>,
    /// What each page allocates and enforces, once the plan is
    /// [compiled](Self::compile).
    programs: Vec<Program<F>>,
    /// The linear combinations the circuit makes, likewise.
    sums: usize,
}

/// What one page allocates and enforces, taken off the plan and a walk of
/// the circuit: the page replays it on any driver, and walks no part of the
/// circuit that another page holds.
#[derive(Clone, Debug)]
struct Program<F: Field> {
    /// The gates the page allocates past the SYSTEM gate: up to the end of
    /// the carry stage, or of its own gates if the carry stage holds none.
    gates: usize,
    /// Its own gates among them, by their index in its polynomial.
    own: Range<usize>,
    /// The linear combinations it makes, in order, each over its wires and
    /// the combinations before it: what the circuit's own combinations
    /// have of the page's wires, or of one source's among them. A wire is
    /// named `4 * gate + kind` with the gate counted in the page's
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
        self.layout.starts.len()
    }

    /// The page that holds a gate of the circuit's own, counted over the
    /// whole circuit, and the gate's index in that page's polynomial.
    fn place(&self, gate: usize) -> Option<(usize, usize)> {
        let (page, local) = *self.places.get(gate.checked_sub(self.layout.own_start)?)?;
        Some((page as usize, local as usize))
    }

    /// Refuses a carry stage too small for its slots.
    fn fits(&self) -> Result<()> {
        let holds = self.layout.carry.len().saturating_mul(2);
        if self.slots.len() > holds {
            return refuse(format!(
                "the circuit carries {} values between pages, more than the {holds} their carry \
                 stage holds",
                self.slots.len(),
            ));
        }
        Ok(())
    }
}

fn diverged(what: &str) -> Error {
    Error::Initialization(format!("a paged circuit diverged from its plan: {what}").into())
}

/// A circuit cut into pages.
pub struct Paged<F: Field, C> {
    circuit: Arc<C>,
    plan: Arc<Plan<F>>,
    report: PagingReport,
    /// The stages the circuit was cut over, as the caller told them: what
    /// [`Paged::check`] holds the plan's to, since nothing of the plan is
    /// trusted.
    stages: Stages,
}

/// The pages a circuit was cut into, apart from the circuit: what
/// [`Paged::planned`] takes to page the same circuit again without cutting
/// it again.
#[derive(Clone, Debug)]
pub struct Planned<F: Field> {
    plan: Arc<Plan<F>>,
    report: PagingReport,
    stages: Stages,
}
