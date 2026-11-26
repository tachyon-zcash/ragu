//! Experimental paging: one circuit laid out over several trace polynomials.
//!
//! A circuit that needs more gates than a polynomial holds is cut into
//! *pages*, in the order it allocates its gates but for the gates it
//! allocates long before it uses them, which are placed with the first
//! gate they feed. Each page is an ordinary [`Circuit`](crate::Circuit)
//! ([`Page`], and [`LastPage`] for the one that carries the public output):
//! it has its own trace polynomial, wiring polynomial and claim, and nothing
//! downstream needs to know it is a piece of something larger.
//!
//! # Layout
//!
//! A page's polynomial holds, in gate order ([`Layout`]):
//!
//! ```text
//! gate 0   | the stages the page loads | the page's own gates | carry stage
//! SYSTEM   | up to the page's first    | up to the carry      | same gates
//!          | own gate                  | stage                | on every page
//! ```
//!
//! The circuit's stages are polynomials of their own, each holding its
//! values at fixed gates ([`Stages::spans`]). A page loads some of them
//! ([`Stages::loads`]) and its own gates start past those: a page that
//! loads little has room for more of the circuit. Stages that no page loads
//! together may share gates, so a circuit whose stages would not fit a
//! polynomial end to end pages over stages laid side by side. The *carry
//! stage* is one more such polynomial, which paging adds and every page
//! loads, at the same gates past every page's own.
//!
//! # Carrying
//!
//! A constraint is *homed* on the last page it names a wire of. What it
//! names elsewhere, on an earlier page or in a stage its home does not
//! load, is a linear combination of that page's or that stage's wires: a
//! page that has them holds a slot of the carry stage equal to that
//! combination, and the home page reads the slot in its place. Every page
//! loads the same carry polynomial, so the two agree. A plan, made by
//! walking the circuit once on a driver that follows every wire back to its
//! gates, fixes each constraint's home and slots.
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
//! # Pages apart
//!
//! A constraint may name the wires of stages alone, of stages no page
//! loads together: an equality between two stages laid side by side. One
//! such equality is one carried value, and a circuit that holds one stage
//! to copies in the others carries a stage's worth of them, which no page
//! that loads that stage has the room for beside the rest of the circuit.
//! The first pages may therefore be set *apart*, in groups
//! ([`Stages::apart`]): a group's pages hold no gates of the circuit's
//! own and load a carry stage of the group's own in place of the
//! circuit's. Such a constraint is held by the first group whose pages
//! load every stage it names and whose carry stage has a slot left for
//! it, so that a relation too large for one carry stage spreads over
//! several.
//!
//! # Pages that share a carry stage
//!
//! The carry stage takes its gates on every page, whatever the page reads
//! of it. Where a stretch of the circuit passes much between its own pages
//! and little to the rest, its pages may share a second carry stage
//! ([`Stages::local`]), which only they load, right before the first: what
//! one of them reads of another, or of a stage another of them loads, is
//! carried there. A group whose first page loads a stage and holds no
//! gates thus hands the others the part of that stage each reads, and no
//! other page gives it room.
//!
//! # What soundness rests on
//!
//! - every page's claim is checked, on the sum of its own polynomial, the
//!   carry polynomial and the polynomials of the stages it loads;
//! - a carry polynomial is the same one in the sum of every page that
//!   loads it, and is zero off its own wires ([`Paged::carry_mask`],
//!   [`Paged::apart_mask`], [`Paged::local_mask`]);
//! - a page's own polynomial is zero off its own gates
//!   ([`Paged::own_mask`]), which are apart from the carry stage's and from
//!   those of every stage the page loads;
//! - the stages a page loads share no gate;
//! - the plan carries every combination a constraint names off its home
//!   page, which [`Paged::check`] holds against the unpaged circuit.
//!
//! # The code
//!
//! The `plan` module chooses the cuts and compiles them; nothing in it is
//! trusted, since [`Paged::check`] holds its pages to the circuit. The
//! `page` module is what is registered and proven: the pages, their carry
//! stages' polynomials and masks, and that check. This module holds what
//! the two share: the stages, the layout, and the plan between them.

use alloc::{collections::BTreeMap, format, string::String, sync::Arc, vec, vec::Vec};
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

/// A circuit's stages, as its pages see them.
///
/// The circuit reserves its stages one after another, so a walk of it
/// counts their gates end to end. Their polynomials hold them at
/// [`spans`](Self::spans), which need not be end to end: two stages may
/// share gates as long as no page loads both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stages {
    /// Each stage's gates in a polynomial, in the order the circuit
    /// reserves the stages.
    pub spans: Vec<Range<usize>>,
    /// For each page, the stages it loads, by their place in `spans`.
    pub loads: Vec<Vec<usize>>,
    /// The pages before the last that hold no gates of the circuit's own:
    /// a page that only holds slots to the wires of the stages it loads,
    /// for the pages that do not load them.
    pub idle: Vec<usize>,
    /// The first pages, set apart in groups: the pages of each group, in
    /// order. A group's pages hold no gates of the circuit's own and load
    /// a carry stage of the group's own. They hold the constraints that
    /// name the wires of stages alone and that none of the other pages
    /// loads the stages of together.
    pub apart: Vec<usize>,
    /// Groups of the other pages, each a range of them, that share a carry
    /// stage of the group's own beside the circuit's. What a page of a
    /// group reads of another page of it, or of a stage another page of
    /// it loads, is carried there, and takes no gates on the pages
    /// outside the group.
    pub local: Vec<Range<usize>>,
    /// Whether the last page's own gates start past the circuit's last
    /// stage whatever it loads: the page takes the circuit's place, and a
    /// circuit's place may be under a mask that holds its polynomial off
    /// that stage and the gates before it.
    pub sealed: bool,
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
        Stages {
            spans,
            loads: vec![],
            idle: vec![],
            apart: vec![],
            local: vec![],
            sealed: true,
        }
        .pages(1)
    }

    /// The same stages, with `pages` holding no gates of the circuit's own.
    pub fn idling(mut self, pages: Vec<usize>) -> Self {
        self.idle = pages;
        self
    }

    /// The same stages, with the first pages apart, in groups of `groups`
    /// pages each.
    pub fn apart(mut self, groups: Vec<usize>) -> Self {
        self.apart = groups;
        self
    }

    /// The same stages, with each of `groups` a range of pages that share
    /// a carry stage of their own beside the circuit's.
    pub fn sharing(mut self, groups: Vec<Range<usize>>) -> Self {
        self.local = groups;
        self
    }

    /// The group of pages `page` shares a carry stage of their own with.
    fn local_of(&self, page: usize) -> Option<usize> {
        self.local.iter().position(|pages| pages.contains(&page))
    }

    /// The pages apart, over every group.
    fn num_apart(&self) -> usize {
        self.apart.iter().sum()
    }

    /// The pages of group `group` of the pages apart.
    fn group(&self, group: usize) -> Range<usize> {
        let start = self.apart[..group].iter().sum();
        start..start + self.apart[group]
    }

    /// The group page `page` is in, if it is apart.
    fn group_of(&self, page: usize) -> Option<usize> {
        let mut end = 0;
        self.apart.iter().position(|&pages| {
            end += pages;
            page < end
        })
    }

    /// The same stages, for a circuit whose place is under no mask of its
    /// last stage: the last page's own gates start past the stages it
    /// loads, as any page's do.
    pub fn unsealed(mut self) -> Self {
        self.sealed = false;
        self
    }

    /// The gates of the circuit's own that page `page` has room for before
    /// a carry stage that starts at gate `carry`, if the stages it loads
    /// end before that.
    fn room(&self, page: usize, carry: usize) -> Option<usize> {
        let room = carry.checked_sub(self.first(page))?;
        let holds = !self.idle.contains(&page) && page >= self.num_apart();
        Some(if holds { room } else { 0 })
    }

    /// The same stages, for `pages` pages that each load every stage.
    pub fn pages(mut self, pages: usize) -> Self {
        self.loads = vec![(0..self.spans.len()).collect(); pages];
        self
    }

    /// The same stages, with page `page` loading `loads[page]`.
    pub fn loading(mut self, loads: Vec<Vec<usize>>) -> Self {
        self.loads = loads;
        self
    }

    /// The pages the stages are told the loads of.
    pub fn num_pages(&self) -> usize {
        self.loads.len()
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

    /// Whether page `page` loads stage `stage`.
    fn loaded(&self, page: usize, stage: usize) -> bool {
        self.loads
            .get(page)
            .is_some_and(|loads| loads.contains(&stage))
    }

    /// The page that holds a slot to stage `stage`'s wires for page
    /// `home`, which does not load it: the first page that does among
    /// those `home` shares a carry stage of their own with, or else among
    /// all the pages but those apart.
    fn exporter(&self, stage: usize, home: usize) -> Option<usize> {
        let loads = |page: &usize| self.loaded(*page, stage);
        self.local_of(home)
            .and_then(|group| self.local[group].clone().find(loads))
            .or_else(|| (self.num_apart()..self.loads.len()).find(loads))
    }

    /// The first gate of page `page`'s polynomial that can hold a gate of
    /// the circuit's own: past every stage the page loads. The last page
    /// takes the circuit's place, under whatever holds the circuit's
    /// polynomial off its last stage and the gates before it, so its own
    /// start past that stage too.
    pub fn first(&self, page: usize) -> usize {
        let loaded = self.loads[page]
            .iter()
            .map(|&stage| self.spans[stage].end)
            .max()
            .unwrap_or(1);
        let last = match self.spans.last() {
            Some(span) if self.sealed && page + 1 == self.loads.len() => span.end,
            _ => 1,
        };
        loaded.max(last).max(1)
    }

    /// Refuses stages a page cannot load together, or that are not there.
    fn check(&self) -> Result<()> {
        if self.loads.is_empty() {
            return refuse("a circuit takes a page".into());
        }
        if self.spans.iter().any(|span| span.start == 0) {
            return refuse("a stage holds the SYSTEM gate".into());
        }
        if self.idle.iter().any(|&page| page + 1 >= self.loads.len()) {
            return refuse("the last page, or one past it, is told to hold no gates".into());
        }
        let last = self.loads.len() - 1;
        if self.local.iter().enumerate().any(|(group, pages)| {
            pages.is_empty()
                || pages.start < self.num_apart()
                || pages.end > last
                || self.local[..group]
                    .iter()
                    .any(|other| other.start < pages.end && pages.start < other.end)
        }) {
            return refuse(
                "a group of pages that share a carry stage has no page, a page apart, the last \
                 page or a page of another group"
                    .into(),
            );
        }
        if self.apart.contains(&0) || self.num_apart() >= self.loads.len() {
            return refuse(
                "a group of pages apart has no page, or the groups leave no page for the \
                 circuit's gates"
                    .into(),
            );
        }
        for (page, loads) in self.loads.iter().enumerate() {
            for (position, &stage) in loads.iter().enumerate() {
                let Some(span) = self.spans.get(stage) else {
                    return refuse(format!(
                        "page {page} loads stage {stage}, which the circuit does not have"
                    ));
                };
                for &other in &loads[..position] {
                    let earlier = &self.spans[other];
                    if other == stage
                        || (span.start < earlier.end
                            && earlier.start < span.end
                            && !span.is_empty()
                            && !earlier.is_empty())
                    {
                        return refuse(format!(
                            "page {page} loads stages {other} and {stage}, which share gates"
                        ));
                    }
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
    /// from [`own_start`](Self::own_start) in the order the gates are
    /// placed in: the order the circuit allocates them in, but for a gate
    /// allocated long before it is used, which is placed with the first
    /// gate it feeds. A page ends where the next starts, and the last holds
    /// the rest.
    pub starts: Vec<usize>,
    /// For each page, the gate of its polynomial that holds that gate: past
    /// every stage the page loads (see [`Stages::first`]).
    pub firsts: Vec<usize>,
    /// The carry stage's gates, the same in every page's polynomial and
    /// past every page's own. It holds two values per gate.
    pub carry: Range<usize>,
    /// For each group of pages apart, its pages and the gates of its own
    /// carry stage, which its pages load in place of
    /// [`carry`](Self::carry).
    pub apart: Vec<(Range<usize>, Range<usize>)>,
    /// For each group of pages that share a carry stage of their own, its
    /// pages and that stage's gates, which its pages load beside
    /// [`carry`](Self::carry): right before it, past their own.
    pub local: Vec<(Range<usize>, Range<usize>)>,
}

impl Layout {
    /// The pages.
    pub fn num_pages(&self) -> usize {
        self.starts.len()
    }

    /// The gates of the carry stage page `page` loads: its group's if it
    /// is apart, and the circuit's otherwise.
    pub fn carry_of(&self, page: usize) -> &Range<usize> {
        self.apart
            .iter()
            .find(|(pages, _)| pages.contains(&page))
            .map_or(&self.carry, |(_, carry)| carry)
    }

    /// The gates of the circuit's own that page `page`'s polynomial has
    /// room for.
    pub fn room(&self, page: usize) -> usize {
        self.window(page).len()
    }

    /// The gates of its polynomial that hold page `page`'s own. The pages
    /// of a group apart hold none, and have one window between them: past
    /// what any of them loads.
    pub fn window(&self, page: usize) -> Range<usize> {
        let (first, end) = match self.apart.iter().find(|(pages, _)| pages.contains(&page)) {
            Some((pages, carry)) => (
                pages
                    .clone()
                    .map(|page| self.firsts[page])
                    .max()
                    .unwrap_or(1),
                carry.start,
            ),
            // Up to the carry stage the page shares with its group, if
            // it shares one, which is before the circuit's.
            None => (
                self.firsts[page],
                self.local_of(page)
                    .map_or(self.carry.start, |local| local.start),
            ),
        };
        first..end.max(first)
    }

    /// The gates of the carry stage page `page` shares with its group, if
    /// it shares one, beside the circuit's.
    pub fn local_of(&self, page: usize) -> Option<&Range<usize>> {
        self.local
            .iter()
            .find(|(pages, _)| pages.contains(&page))
            .map(|(_, gates)| gates)
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
    /// The slots of each group's carry stage, for the pages apart.
    pub apart: Vec<usize>,
    /// The slots of each group's carry stage, for the pages that share
    /// one.
    pub local: Vec<usize>,
}

/// Whose wires a carry slot combines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// A page's own.
    Page(u32),
    /// A stage's.
    Stage(u32),
}

/// A carry slot a constraint reads off its home page.
#[derive(Clone, Debug)]
struct Link<F> {
    source: Source,
    /// The page that holds the slot to its wires: the source page, or the
    /// first page that loads the source stage.
    exporter: u32,
    slot: u32,
    /// The constraint names `scale` times the slot's combination.
    scale: F,
    /// Whether this constraint is the first to name the slot: the one its
    /// exporter holds the slot to.
    defines: bool,
    /// Whether the slot is of the carry stage the home page shares with
    /// its group, the exporter among them, rather than of the one it
    /// loads otherwise.
    local: bool,
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
    /// The slots of each group's carry stage, for the pages apart. A
    /// constraint's slots are of the carry stage its home page loads.
    apart: Vec<Vec<Vec<(u32, F)>>>,
    /// The slots of each group's carry stage, for the pages that share
    /// one.
    local: Vec<Vec<Vec<(u32, F)>>>,
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
    /// the last carry stage it loads, or of its own gates if it loads none.
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
        let groups = self
            .apart
            .iter()
            .zip(&self.layout.apart)
            .chain(self.local.iter().zip(&self.layout.local));
        let carries = core::iter::once((&self.slots, &self.layout.carry))
            .chain(groups.map(|(slots, (_, carry))| (slots, carry)));
        for (slots, carry) in carries {
            let holds = carry.len().saturating_mul(2);
            if slots.len() > holds {
                return refuse(format!(
                    "the circuit carries {} values between pages, more than the {holds} their \
                     carry stage holds",
                    slots.len(),
                ));
            }
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
}

/// The pages a circuit was cut into, apart from the circuit: what
/// [`Paged::planned`] takes to page the same circuit again without cutting
/// it again.
#[derive(Clone, Debug)]
pub struct Planned<F: Field> {
    plan: Arc<Plan<F>>,
    report: PagingReport,
}
