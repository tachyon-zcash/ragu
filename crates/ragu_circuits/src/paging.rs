//! Experimental paging: one circuit laid out over several trace polynomials.
//!
//! A circuit that needs more gates than a polynomial holds is cut into
//! *pages*, in the order it allocates its gates but for the gates it
//! allocates long before it uses them, which are placed with the first
//! gate they feed. Each page is an ordinary [`Circuit`]
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
//! gates, fixes each constraint's home and slots; every other walk of a page
//! follows it by position.
//!
//! The carry stage's gates come after a page's own, so a page emits the
//! constraints that name a slot once the circuit is walked, in the order
//! the circuit emitted them.
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

use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    format,
    string::String,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{marker::PhantomData, ops::Range};

use ragu_core::{
    Coeff, Error, Result,
    convert::WireMap,
    drivers::{DirectSum, Driver, DriverTypes, DriverValue, LinearExpression},
    gadgets::{Bound, Gadget},
    maybe::Empty,
};
use udon::field::Field;

use crate::{
    Blind, Circuit, MaskObject, WithAux,
    polynomials::{Rank, sparse},
    raw::{self, CircuitAdapterRef, RawCircuit},
    staging::{self, MultiStageCircuit, Stage},
    trace::Trace,
};

/// The flag of a planning wire that names a linear combination rather than
/// the wire of a gate.
const DERIVED: u32 = 1 << 31;

/// The planning `ONE` wire: the $d$ wire of the SYSTEM gate.
const ONE: u32 = 3;

/// The places among a circuit's gates at which a cut is looked for.
const GRID: usize = 1024;

/// What a value on the circuit's carry stage, which every page loads,
/// counts for against one on a carry stage that a group of pages shares,
/// where the cuts are looked for.
const SHARED: u64 = 4;

/// The rounds a cut's carry stages are sized halfway to what they turned
/// out to hold before they only grow.
const SETTLING: usize = 24;

/// What a carried value counts for where the cuts are looked for: a
/// stage's wire that several stretches of the circuit read counts for a
/// part of it in each.
const UNIT: u64 = 1 << 10;

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

/// What the cuts of a circuit are weighed by, for one order of its gates:
/// the same whatever the carry stages' sizes, so it is counted once and
/// the cuts looked for under each size off it.
struct Costs {
    /// The gates of the circuit's own between two places a page may end
    /// at.
    step: usize,
    /// Those places, the last included.
    places: usize,
    /// For each stage, what the gates before each place read of it.
    reads: Vec<Vec<u64>>,
    /// For each place, the wires of the circuit's own allocated before it
    /// that a constraint past it names.
    crossing: Vec<i64>,
}

impl Costs {
    /// Counts them for `recording` with its gates in `placement`'s order,
    /// the constraints `related` gives the pages apart aside.
    fn of<F: Field>(
        recording: &Recording<F>,
        placement: &Placement,
        stages: &Stages,
        related: &Related<F>,
    ) -> Self {
        let own_start = stages.own_start();
        let own = recording.num_gates.saturating_sub(own_start);
        // The places a page may end at, as gates of the circuit's own
        // before them: every `step`-th, and the last.
        let step = own.div_ceil(GRID).max(1);
        let places = own.div_ceil(step);

        // What each stretch between two places reads of each stage, and
        // for each place the wires of the circuit's own allocated before
        // it that a constraint past it names. A stage's wire is carried
        // once however many constraints name it, so it counts for one
        // [`UNIT`] over all the stretches that read it.
        let mut reads = vec![vec![0u64; places + 1]; stages.spans.len()];
        let mut read: BTreeSet<(u32, usize)> = BTreeSet::new();
        let mut named: BTreeMap<u32, usize> = BTreeMap::new();
        let place = |gate: usize| placement.place(gate).map(|place| place - own_start);
        for (index, (emitted, terms)) in recording.constraints.iter().enumerate() {
            if related.holds(index) {
                continue;
            }
            // The constraint's home is the page of the last gate it names,
            // or else of the last gate allocated before it.
            let Some(position) = terms
                .iter()
                .filter_map(|&(wire, _)| place((wire / 4) as usize))
                .max()
                .or_else(|| emitted.checked_sub(1).and_then(place))
            else {
                continue;
            };
            for &(wire, _) in terms {
                match stages.stage_of((wire / 4) as usize) {
                    Some(_) => {
                        read.insert((wire, position / step + 1));
                    }
                    None if wire >= 4 => {
                        let last = named.entry(wire).or_insert(position);
                        *last = (*last).max(position);
                    }
                    None => {}
                }
            }
        }
        let mut stretches: BTreeMap<u32, u64> = BTreeMap::new();
        for &(wire, _) in &read {
            *stretches.entry(wire).or_default() += 1;
        }
        for &(wire, stretch) in &read {
            let (stage, _) = stages
                .stage_of((wire / 4) as usize)
                .expect("a stage's wire");
            reads[stage][stretch] += (UNIT / stretches[&wire]).max(1);
        }
        for stage in &mut reads {
            for place in 1..=places {
                stage[place] += stage[place - 1];
            }
        }
        let mut crossing = vec![0i64; places + 2];
        for (&wire, &last) in &named {
            let gate = place((wire / 4) as usize).expect("a gate of the circuit's own");
            // The places past the wire's gate and not past its last reader.
            let (from, to) = (gate / step + 1, last / step);
            if from <= to {
                crossing[from] += 1;
                crossing[to + 1] -= 1;
            }
        }
        for place in 1..crossing.len() {
            crossing[place] += crossing[place - 1];
        }

        Costs {
            step,
            places,
            reads,
            crossing,
        }
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
    /// The layout that shares `own` gates of a circuit's own among the
    /// pages of `stages` in proportion to the room each has before a carry
    /// stage of `carry_gates` gates that ends at gate `limit`.
    ///
    /// # Errors
    ///
    /// Fails if the pages do not have the room.
    pub fn fill(stages: &Stages, own: usize, limit: usize, carry_gates: usize) -> Result<Self> {
        let firsts: Vec<usize> = (0..stages.num_pages())
            .map(|page| stages.first(page))
            .collect();
        let short = || Error::GateBoundExceeded { limit };
        let carry = limit.checked_sub(carry_gates).ok_or_else(short)?..limit;
        let rooms = (0..firsts.len())
            .map(|page| stages.room(page, carry.start))
            .collect::<Option<Vec<usize>>>()
            .ok_or_else(short)?;
        // Carry stages that hold nothing, for the pages that share one.
        let local = stages
            .local
            .iter()
            .map(|pages| (pages.clone(), carry.start..carry.start))
            .collect();
        let (mut left, mut total) = (own, rooms.iter().sum::<usize>());
        if left > total {
            return Err(short());
        }
        // Each page in turn takes its share of what is left, so the shares
        // sum to `own` and none is more than its page's room.
        let mut starts = Vec::with_capacity(rooms.len());
        let mut next = stages.own_start();
        for room in rooms {
            starts.push(next);
            let share = if total == 0 {
                0
            } else {
                (left * room).div_ceil(total).min(room)
            };
            total -= room;
            left -= share;
            next += share;
        }
        Ok(Layout {
            own_start: stages.own_start(),
            starts,
            firsts,
            carry,
            // Carry stages that hold nothing, for the pages apart.
            apart: (0..stages.apart.len())
                .map(|group| (stages.group(group), limit..limit))
                .collect(),
            local,
        })
    }

    /// The layout that cuts `recording` into the pages of `stages`, before
    /// a carry stage of `carry_gates` gates that ends at gate `limit`, so
    /// that the pages carry little: a page ends where few of the wires
    /// before are named after, and holds the constraints that name little
    /// of the stages it does not load. The cuts are looked for on a grid
    /// of [`GRID`] places at most, and what a cut carries is counted with
    /// repeats, so the layout is a good one rather than the best. The
    /// pages apart hold what `related` gives them, before carry stages of
    /// their own that end at gate `limit` too, and each group of pages
    /// that share a carry stage has one of `local_gates` gates right
    /// before the circuit's. What a page can read off such a stage counts
    /// for a part of what it reads off the circuit's ([`SHARED`]), which
    /// every page gives its gates to.
    fn fit<F: Field>(
        costs: &Costs,
        num_gates: usize,
        stages: &Stages,
        limit: usize,
        (carry_gates, local_gates): (usize, &[usize]),
        related: &Related<F>,
    ) -> Result<Self> {
        let short = || Error::GateBoundExceeded { limit };
        let pages = stages.num_pages();
        let own_start = stages.own_start();
        let own = num_gates.saturating_sub(own_start);
        let firsts: Vec<usize> = (0..pages).map(|page| stages.first(page)).collect();
        let carry = limit.checked_sub(carry_gates).ok_or_else(short)?..limit;
        let local = stages
            .local
            .iter()
            .zip(local_gates)
            .map(|(pages, &gates)| {
                Some((pages.clone(), carry.start.checked_sub(gates)?..carry.start))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(short)?;
        let rooms = (0..firsts.len())
            .map(|page| {
                let end = stages
                    .local_of(page)
                    .map_or(carry.start, |group| local[group].1.start);
                stages.room(page, end)
            })
            .collect::<Option<Vec<usize>>>()
            .ok_or_else(short)?;

        // The places a page may end at, as gates of the circuit's own
        // before them: every `step`-th, and the last.
        let Costs {
            step,
            places,
            reads,
            crossing,
        } = costs;
        let (step, places) = (*step, *places);
        let before = |place: usize| (place * step).min(own);

        // The least a cut of the gates before each place into the pages so
        // far carries, and where the last of those pages then starts.
        const NONE: u64 = u64::MAX;
        let mut least = vec![NONE; places + 1];
        least[0] = 0;
        let mut cuts: Vec<Vec<usize>> = Vec::with_capacity(pages);
        for (page, &room) in rooms.iter().enumerate() {
            // What the page carries of the stages it does not load, if it
            // holds everything before each place.
            // A stage a page of its group loads is read off the group's
            // own carry stage.
            let weight = |stage: usize| match stages.local_of(page) {
                Some(group)
                    if stages.local[group]
                        .clone()
                        .any(|of| stages.loaded(of, stage)) =>
                {
                    1
                }
                _ => SHARED,
            };
            let foreign: Vec<u64> = (0..=places)
                .map(|place| {
                    (0..stages.spans.len())
                        .filter(|&stage| !stages.loaded(page, stage))
                        .map(|stage| weight(stage) * reads[stage][place])
                        .sum()
                })
                .collect();
            // What crosses to the next page is carried on their own
            // carry stage if they share one.
            let across = match stages.local_of(page) {
                Some(group) if stages.local_of(page + 1) == Some(group) => 1,
                _ => SHARED,
            };
            let mut next = vec![NONE; places + 1];
            let mut from = vec![0; places + 1];
            for end in 0..=places {
                for start in (0..=end).rev() {
                    if before(end) - before(start) > room {
                        break;
                    }
                    if least[start] == NONE {
                        continue;
                    }
                    let crossed = if start < end && end < places {
                        across * UNIT * crossing[end] as u64
                    } else {
                        0
                    };
                    let carried = least[start] + foreign[end] - foreign[start] + crossed;
                    if carried < next[end] {
                        (next[end], from[end]) = (carried, start);
                    }
                }
            }
            least = next;
            cuts.push(from);
        }
        if least[places] == NONE {
            return Err(short());
        }
        let mut starts = vec![0; pages];
        let mut end = places;
        for page in (0..pages).rev() {
            end = cuts[page][end];
            starts[page] = own_start + before(end);
        }
        Ok(Layout {
            own_start,
            starts,
            firsts,
            carry,
            apart: related.layout(stages, limit),
            local,
        })
    }

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
/// circuit and followed by every walk of a page.
#[derive(Clone, Debug)]
struct Plan<F> {
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
}

impl<F> Plan<F> {
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

/// A planning linear expression: its raw terms.
struct Terms<F> {
    terms: Vec<(u32, F)>,
    gain: F,
}

impl<F: Field> Terms<F> {
    fn new() -> Self {
        Terms {
            terms: Vec::new(),
            gain: F::ONE,
        }
    }
}

impl<F: Field> LinearExpression<u32, F> for Terms<F> {
    fn add_term(mut self, wire: &u32, coeff: Coeff<F>) -> Self {
        if !coeff.is_zero() {
            self.terms.push((*wire, coeff.value() * self.gain));
        }
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain *= coeff.value();
        self
    }
}

/// What one walk of a circuit emits, with every wire followed back to the
/// gates' wires.
struct Recording<F> {
    /// The gates the circuit allocates, the SYSTEM gate included.
    num_gates: usize,
    /// Each constraint, with the gates allocated when it was emitted.
    constraints: Vec<(usize, Vec<(u32, F)>)>,
    /// Each wire of the public output, in traversal order.
    outputs: Vec<Vec<(u32, F)>>,
}

/// The cuts made in this process, by a digest of what each was made of: a
/// circuit is cut once where it is registered and again each time it is
/// proven, to the same pages.
#[cfg(feature = "std")]
mod memo {
    extern crate std;

    use alloc::{boxed::Box, collections::BTreeMap};
    use core::any::Any;
    use std::sync::{Mutex, OnceLock, PoisonError};

    type Cuts = BTreeMap<[u8; 32], Box<dyn Any + Send + Sync>>;

    static CUTS: OnceLock<Mutex<Cuts>> = OnceLock::new();

    pub(super) fn get<T: Clone + 'static>(key: &[u8; 32]) -> Option<T> {
        let cuts = CUTS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        cuts.get(key)?.downcast_ref::<T>().cloned()
    }

    pub(super) fn put<T: Send + Sync + 'static>(key: [u8; 32], cut: T) {
        CUTS.get_or_init(Default::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, Box::new(cut));
    }
}

impl<F: Field> Recording<F> {
    /// A digest of the recording, the stages its pages load and the gates
    /// their polynomials hold: what a cut is a function of.
    #[cfg(feature = "std")]
    fn digest(&self, stages: &Stages, limit: usize) -> [u8; 32] {
        let mut state = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ragu_paging_cut_")
            .to_state();
        let mut word = |value: usize| {
            state.update(&(value as u64).to_le_bytes());
        };
        word(limit);
        word(usize::from(stages.sealed));
        let local: Vec<usize> = stages
            .local
            .iter()
            .flat_map(|pages| [pages.start, pages.end])
            .collect();
        for list in [&stages.idle, &stages.apart, &local]
            .into_iter()
            .chain(&stages.loads)
            .map(Vec::as_slice)
        {
            word(list.len());
            list.iter().for_each(|&entry| word(entry));
        }
        word(stages.spans.len());
        for span in &stages.spans {
            word(span.start);
            word(span.end);
        }
        word(self.num_gates);
        let lists = self
            .constraints
            .iter()
            .map(|(at, terms)| (*at, terms))
            .chain(self.outputs.iter().map(|terms| (usize::MAX, terms)));
        for (at, terms) in lists {
            word(at);
            word(terms.len());
        }
        state.update(core::any::type_name::<F>().as_bytes());
        for terms in self
            .constraints
            .iter()
            .map(|(_, terms)| terms)
            .chain(&self.outputs)
        {
            for (wire, coeff) in terms {
                state.update(&wire.to_le_bytes());
                state.update(coeff.to_bytes().as_ref());
            }
        }
        let mut digest = [0; 32];
        digest.copy_from_slice(state.finalize().as_bytes());
        digest
    }

    /// Walks `circuit`.
    fn of<C: Circuit<F>>(circuit: &C) -> Result<Self> {
        let mut dr = Prober {
            derived: Vec::new(),
            recording: Recording {
                num_gates: 0,
                constraints: Vec::new(),
                outputs: Vec::new(),
            },
        };
        walk(&mut dr, &CircuitAdapterRef(circuit))?;
        Ok(dr.recording)
    }
}

/// The gates `circuit` allocates, the SYSTEM gate included, and its
/// constraints, the wires of its public output included.
///
/// # Errors
///
/// Fails if the circuit cannot be walked.
pub fn size<F: Field, C: Circuit<F>>(circuit: &C) -> Result<(usize, usize)> {
    let recording = Recording::of(circuit)?;
    Ok((
        recording.num_gates,
        recording.constraints.len() + recording.outputs.len(),
    ))
}

/// What each of `parts` stretches of `circuit`'s own gates, in the order it
/// allocates them, reads of each of `stages`: the distinct wires of the
/// stage that the constraints of the stretch name, a constraint being of
/// the stretch of the last gate it names, or else of the last gate
/// allocated before it. It tells which stages a page of those gates is
/// best told to load.
///
/// # Errors
///
/// Fails if the circuit cannot be walked.
pub fn reads<F: Field, C: Circuit<F>>(
    circuit: &C,
    stages: &Stages,
    parts: usize,
) -> Result<Vec<Vec<usize>>> {
    let recording = Recording::of(circuit)?;
    let own_start = stages.own_start();
    let own = recording.num_gates.saturating_sub(own_start).max(1);
    let parts = parts.max(1);
    let mut read = vec![vec![BTreeSet::new(); stages.spans.len()]; parts];
    for (emitted, terms) in &recording.constraints {
        let gate = terms
            .iter()
            .map(|&(wire, _)| (wire / 4) as usize)
            .filter(|&gate| gate >= own_start)
            .max()
            .unwrap_or(emitted.saturating_sub(1));
        let part = (gate.saturating_sub(own_start) * parts / own).min(parts - 1);
        for &(wire, _) in terms {
            if let Some((stage, _)) = stages.stage_of((wire / 4) as usize) {
                read[part][stage].insert(wire);
            }
        }
    }
    Ok(read
        .into_iter()
        .map(|stages| stages.iter().map(BTreeSet::len).collect())
        .collect())
}

/// A combination a constraint names of one page's or one stage's wires, as
/// the slot that carries it holds it: scaled so that its first term's
/// coefficient is one. Gives the scale, the slot's combination and the key
/// two constraints that name the same combination share.
fn normalized<F: Field>(component: &[(u32, F)]) -> (F, Vec<(u32, F)>, Vec<u8>) {
    let scale = component[0].1;
    let inverse = scale.invert().expect("expanded terms are nonzero");
    let combination: Vec<(u32, F)> = component
        .iter()
        .map(|&(wire, coeff)| (wire, coeff * inverse))
        .collect();
    let mut key = Vec::new();
    for &(wire, coeff) in &combination {
        key.extend_from_slice(&wire.to_le_bytes());
        key.extend_from_slice(coeff.to_bytes().as_ref());
    }
    (scale, combination, key)
}

/// What the pages apart hold: the constraints that name the wires of
/// stages alone and that none of the other pages loads the stages of
/// together, each with its home page and its slots in the carry stage of
/// that page's group.
struct Related<F> {
    homes: BTreeMap<u32, (u32, Vec<Link<F>>)>,
    /// Each group's slots.
    slots: Vec<Vec<Vec<(u32, F)>>>,
}

impl<F: Field> Related<F> {
    /// Gives each such constraint of `recording` to the first group whose
    /// pages load every stage it names and whose carry stage, of
    /// `holds(group)` values, has a slot left for each combination the
    /// constraint names of a stage its home does not load. Its home is the
    /// group's first page that loads the last stage it names. A constraint
    /// no group takes is left to the other pages.
    fn of(recording: &Recording<F>, stages: &Stages, holds: impl Fn(usize) -> usize) -> Self {
        let groups = stages.apart.len();
        let mut related = Related {
            homes: BTreeMap::new(),
            slots: vec![Vec::new(); groups],
        };
        if groups == 0 || stages.check().is_err() {
            return related;
        }
        let others = stages.num_apart()..stages.num_pages();
        let mut keys: Vec<BTreeMap<Vec<u8>, u32>> = vec![BTreeMap::new(); groups];
        'constraints: for (index, (_, terms)) in recording.constraints.iter().enumerate() {
            let mut staged: BTreeMap<usize, Vec<(u32, F)>> = BTreeMap::new();
            for &(wire, coeff) in terms {
                let gate = (wire / 4) as usize;
                if gate == 0 {
                    continue;
                }
                match stages.stage_of(gate) {
                    Some((stage, _)) => staged.entry(stage).or_default().push((wire, coeff)),
                    None => continue 'constraints,
                }
            }
            let loads_all = |page: usize| staged.keys().all(|&stage| stages.loaded(page, stage));
            if staged.len() < 2 || others.clone().any(loads_all) {
                continue;
            }
            let carries = keys.iter_mut().zip(related.slots.iter_mut());
            for (group, (keys, slots)) in carries.enumerate() {
                let loader =
                    |stage: usize| stages.group(group).find(|&page| stages.loaded(page, stage));
                let Some(home) = staged.keys().next_back().and_then(|&stage| loader(stage)) else {
                    continue;
                };
                let foreign: Option<Vec<_>> = staged
                    .iter()
                    .filter(|&(&stage, _)| !stages.loaded(home, stage))
                    .map(|(&stage, component)| Some((stage, loader(stage)?, normalized(component))))
                    .collect();
                let Some(foreign) = foreign else {
                    continue;
                };
                let fresh = foreign
                    .iter()
                    .map(|(_, _, (_, _, key))| key)
                    .filter(|key| !keys.contains_key(*key))
                    .collect::<BTreeSet<_>>()
                    .len();
                if slots.len() + fresh > holds(group) {
                    continue;
                }
                let links = foreign
                    .into_iter()
                    .map(|(stage, exporter, (scale, combination, key))| {
                        let next = u32::try_from(slots.len()).expect("slots fit a u32");
                        let (slot, defines) = match keys.entry(key) {
                            Entry::Vacant(entry) => {
                                entry.insert(next);
                                slots.push(combination);
                                (next, true)
                            }
                            Entry::Occupied(entry) => (*entry.get(), false),
                        };
                        Link {
                            source: Source::Stage(stage as u32),
                            exporter: exporter as u32,
                            slot,
                            scale,
                            defines,
                            local: false,
                        }
                    })
                    .collect();
                let index = u32::try_from(index).expect("constraints fit a u32");
                related.homes.insert(index, (home as u32, links));
                break;
            }
        }
        related
    }

    /// Whether a page apart holds constraint `index`.
    fn holds(&self, index: usize) -> bool {
        u32::try_from(index).is_ok_and(|index| self.homes.contains_key(&index))
    }

    /// Each group's pages and the gates of its carry stage, which ends at
    /// gate `limit` and is as large as its slots take.
    fn layout(&self, stages: &Stages, limit: usize) -> Vec<(Range<usize>, Range<usize>)> {
        self.slots
            .iter()
            .enumerate()
            .map(|(group, slots)| {
                let gates = slots.len().div_ceil(2);
                (stages.group(group), limit.saturating_sub(gates)..limit)
            })
            .collect()
    }
}

/// Which of the gates that feed a gate a [`Placement`] places first.
#[derive(Clone, Copy)]
enum Feeders {
    /// The one with the longest chain of gates behind it.
    Deepest,
    /// The one the circuit allocates last.
    Latest,
}

/// The order a recording's own gates are placed in.
///
/// A gate *feeds* the last gate named by a constraint that names both. The
/// gates are placed as a walk back from each gate that feeds nothing finds
/// them: before a gate come the gates that feed it and are not placed yet.
/// Most gates feed the next ones and stay where the circuit allocates
/// them. Gates allocated long before their use, as a batch of inverses is
/// before the sums that take them or the powers of a challenge before the
/// terms they scale, come right before it instead, so that a cut between
/// the two carries only what the gates on both sides share.
///
/// Which of a gate's feeders the walk looks at first decides what waits
/// while the others are placed, and no one way suits every circuit: the
/// feeder with the longest chain of gates behind it ([`Feeders::Deepest`])
/// or the one allocated last ([`Feeders::Latest`]). A cut is looked for in
/// each order, and in the order the circuit allocates its gates in.
struct Placement {
    own_start: usize,
    /// For each gate of the circuit's own, in the order it allocates them,
    /// its place.
    rank: Vec<u32>,
}

impl Placement {
    /// The order the circuit allocates its gates in.
    fn allocated<F: Field>(recording: &Recording<F>, own_start: usize) -> Self {
        let own = recording.num_gates.saturating_sub(own_start);
        Placement {
            own_start,
            rank: (0..own as u32).collect(),
        }
    }

    fn of<F: Field>(recording: &Recording<F>, own_start: usize, first: Feeders) -> Self {
        /// The gates of the circuit's own that a constraint names,
        /// counted from the first of them.
        fn named<F>(terms: &[(u32, F)], own_start: usize) -> impl Iterator<Item = u32> + '_ {
            terms
                .iter()
                .map(|&(wire, _)| (wire / 4) as usize)
                .filter(move |&gate| gate >= own_start)
                .map(move |gate| (gate - own_start) as u32)
        }
        let own = recording.num_gates.saturating_sub(own_start);
        // For each gate, the gates that feed it and whether it feeds any.
        let mut feeders: Vec<Vec<u32>> = vec![Vec::new(); own];
        let mut feeds = vec![false; own];
        for (_, terms) in &recording.constraints {
            let Some(last) = named(terms, own_start).max() else {
                continue;
            };
            for gate in named(terms, own_start).filter(|&gate| gate < last) {
                feeders[last as usize].push(gate);
                feeds[gate as usize] = true;
            }
        }
        // The longest chain of gates behind each gate, and each gate's
        // feeders in the order the walk looks at them.
        let mut depth = vec![0u32; own];
        for gate in 0..own {
            let behind = feeders[gate].iter().map(|&feeder| depth[feeder as usize]);
            depth[gate] = behind.max().map_or(0, |depth| depth + 1);
            match first {
                Feeders::Deepest => feeders[gate].sort_unstable_by_key(|&feeder| {
                    (core::cmp::Reverse(depth[feeder as usize]), feeder)
                }),
                Feeders::Latest => feeders[gate].sort_unstable_by(|a, b| b.cmp(a)),
            }
            feeders[gate].dedup();
        }

        let mut rank = vec![u32::MAX; own];
        let mut placed = 0;
        // A gate waits on the stack, with the feeders it has yet to look
        // at, until every gate that feeds it is placed.
        let mut waiting: Vec<(u32, usize)> = Vec::new();
        for root in (0..own as u32).filter(|&gate| !feeds[gate as usize]) {
            waiting.push((root, 0));
            while let Some((gate, next)) = waiting.pop() {
                match feeders[gate as usize][next..]
                    .iter()
                    .position(|&feeder| rank[feeder as usize] == u32::MAX)
                {
                    Some(skipped) => {
                        let feeder = feeders[gate as usize][next + skipped];
                        waiting.push((gate, next + skipped + 1));
                        waiting.push((feeder, 0));
                    }
                    None if rank[gate as usize] == u32::MAX => {
                        rank[gate as usize] = placed;
                        placed += 1;
                    }
                    None => {}
                }
            }
        }
        debug_assert_eq!(
            placed as usize, own,
            "every gate feeds one that feeds nothing"
        );
        Placement { own_start, rank }
    }

    /// The place of a gate counted over the whole circuit, counted from
    /// the first of the circuit's own likewise.
    fn place(&self, gate: usize) -> Option<usize> {
        let rank = *self.rank.get(gate.checked_sub(self.own_start)?)?;
        Some(self.own_start + rank as usize)
    }
}

/// The planning driver: its wires are the gates' wires or linear
/// combinations of them, kept expanded.
struct Prober<F> {
    /// The linear combinations [`Driver::add`] made, each over gates'
    /// wires and the combinations made before it.
    derived: Vec<Vec<(u32, F)>>,
    recording: Recording<F>,
}

impl<F: Field> Prober<F> {
    /// Expands raw terms into a combination of gates' wires, in wire order
    /// and without zero terms.
    ///
    /// A combination names only combinations made before it, so the ones
    /// the terms reach are taken latest first, each once with all it
    /// counts for: a sum built one term at a time expands in one pass
    /// over its terms, and a combination that several others name is not
    /// walked again for each.
    fn expand(&self, terms: Vec<(u32, F)>) -> Vec<(u32, F)> {
        let mut sum: BTreeMap<u32, F> = BTreeMap::new();
        let mut pending: BTreeMap<u32, F> = BTreeMap::new();
        let mut take = |pending: &mut BTreeMap<u32, F>, wire: u32, coeff: F| {
            let (into, key) = if wire & DERIVED == 0 {
                (&mut sum, wire)
            } else {
                (pending, wire ^ DERIVED)
            };
            *into.entry(key).or_insert(F::ZERO) += coeff;
        };
        for (wire, coeff) in terms {
            take(&mut pending, wire, coeff);
        }
        while let Some((index, coeff)) = pending.pop_last() {
            for &(inner, scale) in &self.derived[index as usize] {
                take(&mut pending, inner, scale * coeff);
            }
        }
        sum.into_iter()
            .filter(|(_, coeff)| !coeff.is_zero())
            .collect()
    }
}

impl<F: Field> DriverTypes for Prober<F> {
    type ImplField = F;
    type ImplWire = u32;
    type MaybeKind = Empty;
    type LCadd = Terms<F>;
    type LCenforce = Terms<F>;
    type Extra = u32;

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(u32, u32, u32, u32)> {
        let gate = u32::try_from(self.recording.num_gates).expect("gate indices fit a wire");
        assert!(gate < DERIVED / 4, "gate indices fit a wire");
        self.recording.num_gates += 1;
        Ok((4 * gate, 4 * gate + 1, 4 * gate + 2, 4 * gate + 3))
    }

    fn assign_extra(&mut self, extra: u32, _: impl Fn() -> Result<Coeff<F>>) -> Result<u32> {
        Ok(extra)
    }
}

impl<'dr, F: Field> Driver<'dr> for Prober<F> {
    type F = F;
    type Wire = u32;
    const ONE: u32 = ONE;

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> u32 {
        // Kept as made: a combination is expanded where a constraint or
        // the public output names it.
        let terms = lc(Terms::new()).terms;
        if let [(wire, coeff)] = terms[..]
            && coeff == F::ONE
        {
            return wire;
        }
        let index = u32::try_from(self.derived.len()).expect("combinations fit a wire");
        assert!(index < DERIVED, "combinations fit a wire");
        self.derived.push(terms);
        DERIVED | index
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let expanded = self.expand(lc(Terms::new()).terms);
        let at = self.recording.num_gates;
        self.recording.constraints.push((at, expanded));
        Ok(())
    }
}

/// Records each wire of the public output.
struct Recorder<'a, F: Field>(&'a mut Prober<F>);

impl<F: Field> WireMap<F> for Recorder<'_, F> {
    type Src = Prober<F>;
    type Dst = Prober<F>;

    fn convert_wire(&mut self, wire: &u32) -> Result<u32> {
        let expanded = self.0.expand(vec![(*wire, F::ONE)]);
        self.0.recording.outputs.push(expanded);
        Ok(*wire)
    }
}

/// Walks `circuit` on the planning driver.
fn walk<'dr, F: Field, RC: RawCircuit<F> + 'dr>(dr: &mut Prober<F>, circuit: &RC) -> Result<()> {
    // The SYSTEM gate, which the pages' walks find already allocated.
    let (_, _, _, extra) = dr.gate(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
    dr.assign_extra(extra, || Ok(Coeff::Zero))?;

    let output = circuit.witness(dr, Empty)?.into_output();
    output.map(&mut Recorder(dr))?;
    Ok(())
}

#[derive(Default)]
struct PageAcc {
    constraints: usize,
    imported_wires: BTreeSet<u32>,
    imported_slots: BTreeSet<u32>,
    exported_wires: BTreeSet<u32>,
    stage_wires: BTreeSet<u32>,
}

/// Homes a recording's constraints on the pages of a layout.
struct Arranger<'a, F> {
    own_start: usize,
    /// The page of each gate of the circuit's own.
    places: &'a [(u32, u32)],
    stages: &'a Stages,
    slots: Vec<Vec<(u32, F)>>,
    slot_keys: BTreeMap<Vec<u8>, u32>,
    /// The slots of each group's carry stage, for the pages that share
    /// one, and their keys.
    local: Vec<(Vec<Vec<(u32, F)>>, BTreeMap<Vec<u8>, u32>)>,
    pages: Vec<PageAcc>,
    cross_constraints: usize,
    /// Each carried wire, with the last page that names it.
    carried: BTreeMap<u32, usize>,
}

impl<F: Field> Arranger<'_, F> {
    /// The page of a gate of the circuit's own, counted over the whole
    /// circuit.
    fn page_of(&self, gate: usize) -> Option<usize> {
        let (page, _) = self.places.get(gate.checked_sub(self.own_start)?)?;
        Some(*page as usize)
    }

    /// The page that holds slots to stage `stage`'s wires for page `home`.
    fn exporter(&self, stage: usize, home: usize) -> Result<usize> {
        match self.stages.exporter(stage, home) {
            Some(page) => Ok(page),
            None => refuse(format!(
                "no page loads stage {stage}, which the circuit reads"
            )),
        }
    }

    /// Homes a constraint emitted with `at` gates allocated, on `home` or
    /// else on the last page it names a wire of, and gives the slots it
    /// reads off that page.
    fn home(
        &mut self,
        lc: &[(u32, F)],
        home: Option<usize>,
        at: usize,
    ) -> Result<(usize, Vec<Link<F>>)> {
        let mut own: BTreeMap<usize, Vec<(u32, F)>> = BTreeMap::new();
        let mut staged: BTreeMap<usize, Vec<(u32, F)>> = BTreeMap::new();
        for &(wire, coeff) in lc {
            let gate = (wire / 4) as usize;
            if gate == 0 {
                continue;
            }
            match self.stages.stage_of(gate) {
                Some((stage, _)) => staged.entry(stage).or_default().push((wire, coeff)),
                None => {
                    let page = self
                        .page_of(gate)
                        .expect("a gate past the stages is the circuit's own");
                    own.entry(page).or_default().push((wire, coeff));
                }
            }
        }

        let home = match (home, own.keys().next_back()) {
            (Some(home), _) => home,
            (None, Some(&page)) => page,
            // Only stages' wires: the page the walk is on if it loads them
            // all, or else one that loads the last of them.
            (None, None) => {
                let here = at
                    .checked_sub(1)
                    .and_then(|gate| self.page_of(gate))
                    .unwrap_or(self.stages.num_apart());
                match staged.keys().next_back() {
                    Some(&last) if !staged.keys().all(|&s| self.stages.loaded(here, s)) => {
                        self.exporter(last, here)?
                    }
                    _ => here,
                }
            }
        };
        let acc = &mut self.pages[home];
        acc.constraints += 1;
        acc.stage_wires
            .extend(staged.values().flatten().map(|&(wire, _)| wire));

        let mut foreign = Vec::new();
        for (page, component) in own {
            if page != home {
                foreign.push((Source::Page(page as u32), page, component));
            }
        }
        for (stage, component) in staged {
            if !self.stages.loaded(home, stage) {
                foreign.push((
                    Source::Stage(stage as u32),
                    self.exporter(stage, home)?,
                    component,
                ));
            }
        }

        let mut links = Vec::new();
        for (source, exporter, component) in foreign {
            let (scale, normalized, key) = normalized(&component);
            for &(wire, _) in &normalized {
                let last = self.carried.entry(wire).or_insert(home);
                *last = (*last).max(home);
                self.pages[home].imported_wires.insert(wire);
                self.pages[exporter].exported_wires.insert(wire);
            }
            // On the carry stage the two pages share, if they share one.
            let shared = self
                .stages
                .local_of(home)
                .filter(|&group| self.stages.local_of(exporter) == Some(group));
            let (slots, keys) = match shared {
                Some(group) => {
                    let (slots, keys) = &mut self.local[group];
                    (slots, keys)
                }
                None => (&mut self.slots, &mut self.slot_keys),
            };
            let next = u32::try_from(slots.len()).expect("slots fit a u32");
            let (slot, defines) = match keys.entry(key) {
                Entry::Vacant(entry) => {
                    entry.insert(next);
                    slots.push(normalized);
                    (next, true)
                }
                Entry::Occupied(entry) => (*entry.get(), false),
            };
            let local = shared.is_some();
            self.pages[home]
                .imported_slots
                .insert(slot | (u32::from(local) << 31));
            links.push(Link {
                source,
                exporter: u32::try_from(exporter).expect("pages fit a u32"),
                slot,
                scale,
                defines,
                local,
            });
        }
        if !links.is_empty() {
            self.cross_constraints += 1;
        }
        Ok((home, links))
    }
}

/// Homes `recording`'s constraints on the pages of `layout`: those
/// `related` holds on the pages apart, and the rest on the others.
fn arrange<F: Field>(
    recording: &Recording<F>,
    placement: &Placement,
    stages: &Stages,
    layout: Layout,
    related: &Related<F>,
) -> Result<(Plan<F>, PagingReport)> {
    stages.check()?;
    let pages = stages.num_pages();
    let num_gates = recording.num_gates;
    if layout.own_start != stages.own_start() || num_gates < layout.own_start {
        return refuse(format!(
            "the circuit's {num_gates} gates do not follow its stages', which end at gate {}",
            stages.own_start()
        ));
    }
    if layout.starts.len() != pages
        || layout.firsts.len() != pages
        || layout.starts[0] != layout.own_start
        || layout.starts.windows(2).any(|pair| pair[0] > pair[1])
        || layout.starts[pages - 1] > num_gates
    {
        return refuse(format!(
            "a layout of {} pages does not cut the circuit's gates into its {pages} pages",
            layout.starts.len()
        ));
    }
    if layout.apart.len() != stages.apart.len()
        || layout.apart.iter().enumerate().any(|(group, (of, carry))| {
            *of != stages.group(group) || of.clone().any(|page| carry.start < layout.firsts[page])
        })
    {
        return refuse(
            "a layout's carry stages for the pages apart are not one for each group of them, \
             past what its pages load"
                .into(),
        );
    }
    if layout.local.len() != stages.local.len()
        || layout
            .local
            .iter()
            .zip(&stages.local)
            .any(|((of, gates), pages)| {
                of != pages
                    || gates.end > layout.carry.start
                    || of.clone().any(|page| gates.start < layout.firsts[page])
            })
    {
        return refuse(
            "a layout's carry stages for the pages that share one are not one for each group \
             of them, past what its pages load and before the circuit's"
                .into(),
        );
    }
    for page in 0..pages {
        let end = layout.starts.get(page + 1).copied().unwrap_or(num_gates);
        let gates = end - layout.starts[page];
        let idle = (stages.idle.contains(&page) || page < stages.num_apart()) && gates > 0;
        if layout.firsts[page] < stages.first(page) || gates > layout.room(page) || idle {
            return refuse(format!(
                "page {page} holds {gates} gates of the circuit's own from gate {}, which the \
                 stages it loads, up to gate {}, and the carry stage, from gate {}, leave no \
                 room for",
                layout.firsts[page],
                stages.first(page),
                layout.carry_of(page).start,
            ));
        }
    }

    // Each gate's page, and its index there: a page's polynomial holds
    // its gates in the order the circuit allocates them.
    let mut held: Vec<Vec<u32>> = vec![Vec::new(); pages];
    let mut places = Vec::with_capacity(num_gates - layout.own_start);
    for gate in layout.own_start..num_gates {
        let page = placement
            .place(gate)
            .and_then(|place| layout.page_of(place))
            .expect("a gate of the circuit's own has a place");
        places.push((page as u32, (layout.firsts[page] + held[page].len()) as u32));
        held[page].push(gate as u32);
    }

    let mut arranger = Arranger {
        own_start: layout.own_start,
        places: &places,
        stages,
        slots: Vec::new(),
        slot_keys: BTreeMap::new(),
        local: stages
            .local
            .iter()
            .map(|_| (Vec::new(), BTreeMap::new()))
            .collect(),
        pages: (0..pages).map(|_| PageAcc::default()).collect(),
        cross_constraints: 0,
        carried: BTreeMap::new(),
    };
    let mut homes = Vec::with_capacity(recording.constraints.len());
    let mut links = BTreeMap::new();
    for (index, (at, terms)) in recording.constraints.iter().enumerate() {
        let index = u32::try_from(index).expect("constraints fit a u32");
        let (home, read) = match related.homes.get(&index) {
            Some((home, read)) => {
                arranger.pages[*home as usize].constraints += 1;
                (*home as usize, read.clone())
            }
            None => arranger.home(terms, None, *at)?,
        };
        homes.push(u32::try_from(home).expect("pages fit a u32"));
        if !read.is_empty() {
            links.insert(index, read);
        }
    }
    // The public output binds one instance polynomial, so one page holds
    // every wire of it: the last.
    let mut outputs = Vec::with_capacity(recording.outputs.len());
    for terms in &recording.outputs {
        outputs.push(arranger.home(terms, Some(pages - 1), num_gates)?.1);
    }

    let cuts = (0..pages - 1)
        .map(|boundary| {
            arranger
                .carried
                .iter()
                .filter(|&(&wire, &last)| {
                    arranger
                        .page_of((wire / 4) as usize)
                        .is_some_and(|page| page <= boundary && boundary < last)
                })
                .count()
        })
        .collect();
    let report = PagingReport {
        num_gates,
        num_constraints: homes.len() + outputs.len(),
        pages: arranger
            .pages
            .iter()
            .enumerate()
            .map(|(page, acc)| PageReport {
                gates: layout.starts.get(page + 1).copied().unwrap_or(num_gates)
                    - layout.starts[page],
                constraints: acc.constraints,
                imported_wires: acc.imported_wires.len(),
                imported_slots: acc.imported_slots.len(),
                exported_wires: acc.exported_wires.len(),
                stage_wires: acc.stage_wires.len(),
                stage_gates: acc
                    .stage_wires
                    .iter()
                    .map(|wire| (wire / 4) as usize)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            })
            .collect(),
        cross_constraints: arranger.cross_constraints,
        carried_wires: arranger.carried.len(),
        slots: arranger.slots.len(),
        cuts,
        apart: related.slots.iter().map(Vec::len).collect(),
        local: arranger
            .local
            .iter()
            .map(|(slots, _)| slots.len())
            .collect(),
    };
    let slots = arranger.slots;
    let local = arranger.local.into_iter().map(|(slots, _)| slots).collect();
    let plan = Plan {
        layout,
        stages: stages.clone(),
        num_gates,
        homes,
        links,
        outputs,
        slots,
        apart: related.slots.clone(),
        local,
        places,
        held,
    };
    Ok((plan, report))
}

/// A wire of a page's walk: what it holds of the page's own wires, of the
/// `ONE` wire, and of the wires of each stage the page loads.
#[derive(Clone)]
struct PageWire<W> {
    own: Option<W>,
    one: Option<W>,
    /// By stage, in stage order.
    stages: Vec<(u32, W)>,
}

impl<W> PageWire<W> {
    const ABSENT: Self = PageWire {
        own: None,
        one: None,
        stages: Vec::new(),
    };

    fn own(wire: W) -> Self {
        PageWire {
            own: Some(wire),
            one: None,
            stages: Vec::new(),
        }
    }

    fn stage(stage: u32, wire: W) -> Self {
        PageWire {
            own: None,
            one: None,
            stages: vec![(stage, wire)],
        }
    }

    /// The part over stage `stage`'s wires.
    fn of_stage(&self, stage: u32) -> Option<&W> {
        self.stages
            .iter()
            .find(|(of, _)| *of == stage)
            .map(|(_, wire)| wire)
    }
}

/// The token of a gate's $d$ wire in a page's walk.
enum PageExtra<W, E> {
    /// A gate of the page's own: the page's driver's token.
    Own(E),
    /// A gate of a stage the page loads: the wire, allocated already.
    Ready(PageWire<W>),
    Absent,
}

/// Which parts of its terms a page's linear expression takes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Select {
    All,
    Own,
    One,
    Stage(u32),
}

/// A step of a linear expression, kept to be made again.
enum Op<W, F: Field> {
    Term(W, Coeff<F>),
    Gain(Coeff<F>),
}

/// Makes `ops` again on `lc`.
fn replay<W: Clone, F: Field, L: LinearExpression<W, F>>(lc: L, ops: &[Op<W, F>]) -> L {
    ops.iter().fold(lc, |lc, op| match op {
        Op::Term(wire, coeff) => lc.add_term(wire, *coeff),
        Op::Gain(coeff) => lc.gain(*coeff),
    })
}

/// A page's linear expression: the selected parts of the terms, in the
/// page's driver's expression if there is one, or kept for later if they
/// are. It also notes which parts the terms have, which a walk needs even
/// of a driver that never evaluates an expression.
struct PageTerms<L, W, F: Field> {
    inner: Option<L>,
    kept: Option<Vec<Op<W, F>>>,
    select: Select,
    /// Whether a term has a part of the page's own wires.
    own: bool,
    /// Whether a term has a part of the `ONE` wire.
    one: bool,
    /// The stages a term has a part of.
    stages: Vec<u32>,
}

impl<L, W, F: Field> PageTerms<L, W, F> {
    fn new(inner: Option<L>, kept: Option<Vec<Op<W, F>>>, select: Select) -> Self {
        PageTerms {
            inner,
            kept,
            select,
            own: false,
            one: false,
            stages: Vec::new(),
        }
    }

    /// The selected parts, in `inner`.
    fn over(inner: L, select: Select) -> Self {
        Self::new(Some(inner), None, select)
    }

    /// The selected parts, kept.
    fn keeping(select: Select) -> Self {
        Self::new(None, Some(Vec::new()), select)
    }

    /// No expression: only which parts the terms have.
    fn parts() -> Self {
        Self::new(None, None, Select::All)
    }

    /// The page's driver's expression.
    fn into_inner(self) -> L {
        self.inner.expect("an expression over the page's driver")
    }

    /// The kept steps.
    fn into_kept(self) -> Vec<Op<W, F>> {
        self.kept.expect("a kept expression")
    }
}

impl<W: Clone, F: Field, L: LinearExpression<W, F>> PageTerms<L, W, F> {
    fn take(&mut self, wire: &W, coeff: Coeff<F>) {
        self.inner = self.inner.take().map(|inner| inner.add_term(wire, coeff));
        if let Some(kept) = &mut self.kept {
            kept.push(Op::Term(wire.clone(), coeff));
        }
    }
}

impl<W: Clone, F: Field, L: LinearExpression<W, F>> LinearExpression<PageWire<W>, F>
    for PageTerms<L, W, F>
{
    fn add_term(mut self, wire: &PageWire<W>, coeff: Coeff<F>) -> Self {
        if let Some(own) = &wire.own {
            self.own = true;
            if matches!(self.select, Select::All | Select::Own) {
                self.take(own, coeff);
            }
        }
        if let Some(one) = &wire.one {
            self.one = true;
            if matches!(self.select, Select::All | Select::One) {
                self.take(one, coeff);
            }
        }
        for (stage, part) in &wire.stages {
            if !self.stages.contains(stage) {
                self.stages.push(*stage);
            }
            if self.select == Select::All || self.select == Select::Stage(*stage) {
                self.take(part, coeff);
            }
        }
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.inner = self.inner.map(|inner| inner.gain(coeff));
        if let Some(kept) = &mut self.kept {
            kept.push(Op::Gain(coeff));
        }
        self
    }
}

fn diverged(what: &str) -> Error {
    Error::Initialization(
        format!("a page's walk of the circuit diverged from its plan: {what}").into(),
    )
}

/// A constraint that names slots of the carry stage, kept until the page
/// has allocated the carry stage's gates.
struct Deferred<W, F: Field> {
    /// The slots, each with whether it is of the carry stage the page
    /// shares with its group, and what the constraint multiplies each by.
    slots: Vec<((bool, u32), Coeff<F>)>,
    /// The rest of the constraint.
    ops: Vec<Op<W, F>>,
}

/// The driver a page walks the whole circuit on: it passes the page's own
/// gates and constraints to the page's driver and drops the other pages'.
struct Pager<'a, F: Field, D: DriverTypes<ImplField = F>> {
    inner: &'a mut D,
    plan: &'a Plan<F>,
    page: usize,
    /// The next gate, counted over the whole circuit. The SYSTEM gate is
    /// the page's driver's already.
    gate: usize,
    /// The next constraint, counted over the whole circuit.
    constraint: usize,
    /// The $a$, $b$, $c$ and $d$ wires of the gates before the page's own,
    /// from gate 1, once allocated: the gates of the stages it loads.
    prefix: Option<Vec<[D::ImplWire; 4]>>,
    /// The page's own gates allocated so far.
    own: usize,
    /// The constraints that wait for the carry stage.
    deferred: Vec<Deferred<D::ImplWire, F>>,
    /// The $a$ and $d$ wires of the carry stage's gates, once allocated.
    carry: Option<Vec<[D::ImplWire; 2]>>,
    /// Those of the gates of the carry stage the page shares with its
    /// group, if it shares one.
    local: Vec<[D::ImplWire; 2]>,
}

impl<'a, F: Field, D: DriverTypes<ImplField = F>> Pager<'a, F, D> {
    fn new(inner: &'a mut D, plan: &'a Plan<F>, page: usize) -> Self {
        Pager {
            inner,
            plan,
            page,
            gate: 1,
            constraint: 0,
            prefix: None,
            own: 0,
            deferred: Vec::new(),
            carry: None,
            local: Vec::new(),
        }
    }

    /// Allocates a gate the page gives no value.
    fn blank(&mut self) -> Result<[D::ImplWire; 4]> {
        let (a, b, c, extra) = self
            .inner
            .gate(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
        let d = self.inner.assign_extra(extra, || Ok(Coeff::Zero))?;
        Ok([a, b, c, d])
    }

    /// Allocates the gates before the page's own: where the polynomials of
    /// the stages it loads hold their values.
    fn reserve(&mut self) -> Result<()> {
        if self.prefix.is_some() {
            return Ok(());
        }
        let gates = self.plan.layout.firsts[self.page] - 1;
        let mut prefix = Vec::with_capacity(gates);
        for _ in 0..gates {
            prefix.push(self.blank()?);
        }
        self.prefix = Some(prefix);
        Ok(())
    }

    /// The wire of the carry stage that holds slot `slot`.
    fn slot(&self, (local, slot): (bool, u32)) -> Result<&D::ImplWire> {
        let carry = if local {
            Some(&self.local)
        } else {
            self.carry.as_ref()
        };
        carry
            .and_then(|carry| carry.get((slot / 2) as usize))
            .map(|wires| &wires[(slot % 2) as usize])
            .ok_or_else(|| diverged("a slot past the carry stage"))
    }
}

impl<F: Field, D: DriverTypes<ImplField = F>> Pager<'_, F, D> {
    /// Ends the page's own gates: allocates the carry stage's after them
    /// and emits the constraints that waited for it.
    fn seal<'dr>(&mut self) -> Result<()>
    where
        D: Driver<'dr, F = F>,
    {
        if self.carry.is_some() {
            return Ok(());
        }
        self.reserve()?;
        let plan = self.plan;
        let layout = &plan.layout;
        // The carry stage the page shares with its group, if it shares
        // one, then the one it loads otherwise, in gate order.
        let mut next = layout.firsts[self.page] + self.own;
        let mut carries = [Vec::new(), Vec::new()];
        let stages = [layout.local_of(self.page), Some(layout.carry_of(self.page))];
        for (gates, wires) in stages.into_iter().zip(&mut carries) {
            let Some(gates) = gates.filter(|gates| !gates.is_empty()) else {
                continue;
            };
            let blanks = gates
                .start
                .checked_sub(next)
                .ok_or_else(|| diverged("a page's gates reach a carry stage"))?;
            for _ in 0..blanks {
                self.blank()?;
            }
            for _ in gates.clone() {
                let [a, _, _, d] = self.blank()?;
                wires.push([a, d]);
            }
            next = gates.end;
        }
        let [local, carry] = carries;
        self.local = local;
        self.carry = Some(carry);

        for deferred in core::mem::take(&mut self.deferred) {
            let slots = deferred
                .slots
                .iter()
                .map(|&(slot, coeff)| Ok((self.slot(slot)?.clone(), coeff)))
                .collect::<Result<Vec<_>>>()?;
            self.inner.enforce_zero(|lc| {
                let lc = slots
                    .iter()
                    .fold(lc, |lc, (wire, coeff)| lc.add_term(wire, *coeff));
                replay(lc, &deferred.ops)
            })?;
        }
        Ok(())
    }

    /// Ends the walk: the circuit must have emitted what its plan saw.
    fn finish<'dr>(mut self) -> Result<()>
    where
        D: Driver<'dr, F = F>,
    {
        self.seal()?;
        if self.gate != self.plan.num_gates || self.constraint != self.plan.homes.len() {
            return Err(diverged(&format!(
                "page {} saw {} gates and {} constraints where the plan has {} and {}",
                self.page,
                self.gate,
                self.constraint,
                self.plan.num_gates,
                self.plan.homes.len(),
            )));
        }
        Ok(())
    }
}

impl<F: Field, D: DriverTypes<ImplField = F>> DriverTypes for Pager<'_, F, D> {
    type ImplField = F;
    type ImplWire = PageWire<D::ImplWire>;
    type MaybeKind = D::MaybeKind;
    type LCadd = PageTerms<D::LCadd, D::ImplWire, F>;
    type LCenforce = PageTerms<D::LCenforce, D::ImplWire, F>;
    type Extra = PageExtra<D::ImplWire, D::Extra>;

    fn gate(
        &mut self,
        values: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::ImplWire, Self::ImplWire, Self::ImplWire, Self::Extra)> {
        self.reserve()?;
        let gate = self.gate;
        self.gate += 1;
        let plan = self.plan;
        if let Some((stage, offset)) = plan.stages.stage_of(gate) {
            // A stage's gate: the page's if it loads the stage, at the
            // gate the stage's polynomial holds it.
            if !plan.stages.loaded(self.page, stage) {
                return Ok((
                    PageWire::ABSENT,
                    PageWire::ABSENT,
                    PageWire::ABSENT,
                    PageExtra::Absent,
                ));
            }
            let local = plan.stages.spans[stage].start + offset;
            let wires = self
                .prefix
                .as_ref()
                .and_then(|prefix| prefix.get(local - 1))
                .ok_or_else(|| diverged("a stage's gate past the gates before the page's own"))?;
            let stage = stage as u32;
            let [a, b, c, d] = wires.clone();
            return Ok((
                PageWire::stage(stage, a),
                PageWire::stage(stage, b),
                PageWire::stage(stage, c),
                PageExtra::Ready(PageWire::stage(stage, d)),
            ));
        }
        if plan.place(gate).is_some_and(|(page, _)| page == self.page) {
            if self.carry.is_some() || self.own >= plan.layout.room(self.page) {
                return Err(diverged("a gate past the page's own"));
            }
            self.own += 1;
            let (a, b, c, extra) = self.inner.gate(values)?;
            Ok((
                PageWire::own(a),
                PageWire::own(b),
                PageWire::own(c),
                PageExtra::Own(extra),
            ))
        } else {
            Ok((
                PageWire::ABSENT,
                PageWire::ABSENT,
                PageWire::ABSENT,
                PageExtra::Absent,
            ))
        }
    }

    fn assign_extra(
        &mut self,
        extra: Self::Extra,
        value: impl Fn() -> Result<Coeff<F>>,
    ) -> Result<Self::ImplWire> {
        Ok(match extra {
            PageExtra::Own(extra) => PageWire::own(self.inner.assign_extra(extra, value)?),
            PageExtra::Ready(wire) => wire,
            PageExtra::Absent => PageWire::ABSENT,
        })
    }
}

impl<'dr, F: Field, D: Driver<'dr, F = F>> Driver<'dr> for Pager<'_, F, D> {
    type F = F;
    type Wire = PageWire<D::Wire>;
    const ONE: Self::Wire = PageWire {
        own: None,
        one: Some(D::ONE),
        stages: Vec::new(),
    };

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        // Which parts the combination has is asked of the combination
        // itself: a driver need not evaluate what it is handed.
        let parts = lc(PageTerms::parts());
        let mut part = |select| {
            self.inner
                .add(|inner| lc(PageTerms::over(inner, select)).into_inner())
        };
        let own = parts.own.then(|| part(Select::Own));
        let one = parts.one.then(|| part(Select::One));
        let mut stages = parts.stages;
        stages.sort_unstable();
        let stages = stages
            .into_iter()
            .map(|stage| (stage, part(Select::Stage(stage))))
            .collect();
        PageWire { own, one, stages }
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let index = self.constraint;
        self.constraint += 1;
        let plan = self.plan;
        let home = *plan
            .homes
            .get(index)
            .ok_or_else(|| diverged("a constraint past the plan's last"))?
            as usize;
        let links = u32::try_from(index)
            .ok()
            .and_then(|index| plan.links.get(&index))
            .map_or(&[][..], Vec::as_slice);

        if home == self.page {
            if links.is_empty() {
                return self
                    .inner
                    .enforce_zero(|inner| lc(PageTerms::over(inner, Select::All)).into_inner());
            }
            // The constraint, with each slot in place of what it names off
            // this page, once the carry stage's gates are there.
            self.deferred.push(Deferred {
                slots: links
                    .iter()
                    .map(|link| ((link.local, link.slot), Coeff::Arbitrary(link.scale)))
                    .collect(),
                ops: lc(PageTerms::keeping(Select::All)).into_kept(),
            });
        } else {
            // What the constraint names of this page's, or of a stage this
            // page holds slots for, held to the slot it is the first to
            // read.
            for link in links
                .iter()
                .filter(|link| link.defines && link.exporter as usize == self.page)
            {
                let select = match link.source {
                    Source::Page(_) => Select::Own,
                    Source::Stage(stage) => Select::Stage(stage),
                };
                self.deferred.push(Deferred {
                    slots: vec![(
                        (link.local, link.slot),
                        Coeff::NegativeArbitrary(link.scale),
                    )],
                    ops: lc(PageTerms::keeping(select)).into_kept(),
                });
            }
        }
        Ok(())
    }
}

/// Holds what each wire of the public output has on a page, or in a stage
/// the page holds slots for, to the slot the last page reads it from.
struct Exporter<'p, 'a, 'dr, F: Field, D: Driver<'dr, F = F>> {
    pager: &'p mut Pager<'a, F, D>,
    index: usize,
    _marker: PhantomData<&'dr ()>,
}

impl<'a, 'dr, F: Field, D: Driver<'dr, F = F>> WireMap<F> for Exporter<'_, 'a, 'dr, F, D> {
    type Src = Pager<'a, F, D>;
    type Dst = Pager<'a, F, D>;

    fn convert_wire(&mut self, wire: &PageWire<D::Wire>) -> Result<PageWire<D::Wire>> {
        let pager = &mut *self.pager;
        let links = pager
            .plan
            .outputs
            .get(self.index)
            .ok_or_else(|| diverged("an output wire past the plan's last"))?;
        self.index += 1;
        for link in links
            .iter()
            .filter(|link| link.defines && link.exporter as usize == pager.page)
        {
            let slot = pager.slot((link.local, link.slot))?.clone();
            let part = match link.source {
                Source::Page(_) => wire.own.as_ref(),
                Source::Stage(stage) => wire.of_stage(stage),
            }
            .ok_or_else(|| diverged("an output wire without the part its page exports"))?;
            pager.inner.enforce_zero(|inner| {
                inner
                    .add_term(&slot, Coeff::NegativeArbitrary(link.scale))
                    .add(part)
            })?;
        }
        Ok(wire.clone())
    }
}

/// Makes each wire of the public output a wire of the last page: what it
/// has there, with each slot in place of what it has elsewhere.
struct Resolver<'p, 'a, 'dr, F: Field, D: Driver<'dr, F = F>> {
    pager: &'p mut Pager<'a, F, D>,
    index: usize,
    _marker: PhantomData<&'dr ()>,
}

impl<'a, 'dr, F: Field, D: Driver<'dr, F = F>> WireMap<F> for Resolver<'_, 'a, 'dr, F, D> {
    type Src = Pager<'a, F, D>;
    type Dst = D;

    fn convert_wire(&mut self, wire: &PageWire<D::Wire>) -> Result<D::Wire> {
        let pager = &mut *self.pager;
        let links = pager
            .plan
            .outputs
            .get(self.index)
            .ok_or_else(|| diverged("an output wire past the plan's last"))?;
        self.index += 1;
        let slots = links
            .iter()
            .map(|link| pager.slot((link.local, link.slot)).cloned())
            .collect::<Result<Vec<_>>>()?;
        Ok(pager.inner.add(|inner| {
            let mut inner = links.iter().zip(&slots).fold(inner, |inner, (link, slot)| {
                inner.add_term(slot, Coeff::Arbitrary(link.scale))
            });
            if let Some(own) = &wire.own {
                inner = inner.add(own);
            }
            if let Some(one) = &wire.one {
                inner = inner.add(one);
            }
            for (_, part) in &wire.stages {
                inner = inner.add(part);
            }
            inner
        }))
    }
}

/// An arbitrary value for a wire, fixed by the wire alone.
fn arbitrary<F: Field>(gate: usize, kind: u32) -> F {
    let mut input = [0u8; 12];
    input[..8].copy_from_slice(&(gate as u64).to_le_bytes());
    input[8..].copy_from_slice(&kind.to_le_bytes());
    F::from_uniform_bytes(
        blake2b_simd::Params::new()
            .personal(b"ragu_paging_____")
            .hash(&input)
            .as_array(),
    )
}

/// A driver that gives every wire a value and records what each constraint
/// evaluates to.
struct Valuer<F, V> {
    value: V,
    gates: usize,
    constraints: Vec<F>,
}

impl<F: Field, V: Fn(usize, u32) -> F> Valuer<F, V> {
    /// What each of `circuit`'s constraints evaluates to, the public
    /// output's and `ONE`'s included, when the wire `kind` of gate `gate`
    /// has value `value(gate, kind)` and `ONE` is one.
    fn walk<C: Circuit<F>>(circuit: &C, value: V) -> Result<Vec<F>> {
        let mut dr = Valuer {
            value,
            gates: 0,
            constraints: Vec::new(),
        };
        raw::orchestrate(&mut dr, &CircuitAdapterRef(circuit), Empty)?;
        Ok(dr.constraints)
    }
}

impl<F: Field, V: Fn(usize, u32) -> F> DriverTypes for Valuer<F, V> {
    type ImplField = F;
    type ImplWire = F;
    type MaybeKind = Empty;
    type LCadd = DirectSum<F>;
    type LCenforce = DirectSum<F>;
    type Extra = F;

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(F, F, F, F)> {
        let gate = self.gates;
        self.gates += 1;
        let value = &self.value;
        Ok((
            value(gate, 0),
            value(gate, 1),
            value(gate, 2),
            value(gate, 3),
        ))
    }

    fn assign_extra(&mut self, extra: F, _: impl Fn() -> Result<Coeff<F>>) -> Result<F> {
        Ok(extra)
    }
}

impl<'dr, F: Field, V: Fn(usize, u32) -> F> Driver<'dr> for Valuer<F, V> {
    type F = F;
    type Wire = F;
    const ONE: F = F::ONE;

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> F {
        lc(DirectSum::default()).value()
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        self.constraints.push(lc(DirectSum::default()).value());
        Ok(())
    }
}

/// The degree at which a polynomial holds the wire `kind` of gate `gate`,
/// in the trace layout.
fn degree<R: Rank>(gate: usize, kind: u32) -> usize {
    let n = R::n();
    match kind {
        0 => 2 * n - 1 - gate,
        1 => 2 * n + gate,
        2 => gate,
        _ => 4 * n - 1 - gate,
    }
}

/// A circuit cut into pages.
pub struct Paged<F: Field, C> {
    circuit: Arc<C>,
    plan: Arc<Plan<F>>,
    report: PagingReport,
}

impl<F: Field, C: Circuit<F>> Paged<F, C> {
    fn planned(circuit: impl Into<Arc<C>>, (plan, report): (Plan<F>, PagingReport)) -> Self {
        Paged {
            circuit: circuit.into(),
            plan: Arc::new(plan),
            report,
        }
    }

    /// Cuts `circuit` into the pages of `layout`, which load `stages`.
    ///
    /// # Errors
    ///
    /// Fails if the circuit cannot be walked, if the layout does not hold
    /// it or its stages cannot be loaded as told, or if it carries more
    /// values between pages than the layout's carry stage holds.
    pub fn new(circuit: C, stages: &Stages, layout: Layout) -> Result<Self> {
        let recording = Recording::of(&circuit)?;
        let placement = Placement::of(&recording, stages.own_start(), Feeders::Deepest);
        let related = Related::of(&recording, stages, |group| {
            layout
                .apart
                .get(group)
                .map_or(0, |(_, carry)| 2 * carry.len())
        });
        let planned = arrange(&recording, &placement, stages, layout, &related)?;
        planned.0.fits()?;
        Ok(Self::planned(circuit, planned))
    }

    /// Cuts `circuit` into the pages `stages` tells the loads of, in
    /// polynomials of `limit` gates: each page holds what it has room for
    /// before a carry stage that ends at gate `limit` and is as large as
    /// the pages need, and the cuts are placed where the pages then carry
    /// little.
    ///
    /// # Errors
    ///
    /// Fails if the circuit cannot be walked, if its stages cannot be
    /// loaded as told, or if the pages do not have the room.
    pub fn cut(circuit: impl Into<Arc<C>>, stages: &Stages, limit: usize) -> Result<Self> {
        let circuit: Arc<C> = circuit.into();
        stages.check()?;
        let recording = Recording::of(&*circuit)?;
        let Some(own) = recording.num_gates.checked_sub(stages.own_start()) else {
            return refuse(format!(
                "the circuit's {} gates do not follow its stages', which end at gate {}",
                recording.num_gates,
                stages.own_start()
            ));
        };
        #[cfg(feature = "std")]
        let key = recording.digest(stages, limit);
        #[cfg(feature = "std")]
        if let Some(planned) = memo::get::<(Plan<F>, PagingReport)>(&key) {
            return Ok(Self::planned(circuit, planned));
        }

        // What the pages apart hold is the same wherever the cuts go: each
        // group's carry stage may take every gate past what its pages load.
        let related = Related::of(&recording, stages, |group| {
            let first = stages
                .group(group)
                .map(|page| stages.first(page))
                .max()
                .unwrap_or(1);
            2 * limit.saturating_sub(first)
        });

        // With the gates that wait placed beside their use, either way,
        // and with every gate where the circuit allocates it: whichever
        // carries least.
        let placements = [
            Placement::of(&recording, stages.own_start(), Feeders::Deepest),
            Placement::of(&recording, stages.own_start(), Feeders::Latest),
            Placement::allocated(&recording, stages.own_start()),
        ];
        let cuts = placements.iter().map(|placement| {
            let costs = Costs::of(&recording, placement, stages, &related);
            // A larger carry stage shrinks the pages, which moves the cuts
            // and may change what they carry: grow each until it holds.
            // A carry stage is first sized halfway to what the cuts last
            // made it hold: the pages of a group that shares one fill the
            // room a smaller stage leaves them and then read more off it,
            // so the size that holds is between the two. If the sizes do
            // not settle so, they only grow, by an eighth at least.
            let sized = |rounds: usize, needed: usize, gates: usize| {
                if rounds <= SETTLING {
                    match (needed + gates).div_ceil(2) {
                        0 => 0,
                        halfway => halfway + 1,
                    }
                } else if needed > gates {
                    needed.max(gates + gates / 8 + 1)
                } else {
                    gates
                }
            };
            let mut rounds = 0;
            let mut carry_gates = 0;
            let mut local_gates = vec![0; stages.local.len()];
            loop {
                let sizes = (carry_gates, &local_gates[..]);
                let fit = Layout::fit(&costs, recording.num_gates, stages, limit, sizes, &related);
                let layout = match fit {
                    Err(Error::GateBoundExceeded { .. })
                        if carry_gates > 0 || local_gates.iter().any(|&gates| gates > 0) =>
                    {
                        return refuse(format!(
                            "the pages carry values a carry stage of {carry_gates} gates holds, \
                             which leaves them less room than the circuit's {own} gates take in \
                             polynomials of {limit} gates"
                        ));
                    }
                    layout => layout?,
                };
                let mut planned = arrange(&recording, placement, stages, layout, &related)?;
                let needed = planned.0.slots.len().div_ceil(2);
                let needed_local: Vec<usize> = planned
                    .0
                    .local
                    .iter()
                    .map(|slots| slots.len().div_ceil(2))
                    .collect();
                if needed <= carry_gates
                    && needed_local
                        .iter()
                        .zip(&local_gates)
                        .all(|(needed, gates)| needed <= gates)
                {
                    // The cuts may have settled on less than the carry
                    // stages they were looked for under: each takes what
                    // its slots do, and the pages keep their gates.
                    let start = limit - needed;
                    planned.0.layout.carry.start = start;
                    for ((_, gates), needed) in planned.0.layout.local.iter_mut().zip(&needed_local)
                    {
                        *gates = start - needed..start;
                    }
                    return Ok(planned);
                }
                rounds += 1;
                carry_gates = sized(rounds, needed, carry_gates);
                for (gates, &needed) in local_gates.iter_mut().zip(&needed_local) {
                    *gates = sized(rounds, needed, *gates);
                }
            }
        });
        let mut least: Option<Result<(Plan<F>, PagingReport)>> = None;
        for cut in cuts {
            least = Some(match (least, cut) {
                (Some(Ok(least)), Ok(cut)) => {
                    // By the gates the carry stages take over the pages
                    // that load them.
                    let taken = |layout: &Layout| {
                        let shared = layout.local.iter();
                        layout.carry.len() * layout.num_pages()
                            + shared
                                .map(|(pages, gates)| pages.len() * gates.len())
                                .sum::<usize>()
                    };
                    Ok(if taken(&cut.0.layout) < taken(&least.0.layout) {
                        cut
                    } else {
                        least
                    })
                }
                (Some(Ok(least)), Err(_)) => Ok(least),
                (Some(Err(error)), Err(_)) => Err(error),
                (_, cut) => cut,
            });
        }
        let planned = least.expect("an order")?;
        #[cfg(feature = "std")]
        memo::put(key, planned.clone());
        Ok(Self::planned(circuit, planned))
    }

    /// Cuts `circuit` into as many pages of `page_gates` gates as it
    /// takes, each loading every stage of `stages`, with a carry stage of
    /// the size they turn out to need right after a page's gates.
    ///
    /// # Errors
    ///
    /// Fails if the circuit cannot be walked or its stages cannot be
    /// loaded together.
    ///
    /// # Panics
    ///
    /// Panics if `page_gates` is zero.
    pub fn fitted(circuit: C, stages: &Stages, page_gates: usize) -> Result<Self> {
        assert!(page_gates > 0, "a page holds a gate");
        let recording = Recording::of(&circuit)?;
        let own = recording.num_gates.saturating_sub(stages.own_start());
        let pages = own.div_ceil(page_gates).max(1);
        let stages = stages
            .clone()
            .pages(pages)
            .apart(Vec::new())
            .sharing(Vec::new());
        let first = stages.first(0);
        let layout = Layout {
            own_start: stages.own_start(),
            starts: (0..pages)
                .map(|page| stages.own_start() + page * page_gates)
                .collect(),
            firsts: vec![first; pages],
            carry: first + page_gates.min(own)..usize::MAX,
            apart: Vec::new(),
            local: Vec::new(),
        };
        let placement = Placement::of(&recording, stages.own_start(), Feeders::Deepest);
        let related = Related::of(&recording, &stages, |_| 0);
        let (mut plan, report) = arrange(&recording, &placement, &stages, layout, &related)?;
        plan.layout.carry.end = plan.layout.carry.start + plan.slots.len().div_ceil(2);
        Ok(Self::planned(circuit, (plan, report)))
    }

    /// Checks the pages' constraints against the circuit's own.
    ///
    /// Every wire is given an arbitrary value, the same in the circuit and
    /// on its page, and every carry slot the value of the combination it
    /// stands for. The circuit's constraints then evaluate to some values,
    /// which need not be zero, and the pages' constraints must evaluate to
    /// the same values: each of the circuit's once, a zero more for each
    /// slot a page holds to its wires, and `ONE`'s once more for each page
    /// past the first. A constraint that lost or gained a term, or moved to
    /// a page that lacks a wire it names, evaluates to something else.
    ///
    /// # Errors
    ///
    /// Fails if a walk fails or if the values differ.
    pub fn check(&self) -> Result<()> {
        let plan = &*self.plan;
        let (layout, stages) = (&plan.layout, &plan.stages);
        let pages = plan.pages();
        let values = |slots: &Vec<Vec<(u32, F)>>| -> Vec<F> {
            slots
                .iter()
                .map(|combination| {
                    combination
                        .iter()
                        .map(|&(wire, coeff)| coeff * arbitrary::<F>((wire / 4) as usize, wire % 4))
                        .sum()
                })
                .collect()
        };
        let carry = values(&plan.slots);
        let apart: Vec<Vec<F>> = plan.apart.iter().map(values).collect();
        let local: Vec<Vec<F>> = plan.local.iter().map(values).collect();
        let slots = plan.slots.len()
            + plan
                .apart
                .iter()
                .chain(&plan.local)
                .map(Vec::len)
                .sum::<usize>();

        let mut expected = Valuer::walk(&*self.circuit, |gate, kind| arbitrary(gate, kind))?;
        expected.extend(core::iter::repeat_n(F::ONE, pages - 1));
        expected.extend(core::iter::repeat_n(F::ZERO, slots));

        let on_page = |page: usize| {
            // The carry stage the page loads: its group's if it is apart.
            let (gates, carry) = match stages.group_of(page) {
                Some(group) => (&layout.apart[group].1, &apart[group]),
                None => (&layout.carry, &carry),
            };
            // And the one it shares with its group, if it shares one.
            let shared = stages
                .local_of(page)
                .map(|group| (&layout.local[group].1, &local[group]));
            move |local: usize, kind: u32| {
                if local == 0 {
                    return arbitrary(0, kind);
                }
                let loaded = [Some((gates, carry)), shared];
                if let Some((gates, carry)) = loaded
                    .into_iter()
                    .flatten()
                    .find(|(gates, _)| gates.contains(&local))
                {
                    // A gate of a carry stage: its two values are its
                    // slots', and nothing names its other wires.
                    let gate = local - gates.start;
                    let slot = match kind {
                        0 => 2 * gate,
                        3 => 2 * gate + 1,
                        _ => return F::ZERO,
                    };
                    return carry.get(slot).copied().unwrap_or(F::ZERO);
                }
                if local < layout.firsts[page] {
                    // A gate of a stage the page loads, or of none.
                    return stages
                        .spans
                        .iter()
                        .enumerate()
                        .find(|&(stage, span)| span.contains(&local) && stages.loaded(page, stage))
                        .map_or(F::ZERO, |(stage, span)| {
                            arbitrary(stages.start(stage) + local - span.start, kind)
                        });
                }
                // A gate of the page's own, or one it leaves blank.
                plan.held[page]
                    .get(local - layout.firsts[page])
                    .map_or(F::ZERO, |&gate| arbitrary(gate as usize, kind))
            }
        };
        let mut found = Vec::new();
        for index in 0..pages - 1 {
            found.extend(Valuer::walk(&self.page(index), on_page(index))?);
        }
        found.extend(Valuer::walk(&self.last(), on_page(pages - 1))?);

        let sorted = |values: Vec<F>| {
            let mut bytes: Vec<Vec<u8>> = values
                .iter()
                .map(|value| value.to_bytes().as_ref().to_vec())
                .collect();
            bytes.sort();
            bytes
        };
        let (expected_len, found_len) = (expected.len(), found.len());
        if sorted(expected) != sorted(found) {
            return refuse(format!(
                "the pages' {found_len} constraints are not the circuit's ({expected_len} with \
                 the slots' and the pages' own)"
            ));
        }
        Ok(())
    }

    /// The layout of the pages' polynomials.
    pub fn layout(&self) -> &Layout {
        &self.plan.layout
    }

    /// The circuit's stages, as its pages load them.
    pub fn stages(&self) -> &Stages {
        &self.plan.stages
    }

    /// The pages the circuit takes, the last included.
    pub fn num_pages(&self) -> usize {
        self.plan.pages()
    }

    /// How the circuit spreads over its pages.
    pub fn report(&self) -> &PagingReport {
        &self.report
    }

    /// Page `index`, which is not the last.
    ///
    /// # Panics
    ///
    /// Panics if `index` is the last page or past it.
    pub fn page(&self, index: usize) -> Page<F, C> {
        assert!(
            index + 1 < self.plan.pages(),
            "the last page is `last`'s, with the public output"
        );
        Page {
            circuit: self.circuit.clone(),
            plan: self.plan.clone(),
            index,
        }
    }

    /// The last page, which carries the circuit's public output.
    pub fn last(&self) -> LastPage<F, C> {
        LastPage {
            circuit: self.circuit.clone(),
            plan: self.plan.clone(),
        }
    }

    /// The carry stage's values, read off the pages' traces, in page order,
    /// and off the polynomials of the stages a slot combines the wires of:
    /// `stages[index]` is stage `index`'s, and may be left out past the
    /// last such stage. A page that holds no gates has no trace to give,
    /// and a circuit without gates of its own gives none at all.
    ///
    /// # Errors
    ///
    /// Fails if a slot combines the wires of a stage without a polynomial
    /// or of a page without a trace.
    ///
    /// # Panics
    ///
    /// Panics if `traces` are not this circuit's pages' traces.
    pub fn carry_values<R: Rank>(
        &self,
        traces: &[Option<Trace<F>>],
        stages: &[&sparse::Polynomial<F, R>],
    ) -> Result<Vec<F>> {
        assert!(
            traces.is_empty() || traces.len() == self.plan.pages(),
            "a trace for each page"
        );
        self.values(&self.plan.slots, traces, stages)
    }

    /// The values of `slots`, off the pages' traces and the stages'
    /// polynomials.
    fn values<R: Rank>(
        &self,
        slots: &[Vec<(u32, F)>],
        traces: &[Option<Trace<F>>],
        stages: &[&sparse::Polynomial<F, R>],
    ) -> Result<Vec<F>> {
        let plan = &*self.plan;
        let mut coeffs: Vec<Option<Vec<F>>> = stages.iter().map(|_| None).collect();
        let mut values = Vec::with_capacity(slots.len());
        for combination in slots {
            let mut sum = F::ZERO;
            for &(wire, coeff) in combination {
                let (gate, kind) = ((wire / 4) as usize, wire % 4);
                let value = match plan.stages.stage_of(gate) {
                    Some((stage, offset)) => {
                        let Some(rx) = stages.get(stage) else {
                            return refuse(format!(
                                "the carry stage holds values of stage {stage}, whose \
                                 polynomial it was not given"
                            ));
                        };
                        let coeffs =
                            coeffs[stage].get_or_insert_with(|| rx.iter_coeffs().collect());
                        coeffs[degree::<R>(plan.stages.spans[stage].start + offset, kind)]
                    }
                    None => {
                        let (page, local) = plan
                            .place(gate)
                            .expect("a slot combines a page's or a stage's wires");
                        let Some(trace) = traces.get(page).and_then(Option::as_ref) else {
                            return refuse(format!(
                                "the carry stage holds values of page {page}, whose trace it \
                                 was not given"
                            ));
                        };
                        assert_eq!(trace.segments.len(), 1, "a page's trace is one segment");
                        let segment = &trace.segments[0];
                        match kind {
                            0 => segment.a[local],
                            1 => segment.b[local],
                            2 => segment.c[local],
                            _ => segment.d[local],
                        }
                    }
                };
                sum += coeff * value;
            }
            values.push(sum);
        }
        Ok(values)
    }

    /// The carry stage's polynomial for the pages' traces and the stages'
    /// polynomials (see [`carry_values`](Self::carry_values)).
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`, or as
    /// [`carry_values`](Self::carry_values) does.
    pub fn carry_rx<R: Rank>(
        &self,
        blind: impl Into<Blind<F>>,
        traces: &[Option<Trace<F>>],
        stages: &[&sparse::Polynomial<F, R>],
    ) -> Result<sparse::Polynomial<F, R>> {
        let carry = &self.plan.layout.carry;
        staging::stage_rx(
            blind,
            carry.start,
            2 * carry.len(),
            &self.carry_values(traces, stages)?,
        )
    }

    /// The well-formedness mask of the carry stage's polynomial.
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`.
    pub fn carry_mask<R: Rank>(&self) -> Result<MaskObject<R>> {
        let carry = &self.plan.layout.carry;
        staging::stage_mask(carry.start, carry.len())
    }

    /// The groups of pages that share a carry stage of their own.
    pub fn num_local(&self) -> usize {
        self.plan.local.len()
    }

    /// The polynomial of the carry stage the pages of group `group` share,
    /// off the pages' traces and the stages' polynomials (see
    /// [`carry_values`](Self::carry_values)).
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`, or as
    /// [`carry_values`](Self::carry_values) does.
    ///
    /// # Panics
    ///
    /// Panics if there is no such group, or if `traces` are not this
    /// circuit's pages' traces.
    pub fn local_rx<R: Rank>(
        &self,
        group: usize,
        blind: impl Into<Blind<F>>,
        traces: &[Option<Trace<F>>],
        stages: &[&sparse::Polynomial<F, R>],
    ) -> Result<sparse::Polynomial<F, R>> {
        assert!(
            traces.is_empty() || traces.len() == self.plan.pages(),
            "a trace for each page"
        );
        let carry = &self.plan.layout.local[group].1;
        staging::stage_rx(
            blind,
            carry.start,
            2 * carry.len(),
            &self.values(&self.plan.local[group], traces, stages)?,
        )
    }

    /// The well-formedness mask of the polynomial of the carry stage the
    /// pages of group `group` share.
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`.
    ///
    /// # Panics
    ///
    /// Panics if there is no such group.
    pub fn local_mask<R: Rank>(&self, group: usize) -> Result<MaskObject<R>> {
        let carry = &self.plan.layout.local[group].1;
        staging::stage_mask(carry.start, carry.len())
    }

    /// The groups of pages apart, each with a carry stage of its own.
    pub fn num_apart(&self) -> usize {
        self.plan.apart.len()
    }

    /// The polynomial of the carry stage of group `group` of the pages
    /// apart, whose values are read off the stages' polynomials alone (see
    /// [`carry_values`](Self::carry_values)).
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`, or if a slot
    /// combines the wires of a stage without a polynomial.
    ///
    /// # Panics
    ///
    /// Panics if there is no such group.
    pub fn apart_rx<R: Rank>(
        &self,
        group: usize,
        blind: impl Into<Blind<F>>,
        stages: &[&sparse::Polynomial<F, R>],
    ) -> Result<sparse::Polynomial<F, R>> {
        let carry = &self.plan.layout.apart[group].1;
        staging::stage_rx(
            blind,
            carry.start,
            2 * carry.len(),
            &self.values(&self.plan.apart[group], &[], stages)?,
        )
    }

    /// The well-formedness mask of the polynomial of the carry stage of
    /// group `group` of the pages apart.
    ///
    /// # Errors
    ///
    /// Fails if the carry stage does not fit rank `R`.
    ///
    /// # Panics
    ///
    /// Panics if there is no such group.
    pub fn apart_mask<R: Rank>(&self, group: usize) -> Result<MaskObject<R>> {
        let carry = &self.plan.layout.apart[group].1;
        staging::stage_mask(carry.start, carry.len())
    }

    /// The well-formedness mask of page `page`'s own polynomial, which is
    /// zero off the page's own gates: on the gates before them, where the
    /// stages it loads are, and on the carry stage's.
    ///
    /// # Errors
    ///
    /// Fails if the page's gates do not fit rank `R`.
    pub fn own_mask<R: Rank>(&self, page: usize) -> Result<MaskObject<R>> {
        let window = self.plan.layout.window(page);
        staging::stage_mask(window.start, window.len())
    }
}

/// A page of a [`Paged`] circuit other than the last: a circuit with no
/// public output.
pub struct Page<F: Field, C> {
    circuit: Arc<C>,
    plan: Arc<Plan<F>>,
    index: usize,
}

impl<F: Field, C: Circuit<F>> Circuit<F> for Page<F, C> {
    type Instance<'source> = ();
    type Witness<'source> = C::Witness<'source>;
    type Output = ();
    type Aux<'source> = C::Aux<'source>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Ok(())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let mut pager = Pager::new(dr, &self.plan, self.index);
        let (output, aux) = self.circuit.witness(&mut pager, witness)?.into_parts();
        pager.seal()?;
        output.map(&mut Exporter {
            pager: &mut pager,
            index: 0,
            _marker: PhantomData,
        })?;
        pager.finish()?;
        Ok(WithAux::new((), aux))
    }
}

/// The last page of a [`Paged`] circuit, with the circuit's public output.
pub struct LastPage<F: Field, C> {
    circuit: Arc<C>,
    plan: Arc<Plan<F>>,
}

impl<F: Field, C: Circuit<F>> Circuit<F> for LastPage<F, C> {
    type Instance<'source> = C::Instance<'source>;
    type Witness<'source> = C::Witness<'source>;
    type Output = C::Output;
    type Aux<'source> = C::Aux<'source>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        self.circuit.instance(dr, instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let mut pager = Pager::new(dr, &self.plan, self.plan.pages() - 1);
        let (output, aux) = self.circuit.witness(&mut pager, witness)?.into_parts();
        pager.seal()?;
        let output = output.map(&mut Resolver {
            pager: &mut pager,
            index: 0,
            _marker: PhantomData,
        })?;
        pager.finish()?;
        Ok(WithAux::new(output, aux))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ragu_core::{gadgets::Kind, maybe::Maybe, pasta::Fp};
    use ragu_primitives::{
        Element,
        allocator::Standard,
        vec::{ConstLen, FixedVec},
    };
    use rand::Rng;

    use super::*;
    use crate::{
        CircuitExt, WiringObject, floor_planner, into_wiring_object,
        polynomials::TestRank,
        staging::{MultiStage, StageBuilder, StageExt},
    };

    type R = TestRank;

    /// The gates a polynomial of the test rank holds before its blind gate.
    fn limit() -> usize {
        R::blind_gate()
    }

    /// `LEN` squarings of the witness, each `STRIDE`-th followed by adding
    /// the witness back and some by adding the value two squarings ago: a
    /// narrow cut, one wire every page names, and constraints over two
    /// pages' wires.
    struct Chain<const LEN: usize, const STRIDE: usize>;

    impl<const LEN: usize, const STRIDE: usize> Chain<LEN, STRIDE> {
        fn run(witness: Fp) -> Fp {
            let mut acc = witness;
            let mut history = alloc::vec![witness];
            for step in 0..LEN {
                acc = acc.square();
                if step % STRIDE == 0 {
                    acc += witness;
                }
                if step % (2 * STRIDE) == 1 {
                    acc += history[history.len() - 2];
                }
                history.push(acc);
            }
            acc
        }
    }

    impl<const LEN: usize, const STRIDE: usize> Circuit<Fp> for Chain<LEN, STRIDE> {
        type Instance<'source> = Fp;
        type Witness<'source> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Fp>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, &mut Standard::new(), instance)
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Fp>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
            let first = Element::alloc(dr, &mut Standard::new(), witness)?;
            let mut acc = first.clone();
            let mut history = alloc::vec![first.clone()];
            for step in 0..LEN {
                acc = acc.square(dr)?;
                if step % STRIDE == 0 {
                    acc = acc.add(dr, &first);
                }
                if step % (2 * STRIDE) == 1 {
                    acc = acc.add(dr, &history[history.len() - 2]);
                }
                history.push(acc.clone());
            }
            Ok(WithAux::new(acc, D::unit()))
        }
    }

    /// The gates of its own a circuit without stages allocates.
    fn own_gates<C: Circuit<Fp>>(circuit: &C) -> Result<usize> {
        Ok(Recording::of(circuit)?.num_gates - 1)
    }

    #[test]
    fn one_page_carries_nothing() -> Result<()> {
        let paged = Paged::fitted(Chain::<40, 5>, &Stages::whole(1), 1 << 20)?;
        let report = paged.report();
        assert_eq!(report.pages.len(), 1);
        assert_eq!(report.carried_wires, 0);
        assert_eq!(report.slots, 0);
        assert_eq!(report.cross_constraints, 0);
        assert!(report.cuts.is_empty());
        assert_eq!(report.num_gates, 1 + report.pages[0].gates);
        assert!(paged.layout().carry.is_empty());
        Ok(())
    }

    #[test]
    fn a_chain_carries_its_cut_and_its_long_lived_wire() -> Result<()> {
        let whole = Paged::fitted(Chain::<40, 5>, &Stages::whole(1), 1 << 20)?;
        let paged = Paged::fitted(Chain::<40, 5>, &Stages::whole(1), 8)?;
        let (whole, paged) = (whole.report(), paged.report());
        assert_eq!(paged.num_gates, whole.num_gates);
        assert_eq!(paged.num_constraints, whole.num_constraints);
        assert_eq!(paged.pages.len(), (whole.num_gates - 1).div_ceil(8));
        // A boundary is crossed by the running value, by the values just
        // before it and by the witness, which every later page names.
        assert!(paged.cuts.iter().all(|&cut| (1..=4).contains(&cut)));
        assert!(paged.carried_wires >= paged.pages.len() - 1);
        assert!(paged.carried_wires <= 4 * paged.pages.len());
        Ok(())
    }

    /// Whether the revdot claim of one page holds, on its own polynomial
    /// plus `loaded`, the carry stage's and those of the stages it loads,
    /// for random challenges.
    fn page_claim_holds<C: Circuit<Fp>>(
        page: C,
        witness: C::Witness<'_>,
        instance: C::Instance<'_>,
        loaded: &sparse::Polynomial<Fp, R>,
    ) -> Result<bool> {
        let mut rng = rand::rng();
        let trace = page.trace(witness)?.into_output();
        let y = Fp::random(|bytes| rng.fill_bytes(bytes));
        let z = Fp::random(|bytes| rng.fill_bytes(bytes));
        let expected = page.ky(instance, y)?;
        let object = into_wiring_object::<_, _, R>(page)?;
        let plan = floor_planner::floor_plan(object.segment_records());
        let mut a = trace.assemble::<R>(&plan, Blind::<Fp>::random(&mut rng))?;
        a.add_assign(loaded);
        let mut b = a.clone();
        b.dilate(z);
        b.add_assign(&object.sy(y, &plan));
        b.add_assign(&R::tz(z));
        Ok(expected == a.revdot(&b))
    }

    /// Pages `Chain<LEN, STRIDE>` at the test rank, before a carry stage of
    /// `carry_gates` gates, and tells which pages' claims hold, with the
    /// carry stage's values passed through `tamper`.
    fn claims<const LEN: usize, const STRIDE: usize>(
        carry_gates: usize,
        tamper: impl Fn(&mut Vec<Fp>),
    ) -> Result<(Paged<Fp, Chain<LEN, STRIDE>>, Vec<bool>)> {
        let witness = Fp::from(3u64);
        let instance = Chain::<LEN, STRIDE>::run(witness);
        let own = own_gates(&Chain::<LEN, STRIDE>)?;
        let stages = Stages::whole(1).pages(own.div_ceil(limit() - carry_gates - 1));
        let layout = Layout::fill(&stages, own, limit(), carry_gates)?;
        let paged = Paged::new(Chain::<LEN, STRIDE>, &stages, layout)?;
        let pages = paged.num_pages();

        let mut traces = Vec::new();
        for index in 0..pages - 1 {
            traces.push(Some(paged.page(index).trace(witness)?.into_output()));
        }
        traces.push(Some(paged.last().trace(witness)?.into_output()));
        let mut values = paged.carry_values::<R>(&traces, &[])?;
        tamper(&mut values);
        let carry = paged.layout().carry.clone();
        let carry = staging::stage_rx::<Fp, R>(
            Blind::<Fp>::random(&mut rand::rng()),
            carry.start,
            2 * carry.len(),
            &values,
        )?;

        let mut holds = Vec::new();
        for index in 0..pages - 1 {
            holds.push(page_claim_holds(paged.page(index), witness, (), &carry)?);
        }
        holds.push(page_claim_holds(paged.last(), witness, instance, &carry)?);
        Ok((paged, holds))
    }

    #[test]
    fn every_page_of_a_paged_circuit_satisfies_its_claim() -> Result<()> {
        let (paged, holds) = claims::<100, 3>(8, |_| {})?;
        assert!(paged.num_pages() >= 4, "the chain takes several pages");
        assert!(paged.report().slots > 0, "the chain carries values");
        assert!(holds.iter().all(|&hold| hold), "{holds:?}");
        paged.check()
    }

    #[test]
    fn the_pages_constraints_are_the_circuits() -> Result<()> {
        // Whatever the cut.
        for page_gates in [1, 2, 3, 5, 8, 13, 28, 1 << 20] {
            Paged::fitted(Chain::<100, 3>, &Stages::whole(1), page_gates)?.check()?;
            Paged::fitted(
                MultiStage::<Fp, R, _>::new(Seeded::<90>),
                &Stages::of::<Fp, R, Seeded<90>>(),
                page_gates,
            )?
            .check()?;
        }
        // In polynomials of the test rank, in as many pages as that takes
        // and in more.
        for pages in 5..9 {
            let cut = Paged::cut(Chain::<100, 3>, &Stages::whole(1).pages(pages), limit())?;
            let (layout, report) = (cut.layout(), cut.report());
            assert_eq!(layout.carry.end, limit());
            assert!(2 * layout.carry.len() >= report.slots);
            for (page, held) in report.pages.iter().enumerate() {
                assert!(held.gates <= layout.room(page));
            }
            cut.check()?;
        }
        Ok(())
    }

    #[test]
    fn pages_without_the_room_are_refused() {
        assert!(matches!(
            Paged::cut(Chain::<100, 3>, &Stages::whole(1).pages(2), limit()),
            Err(Error::GateBoundExceeded { .. })
        ));
    }

    /// `paged` with its plan passed through `tamper`.
    fn tampered<C: Circuit<Fp>>(
        paged: &Paged<Fp, C>,
        tamper: impl FnOnce(&mut Plan<Fp>),
    ) -> Paged<Fp, C> {
        let mut plan = (*paged.plan).clone();
        tamper(&mut plan);
        Paged {
            circuit: paged.circuit.clone(),
            plan: Arc::new(plan),
            report: paged.report.clone(),
        }
    }

    #[test]
    fn a_plan_that_miscarries_is_caught() -> Result<()> {
        let paged = Paged::fitted(Chain::<100, 3>, &Stages::whole(1), 8)?;
        paged.check()?;
        let (&constraint, _) = paged.plan.links.iter().next().expect("the chain carries");

        // A slot read at the wrong scale.
        let wrong = tampered(&paged, |plan| {
            plan.links.get_mut(&constraint).unwrap()[0].scale += Fp::ONE;
        });
        assert!(wrong.check().is_err());

        // A slot the constraint no longer reads: the term is dropped.
        let wrong = tampered(&paged, |plan| {
            plan.links.remove(&constraint);
        });
        assert!(wrong.check().is_err());

        // A slot no page holds to its wires.
        let wrong = tampered(&paged, |plan| {
            for links in plan.links.values_mut() {
                for link in links.iter_mut().filter(|link| link.slot == 0) {
                    link.defines = false;
                }
            }
        });
        assert!(wrong.check().is_err());

        // A constraint homed on a page that lacks its wires.
        let wrong = tampered(&paged, |plan| {
            let moved = plan.homes.iter().position(|&home| home == 2).unwrap();
            plan.homes[moved] = 0;
        });
        assert!(wrong.check().is_err());
        Ok(())
    }

    #[test]
    fn a_circuit_of_one_page_is_its_last_page() -> Result<()> {
        let (paged, holds) = claims::<8, 3>(1, |_| {})?;
        assert_eq!(paged.num_pages(), 1);
        assert_eq!(paged.report().slots, 0);
        assert_eq!(holds, [true]);
        Ok(())
    }

    #[test]
    fn a_wrong_carried_value_fails_a_page() -> Result<()> {
        let slots = claims::<100, 3>(8, |_| {})?.0.report().slots;
        for slot in 0..slots {
            let (_, holds) = claims::<100, 3>(8, |values| values[slot] += Fp::ONE)?;
            // The page that holds the slot to its wires no longer does, and
            // neither does a page that reads it.
            assert!(
                holds.iter().filter(|&&hold| !hold).count() >= 2,
                "slot {slot}: {holds:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_carry_stage_too_small_is_refused() -> Result<()> {
        let own = own_gates(&Chain::<100, 3>)?;
        let stages = Stages::whole(1).pages(own.div_ceil(limit() - 2));
        let layout = Layout::fill(&stages, own, limit(), 1)?;
        assert!(matches!(
            Paged::new(Chain::<100, 3>, &stages, layout),
            Err(Error::Initialization(_))
        ));
        Ok(())
    }

    /// Four values every page reads.
    #[derive(Default)]
    struct Seeds;

    impl Stage<Fp, R> for Seeds {
        type Parent = ();
        type Witness<'source> = [Fp; 4];
        type OutputKind = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<4>>];

        fn values() -> usize {
            4
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, [Fp; 4]>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|seeds| seeds[i]))
            })
        }
    }

    /// `LEN` squarings, each followed by adding one of the stage's values:
    /// a circuit over a stage that every page reads.
    struct Seeded<const LEN: usize>;

    impl<const LEN: usize> Seeded<LEN> {
        fn run(seeds: [Fp; 4]) -> Fp {
            (0..LEN).fold(seeds[0], |acc, step| acc.square() + seeds[step % 4])
        }
    }

    impl<const LEN: usize> MultiStageCircuit<Fp, R> for Seeded<LEN> {
        type Last = Seeds;
        type Instance<'source> = Fp;
        type Witness<'source> = [Fp; 4];
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Fp>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, &mut Standard::new(), instance)
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
            witness: DriverValue<D, [Fp; 4]>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
        where
            Self: 'dr,
        {
            let (seeds, builder) = builder.add_stage::<Seeds>()?;
            let dr = builder.finish();
            let seeds = seeds.unenforced(dr, witness)?;
            let mut acc = seeds[0].clone();
            for step in 0..LEN {
                acc = acc.square(dr)?;
                acc = acc.add(dr, &seeds[step % 4]);
            }
            Ok(WithAux::new(acc, D::unit()))
        }
    }

    #[test]
    fn a_staged_circuit_pages_beside_its_stage() -> Result<()> {
        let seeds = [3u64, 5, 7, 11].map(Fp::from);
        let instance = Seeded::<90>::run(seeds);
        let stages = Stages::of::<Fp, R, Seeded<90>>();
        assert_eq!(
            stages.own_start(),
            3,
            "the SYSTEM gate and the stage's two gates"
        );
        let paged = Paged::cut(
            MultiStage::<Fp, R, _>::new(Seeded::<90>),
            &stages.pages(5),
            limit(),
        )?;
        let pages = paged.num_pages();
        // The stage's wires are every page's: none is carried, and every
        // page names them.
        assert!(paged.report().pages.iter().all(|page| page.stage_wires > 0));
        assert!(paged.report().slots <= 2 * (pages - 1));
        assert!(paged.layout().firsts.iter().all(|&first| first == 3));

        let mut traces = Vec::new();
        for index in 0..pages - 1 {
            traces.push(Some(paged.page(index).trace(seeds)?.into_output()));
        }
        traces.push(Some(paged.last().trace(seeds)?.into_output()));
        let mut rng = rand::rng();
        let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces, &[])?;
        let stage = <Seeds as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), seeds)?;
        let mut loaded = carry.clone();
        loaded.add_assign(&stage);

        for index in 0..pages - 1 {
            assert!(page_claim_holds(paged.page(index), seeds, (), &loaded)?);
            // A page reads the stage: without it, its claim fails.
            assert!(!page_claim_holds(paged.page(index), seeds, (), &carry)?);
        }
        assert!(page_claim_holds(paged.last(), seeds, instance, &loaded)?);
        assert!(!page_claim_holds(paged.last(), seeds, instance, &carry)?);
        Ok(())
    }

    /// Four values, at the first gates after the SYSTEM gate.
    #[derive(Default)]
    struct Left;

    impl Stage<Fp, R> for Left {
        type Parent = ();
        type Witness<'source> = [Fp; 4];
        type OutputKind = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<4>>];

        fn values() -> usize {
            4
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, [Fp; 4]>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|values| values[i]))
            })
        }
    }

    /// Four more values, which a circuit reserves after [`Left`]'s but
    /// whose polynomial holds them at the same gates: a branch beside it.
    #[derive(Default)]
    struct Right;

    impl Stage<Fp, R> for Right {
        type Parent = Left;
        type Witness<'source> = [Fp; 4];
        type OutputKind = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<4>>];

        fn values() -> usize {
            4
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, [Fp; 4]>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|values| values[i]))
            })
        }

        fn skip_gates() -> usize {
            1
        }
    }

    /// `LEN` squarings, each followed by adding a value of [`Left`] in the
    /// first half and of [`Right`] in the second, and every seventh by one
    /// of the other stage's: a circuit over two stages that share gates.
    struct Branched<const LEN: usize>;

    impl<const LEN: usize> Branched<LEN> {
        fn run(left: [Fp; 4], right: [Fp; 4]) -> Fp {
            (0..LEN).fold(left[0], |acc, step| {
                let (near, far) = if step < LEN / 2 {
                    (left, right)
                } else {
                    (right, left)
                };
                let acc = acc.square() + near[step % 4];
                if step % 7 == 3 {
                    acc + far[step % 4]
                } else {
                    acc
                }
            })
        }
    }

    impl<const LEN: usize> MultiStageCircuit<Fp, R> for Branched<LEN> {
        type Last = Right;
        type Instance<'source> = Fp;
        type Witness<'source> = ([Fp; 4], [Fp; 4]);
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Fp>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, &mut Standard::new(), instance)
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
            witness: DriverValue<D, ([Fp; 4], [Fp; 4])>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
        where
            Self: 'dr,
        {
            let (left, builder) = builder.add_stage::<Left>()?;
            let (right, builder) = builder.add_stage::<Right>()?;
            let dr = builder.finish();
            let left = left.unenforced(dr, witness.as_ref().map(|w| w.0))?;
            let right = right.unenforced(dr, witness.as_ref().map(|w| w.1))?;
            let mut acc = left[0].clone();
            for step in 0..LEN {
                let (near, far) = if step < LEN / 2 {
                    (&left, &right)
                } else {
                    (&right, &left)
                };
                acc = acc.square(dr)?;
                acc = acc.add(dr, &near[step % 4]);
                if step % 7 == 3 {
                    acc = acc.add(dr, &far[step % 4]);
                }
            }
            Ok(WithAux::new(acc, D::unit()))
        }
    }

    const LEFT: [u64; 4] = [3, 5, 7, 11];
    const RIGHT: [u64; 4] = [13, 17, 19, 23];

    /// `Branched<60>` in the pages `loads` tells the stages of, with the
    /// two stages' polynomials and the carry stage's.
    #[allow(clippy::type_complexity)]
    fn branched(
        loads: Vec<Vec<usize>>,
    ) -> Result<(
        Paged<Fp, MultiStage<Fp, R, Branched<60>>>,
        [sparse::Polynomial<Fp, R>; 2],
        sparse::Polynomial<Fp, R>,
    )> {
        let witness = (LEFT.map(Fp::from), RIGHT.map(Fp::from));
        let stages = Stages::of::<Fp, R, Branched<60>>();
        // The stages share their gates, and the circuit counts them end to
        // end.
        assert_eq!(stages.spans, [1..3, 1..3]);
        assert_eq!(stages.own_start(), 5);
        let paged = Paged::cut(
            MultiStage::<Fp, R, _>::new(Branched::<60>),
            &stages.loading(loads),
            limit(),
        )?;
        let pages = paged.num_pages();

        let mut traces = Vec::new();
        for index in 0..pages - 1 {
            traces.push(Some(paged.page(index).trace(witness)?.into_output()));
        }
        traces.push(Some(paged.last().trace(witness)?.into_output()));
        let mut rng = rand::rng();
        let rxs = [
            <Left as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.0)?,
            <Right as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.1)?,
        ];
        let carry =
            paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces, &[&rxs[0], &rxs[1]])?;
        Ok((paged, rxs, carry))
    }

    /// Whether each page's claim holds on the carry stage's polynomial and
    /// those of the stages `loads` gives it.
    fn branched_claims(
        paged: &Paged<Fp, MultiStage<Fp, R, Branched<60>>>,
        rxs: &[sparse::Polynomial<Fp, R>; 2],
        carry: &sparse::Polynomial<Fp, R>,
        loads: impl Fn(usize) -> Vec<usize>,
    ) -> Result<Vec<bool>> {
        let witness = (LEFT.map(Fp::from), RIGHT.map(Fp::from));
        let instance = Branched::<60>::run(witness.0, witness.1);
        let pages = paged.num_pages();
        let mut holds = Vec::new();
        for index in 0..pages {
            let mut loaded = carry.clone();
            for stage in loads(index) {
                loaded.add_assign(&rxs[stage]);
            }
            holds.push(if index + 1 < pages {
                page_claim_holds(paged.page(index), witness, (), &loaded)?
            } else {
                page_claim_holds(paged.last(), witness, instance, &loaded)?
            });
        }
        Ok(holds)
    }

    #[test]
    fn a_circuit_pages_over_stages_that_share_gates() -> Result<()> {
        let loads = alloc::vec![vec![0], vec![0], vec![1], vec![1]];
        let (paged, rxs, carry) = branched(loads.clone())?;
        assert_eq!(paged.num_pages(), 4);
        assert_eq!(paged.layout().firsts, [3; 4], "a page holds one stage");
        // Each half names the other's stage, which its pages do not load:
        // those values are carried.
        assert!(paged.report().slots > 3);
        paged.check()?;

        // With the stage it loads, a page's claim holds; with the other,
        // which holds other values at the same gates, it fails.
        let holds = branched_claims(&paged, &rxs, &carry, |page| loads[page].clone())?;
        assert_eq!(holds, [true; 4]);
        let holds = branched_claims(&paged, &rxs, &carry, |page| vec![1 - loads[page][0]])?;
        assert_eq!(holds, [false; 4]);
        Ok(())
    }

    #[test]
    fn a_page_that_loads_less_has_more_room() -> Result<()> {
        // The second page loads neither stage and the last one only the
        // first: every value they read of a stage is carried.
        let loads = alloc::vec![vec![0], vec![], vec![1], vec![0]];
        let (paged, rxs, carry) = branched(loads.clone())?;
        let layout = paged.layout();
        // A page's own gates start past the stages it loads, and the last
        // page's past the circuit's last stage, whatever it loads.
        assert_eq!(layout.firsts, [3, 1, 3, 3]);
        assert_eq!(layout.room(1), layout.room(0) + 2);
        let gates: Vec<usize> = paged.report().pages.iter().map(|page| page.gates).collect();
        assert_eq!(gates.iter().sum::<usize>(), 60);
        paged.check()?;

        let holds = branched_claims(&paged, &rxs, &carry, |page| loads[page].clone())?;
        assert_eq!(holds, [true; 4]);
        // The page that loads no stage reads none: either stage beside it
        // moves the gates its own polynomial is at.
        let holds = branched_claims(&paged, &rxs, &carry, |page| {
            if page == 1 {
                vec![0]
            } else {
                loads[page].clone()
            }
        })?;
        assert_eq!(holds, [true, false, true, true]);
        Ok(())
    }

    #[test]
    fn the_cuts_follow_what_the_pages_load() -> Result<()> {
        // The circuit's first half reads the first stage for the most part
        // and its second half the second, and each reads every value of
        // the other stage at some point: whichever pages load which, the
        // eight values of the two are carried, once each, beside what
        // crosses a cut.
        for loads in [
            alloc::vec![vec![0], vec![0], vec![1], vec![1]],
            alloc::vec![vec![1], vec![1], vec![0], vec![0]],
        ] {
            let (paged, ..) = branched(loads)?;
            paged.check()?;
            let report = paged.report();
            assert!(
                (8..=8 + 2 * report.cuts.len()).contains(&report.slots),
                "{report:?}"
            );
        }

        // Where every page loads everything, a cut is placed where few
        // wires are named across it: no worse than cutting evenly.
        let even = Paged::fitted(Chain::<100, 3>, &Stages::whole(1), 21)?;
        let placed = Paged::cut(
            Chain::<100, 3>,
            &Stages::whole(1).pages(even.num_pages()),
            limit(),
        )?;
        assert!(placed.report().slots <= even.report().slots);
        Ok(())
    }

    /// `LEN` squares of sums of the witness, all allocated first, then a
    /// product that takes them one by one: a batch computed long before it
    /// is used, as a batch of inverses is.
    struct Batch<const LEN: usize>;

    impl<const LEN: usize> Batch<LEN> {
        fn run(witness: Fp) -> Fp {
            let mut sum = witness;
            (0..LEN).fold(witness, |acc, _| {
                sum += witness;
                acc * sum.square()
            })
        }
    }

    impl<const LEN: usize> Circuit<Fp> for Batch<LEN> {
        type Instance<'source> = Fp;
        type Witness<'source> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Fp>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, &mut Standard::new(), instance)
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Fp>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
            let first = Element::alloc(dr, &mut Standard::new(), witness)?;
            let mut sum = first.clone();
            let mut squares = Vec::new();
            for _ in 0..LEN {
                sum = sum.add(dr, &first);
                squares.push(sum.square(dr)?);
            }
            let mut acc = first;
            for square in &squares {
                acc = acc.mul(dr, square)?;
            }
            Ok(WithAux::new(acc, D::unit()))
        }
    }

    #[test]
    fn a_gate_is_placed_with_the_first_gate_it_feeds() -> Result<()> {
        // In the order the circuit allocates its gates, a cut between the
        // squares and the product carries every square past it, more than
        // a carry stage beside the pages holds. Each square is placed with
        // the product that takes it, and a cut carries the running product
        // and the witness.
        let witness = Fp::from(3u64);
        let paged = Paged::cut(Batch::<40>, &Stages::whole(1).pages(4), limit())?;
        assert!(paged.report().slots <= 3 * 3, "{:?}", paged.report().cuts);
        paged.check()?;

        let mut traces = Vec::new();
        for index in 0..3 {
            traces.push(Some(paged.page(index).trace(witness)?.into_output()));
        }
        traces.push(Some(paged.last().trace(witness)?.into_output()));
        let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rand::rng()), &traces, &[])?;
        for index in 0..3 {
            assert!(page_claim_holds(paged.page(index), witness, (), &carry)?);
        }
        let instance = Batch::<40>::run(witness);
        assert!(page_claim_holds(paged.last(), witness, instance, &carry)?);
        Ok(())
    }

    #[test]
    fn stages_that_share_gates_cannot_be_loaded_together() {
        let cut = |loads| {
            Paged::cut(
                MultiStage::<Fp, R, _>::new(Branched::<60>),
                &Stages::of::<Fp, R, Branched<60>>().loading(loads),
                limit(),
            )
        };
        assert!(matches!(
            cut(alloc::vec![vec![0, 1], vec![0], vec![1], vec![1]]),
            Err(Error::Initialization(_))
        ));
        // Nor can a stage the circuit reads be loaded by no page.
        assert!(matches!(
            cut(alloc::vec![vec![0], vec![0], vec![0], vec![0]]),
            Err(Error::Initialization(_))
        ));
    }

    /// Holds each value of [`Left`] to the value of [`Right`] at its place:
    /// a circuit with no gates of its own, over two stages that share
    /// gates.
    struct Tie;

    impl MultiStageCircuit<Fp, R> for Tie {
        type Last = Right;
        type Instance<'source> = ();
        type Witness<'source> = ([Fp; 4], [Fp; 4]);
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _: &mut D,
            _: DriverValue<D, ()>,
        ) -> Result<Bound<'dr, D, ()>> {
            Ok(())
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
            witness: DriverValue<D, ([Fp; 4], [Fp; 4])>,
        ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>>
        where
            Self: 'dr,
        {
            let (left, builder) = builder.add_stage::<Left>()?;
            let (right, builder) = builder.add_stage::<Right>()?;
            let dr = builder.finish();
            let left = left.unenforced(dr, witness.as_ref().map(|w| w.0))?;
            let right = right.unenforced(dr, witness.as_ref().map(|w| w.1))?;
            for place in 0..4 {
                dr.enforce_zero(|lc| lc.add(left[place].wire()).sub(right[place].wire()))?;
            }
            Ok(WithAux::new((), D::unit()))
        }
    }

    #[test]
    fn a_circuit_without_gates_pages_too() -> Result<()> {
        let stages = Stages::of::<Fp, R, Tie>().loading(alloc::vec![vec![0], vec![1]]);
        let paged = Paged::cut(MultiStage::<Fp, R, _>::new(Tie), &stages, limit())?;
        assert_eq!(paged.num_pages(), 2);
        assert_eq!(paged.report().slots, 4);
        assert_eq!(paged.report().num_gates, stages.own_start());
        paged.check()?;

        // Each page's claim, on the stage it loads and the carry stage,
        // which holds the first stage's values for the second's page.
        let holds = |right: [u64; 4]| -> Result<[bool; 2]> {
            let mut rng = rand::rng();
            let witness = (LEFT.map(Fp::from), right.map(Fp::from));
            let left = <Left as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.0)?;
            let right = <Right as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.1)?;
            // No page has gates: the carry stage is read off the stage.
            let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &[], &[&left])?;
            let loaded = |stage: &sparse::Polynomial<Fp, R>| {
                let mut loaded = carry.clone();
                loaded.add_assign(stage);
                loaded
            };
            Ok([
                page_claim_holds(paged.page(0), witness, (), &loaded(&left))?,
                page_claim_holds(paged.last(), witness, (), &loaded(&right))?,
            ])
        };
        assert_eq!(holds(LEFT)?, [true, true]);
        assert_eq!(holds([3, 5, 7, 12])?, [true, false]);
        Ok(())
    }

    #[test]
    fn idle_pages_hold_stages_for_pages_that_load_none() -> Result<()> {
        // The first two pages hold no gates: each loads a stage and holds
        // slots to its values for the last two, which load neither and so
        // start at the first gate.
        let witness = (LEFT.map(Fp::from), RIGHT.map(Fp::from));
        let stages = Stages::of::<Fp, R, Branched<40>>()
            .loading(alloc::vec![vec![0], vec![1], vec![], vec![]])
            .idling(alloc::vec![0, 1])
            .unsealed();
        let paged = Paged::cut(
            MultiStage::<Fp, R, _>::new(Branched::<40>),
            &stages,
            limit(),
        )?;
        assert_eq!(paged.layout().firsts, [3, 3, 1, 1]);
        let gates: Vec<usize> = paged.report().pages.iter().map(|page| page.gates).collect();
        assert_eq!(gates[..2], [0, 0]);
        assert_eq!(gates.iter().sum::<usize>(), 40);
        paged.check()?;

        let mut rng = rand::rng();
        let traces = [
            None,
            None,
            Some(paged.page(2).trace(witness)?.into_output()),
            Some(paged.last().trace(witness)?.into_output()),
        ];
        let rxs = [
            <Left as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.0)?,
            <Right as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.1)?,
        ];
        let carry =
            paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces, &[&rxs[0], &rxs[1]])?;

        // An idle page's claim is on the stage it loads and the carry
        // stage: with the other stage, it fails.
        for page in 0..2 {
            for (stage, holds) in [(page, true), (1 - page, false)] {
                let mut loaded = carry.clone();
                loaded.add_assign(&rxs[stage]);
                assert_eq!(
                    page_claim_holds(paged.page(page), witness, (), &loaded)?,
                    holds
                );
            }
        }

        // The other pages' claims are on the carry stage alone.
        let instance = Branched::<40>::run(witness.0, witness.1);
        assert!(page_claim_holds(paged.page(2), witness, (), &carry)?);
        assert!(page_claim_holds(paged.last(), witness, instance, &carry)?);
        Ok(())
    }

    /// [`Branched`], with each value of [`Left`] held equal to the value of
    /// [`Right`] at the same place: a circuit that holds one stage to
    /// another that shares its gates.
    struct Tied<const LEN: usize>;

    impl<const LEN: usize> MultiStageCircuit<Fp, R> for Tied<LEN> {
        type Last = Right;
        type Instance<'source> = Fp;
        type Witness<'source> = ([Fp; 4], [Fp; 4]);
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Fp>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, &mut Standard::new(), instance)
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
            witness: DriverValue<D, ([Fp; 4], [Fp; 4])>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
        where
            Self: 'dr,
        {
            let (left, builder) = builder.add_stage::<Left>()?;
            let (right, builder) = builder.add_stage::<Right>()?;
            let dr = builder.finish();
            let left = left.unenforced(dr, witness.as_ref().map(|w| w.0))?;
            let right = right.unenforced(dr, witness.as_ref().map(|w| w.1))?;
            for place in 0..4 {
                dr.enforce_zero(|lc| lc.add(left[place].wire()).sub(right[place].wire()))?;
            }
            let mut acc = left[0].clone();
            for step in 0..LEN {
                let (near, far) = if step < LEN / 2 {
                    (&left, &right)
                } else {
                    (&right, &left)
                };
                acc = acc.square(dr)?;
                acc = acc.add(dr, &near[step % 4]);
                if step % 7 == 3 {
                    acc = acc.add(dr, &far[step % 4]);
                }
            }
            Ok(WithAux::new(acc, D::unit()))
        }
    }

    /// Whether each page's claim holds, for `Tied<40>` in two groups of two
    /// pages apart and two more pages, with `right` in the second stage.
    fn tied_claims(
        paged: &Paged<Fp, MultiStage<Fp, R, Tied<40>>>,
        right: [u64; 4],
    ) -> Result<Vec<bool>> {
        let mut rng = rand::rng();
        let witness = (LEFT.map(Fp::from), right.map(Fp::from));
        let instance = Branched::<40>::run(witness.0, witness.1);
        let rxs = [
            <Left as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.0)?,
            <Right as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.1)?,
        ];
        let stages = [&rxs[0], &rxs[1]];
        let traces = [
            None,
            None,
            None,
            None,
            Some(paged.page(4).trace(witness)?.into_output()),
            Some(paged.last().trace(witness)?.into_output()),
        ];
        let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces, &stages)?;
        let apart = [
            paged.apart_rx::<R>(0, Blind::<Fp>::random(&mut rng), &stages)?,
            paged.apart_rx::<R>(1, Blind::<Fp>::random(&mut rng), &stages)?,
        ];
        // A page's claim is on the stage it loads and its carry stage.
        let mut holds = Vec::new();
        for page in 0..6 {
            let mut loaded = if page < 4 {
                apart[page / 2].clone()
            } else {
                carry.clone()
            };
            loaded.add_assign(&rxs[page % 2]);
            holds.push(if page < 5 {
                page_claim_holds(paged.page(page), witness, (), &loaded)?
            } else {
                page_claim_holds(paged.last(), witness, instance, &loaded)?
            });
        }
        Ok(holds)
    }

    #[test]
    fn pages_apart_hold_what_ties_two_stages() -> Result<()> {
        // Two groups of two pages apart, a page for each stage, then two
        // pages for the circuit's gates.
        let stages = Stages::of::<Fp, R, Tied<40>>()
            .loading(alloc::vec![
                vec![0],
                vec![1],
                vec![0],
                vec![1],
                vec![0],
                vec![1]
            ])
            .apart(alloc::vec![2, 2]);
        let tied = || MultiStage::<Fp, R, _>::new(Tied::<40>);

        // The first group's carry stage has the room for every tie: the
        // second holds none, and neither do the other pages.
        let paged = Paged::cut(tied(), &stages, limit())?;
        assert_eq!(paged.report().apart, [4, 0]);
        let gates: Vec<usize> = paged.report().pages.iter().map(|page| page.gates).collect();
        assert_eq!(gates[..4], [0; 4]);
        assert_eq!(gates.iter().sum::<usize>(), 40);
        let layout = paged.layout();
        assert_eq!(layout.apart[0], (0..2, limit() - 2..limit()));
        assert_eq!(layout.apart[1], (2..4, limit()..limit()));
        assert_eq!(layout.window(0), 3..limit() - 2);
        assert_eq!(layout.window(1), layout.window(0));
        for group in 0..2 {
            let _: &dyn WiringObject<Fp, R> = &paged.apart_mask::<R>(group)?.into_inner();
        }
        paged.check()?;
        assert_eq!(tied_claims(&paged, LEFT)?, [true; 6]);
        // A second stage that is not the first fails the claim of the
        // page that holds the ties, and of the pages that read it.
        let holds = tied_claims(&paged, [3, 5, 7, 12])?;
        assert_eq!(holds[..4], [true, false, true, true]);

        // With a carry stage of one gate each, the groups hold two ties
        // each; with less, the other pages carry what is left.
        let own = paged.report().num_gates - stages.own_start();
        let spread = |first: usize, second: usize| -> Result<_> {
            let mut layout = Layout::fill(&stages, own, limit(), 8)?;
            layout.apart[0].1 = limit() - first..limit();
            layout.apart[1].1 = limit() - second..limit();
            let paged = Paged::new(tied(), &stages, layout)?;
            paged.check()?;
            assert_eq!(tied_claims(&paged, LEFT)?, [true; 6]);
            Ok(paged.report().apart.clone())
        };
        assert_eq!(spread(1, 1)?, [2, 2]);
        assert_eq!(spread(1, 0)?, [2, 0]);
        assert_eq!(spread(0, 0)?, [0, 0]);
        Ok(())
    }

    #[test]
    fn pages_that_share_a_carry_stage_keep_theirs_off_the_others() -> Result<()> {
        // Each stage is loaded by one page, then read by a page that loads
        // none; a last page loads the second, and the circuit takes them
        // all. With each pair of pages
        // sharing a carry stage, what the second of a pair reads of the
        // first, and of the stage the first loads, is carried there.
        let witness = (LEFT.map(Fp::from), RIGHT.map(Fp::from));
        let instance = Branched::<96>::run(witness.0, witness.1);
        let stages = Stages::of::<Fp, R, Branched<96>>().loading(alloc::vec![
            vec![0],
            vec![],
            vec![1],
            vec![],
            vec![1]
        ]);
        let branched = || MultiStage::<Fp, R, _>::new(Branched::<96>);
        let plain = Paged::cut(branched(), &stages, limit())?;
        let stages = stages.sharing(alloc::vec![0..2, 2..4]);
        let paged = Paged::cut(branched(), &stages, limit())?;
        paged.check()?;
        assert_eq!(paged.num_local(), 2);
        let report = paged.report();
        assert!(report.local.iter().all(|&slots| slots > 0), "{report:?}");
        assert!(report.slots < plain.report().slots, "{report:?}");
        // A shared carry stage is right before the circuit's, and its
        // pages' own gates end where it starts.
        let layout = paged.layout();
        for (group, (pages, gates)) in layout.local.iter().enumerate() {
            assert_eq!(gates.end, layout.carry.start);
            for page in pages.clone() {
                assert_eq!(layout.window(page).end, gates.start);
            }
            let _: &dyn WiringObject<Fp, R> = &paged.local_mask::<R>(group)?.into_inner();
        }
        assert_eq!(layout.window(4).end, layout.carry.start);

        let mut rng = rand::rng();
        let mut traces = Vec::new();
        for index in 0..4 {
            traces.push(Some(paged.page(index).trace(witness)?.into_output()));
        }
        traces.push(Some(paged.last().trace(witness)?.into_output()));
        let rxs = [
            <Left as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.0)?,
            <Right as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.1)?,
        ];
        let stage_rxs = [&rxs[0], &rxs[1]];
        let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces, &stage_rxs)?;
        let local = [
            paged.local_rx::<R>(0, Blind::<Fp>::random(&mut rng), &traces, &stage_rxs)?,
            paged.local_rx::<R>(1, Blind::<Fp>::random(&mut rng), &traces, &stage_rxs)?,
        ];
        // A page's claim is on the circuit's carry stage, the one it
        // shares, and the stages it loads: with the other pair's, it
        // fails.
        let holds = |page: usize, shared: Option<usize>| -> Result<bool> {
            let mut loaded = carry.clone();
            if let Some(group) = shared {
                loaded.add_assign(&local[group]);
            }
            for &stage in &stages.loads[page] {
                loaded.add_assign(&rxs[stage]);
            }
            if page < 4 {
                page_claim_holds(paged.page(page), witness, (), &loaded)
            } else {
                page_claim_holds(paged.last(), witness, instance, &loaded)
            }
        };
        for page in 0..4 {
            assert!(holds(page, Some(page / 2))?, "page {page}");
            assert!(!holds(page, Some(1 - page / 2))?, "page {page}");
        }
        assert!(holds(4, None)?);
        Ok(())
    }

    #[test]
    fn the_masks_cover_the_layout() -> Result<()> {
        let (paged, ..) = branched(alloc::vec![vec![0], vec![], vec![1], vec![0]])?;
        let layout = paged.layout();
        assert_eq!(layout.carry.end, limit());
        let _: &dyn WiringObject<Fp, R> = &paged.carry_mask::<R>()?.into_inner();
        for page in 0..4 {
            let _: &dyn WiringObject<Fp, R> = &paged.own_mask::<R>(page)?.into_inner();
            assert_eq!(layout.window(page), layout.firsts[page]..layout.carry.start);
        }
        Ok(())
    }
}
