//! The pager. It chooses the cuts: where an unpaged circuit's gates go,
//! which page is each constraint's home, what the carry stage holds, and
//! what each page replays.
//!
//! Nothing here is trusted. What this module produces is a [`Plan`], and
//! [`Pages::check`] holds the pages a plan gives to the unpaged circuit
//! they were cut from, whatever chose them: a profile's registrar runs it
//! before it registers a page.

use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    format,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::ops::Range;

use ragu_core::{Coeff, Error, Result};
use udon::field::Field;

use super::{
    DERIVED, Layout, ONE, PageReport, Pageable, Pages, PagingReport, Plan, Stages,
    record::{Call, DERIVED_LIMIT, Recording},
    refuse,
    replay::{Body, Program, Step, Terms},
};
use crate::{Circuit, polynomials::Rank, staging::MultiStage};

/// The target number of stretches to search for cuts. Each contributes
/// at most one candidate, alongside the beginning and end of the circuit.
pub(super) const GRID: usize = 1024;

/// The linear combinations a cut would carry, each named once.
///
/// A constraint homed past a cut names, of the gates before it, a linear
/// combination of their wires, which one carry slot holds for every
/// constraint that names a multiple of it ([`normalized`]). With a
/// constraint's terms in the order their gates are placed in, what it names
/// before a cut is what it names before an earlier cut and more terms. So a
/// combination is kept as the one before it and its last term, scaled so
/// that the first term's coefficient is one: a constraint finds every one
/// it names in one pass over its terms, and two constraints that name the
/// same one find the same.
struct Carried {
    /// The scaled coefficients met, by their bytes: one is the first.
    coeffs: BTreeMap<Vec<u8>, u32>,
    /// Each combination, by the one before it, its last wire and that
    /// wire's scaled coefficient.
    combinations: BTreeMap<(u32, u32, u32), u32>,
    /// For each combination, the cuts that carry it, each cut as the gates
    /// before it: from the first past its last gate to the last before a
    /// constraint that names it names another gate, or is homed. Nothing
    /// carries one whose last is before its first.
    cuts: Vec<(usize, usize)>,
}

impl Carried {
    /// No combination yet.
    const NONE: u32 = u32::MAX;

    fn new<F: Field>() -> Self {
        Carried {
            coeffs: BTreeMap::from([(F::ONE.to_bytes().as_ref().to_vec(), 0)]),
            combinations: BTreeMap::new(),
            cuts: Vec::new(),
        }
    }

    /// Names what a constraint homed at gate `home` names before each cut
    /// it is past: `terms` are its terms over the circuit's own gates, each
    /// with its gate's place, in the order of the places.
    fn name<F: Field>(&mut self, terms: &[(usize, u32, F)], home: usize) {
        let Some(&(_, _, scale)) = terms.first() else {
            return;
        };
        let mut inverse = None;
        let mut combination = Self::NONE;
        for (index, &(place, wire, coeff)) in terms.iter().enumerate() {
            let coeff = if index == 0 {
                0
            } else {
                let inverse = *inverse
                    .get_or_insert_with(|| scale.invert().expect("expanded terms are nonzero"));
                let bytes = (coeff * inverse).to_bytes();
                let next = u32::try_from(self.coeffs.len()).expect("coefficients fit a u32");
                match self.coeffs.get(bytes.as_ref()) {
                    Some(&coeff) => coeff,
                    None => {
                        self.coeffs.insert(bytes.as_ref().to_vec(), next);
                        next
                    }
                }
            };
            let next = u32::try_from(self.cuts.len()).expect("combinations fit a u32");
            combination = match self.combinations.entry((combination, wire, coeff)) {
                Entry::Vacant(entry) => {
                    self.cuts.push((place + 1, 0));
                    *entry.insert(next)
                }
                Entry::Occupied(entry) => *entry.get(),
            };
            // The constraint names this much and no more before every cut
            // up to the next gate it names, or to its home.
            let until = terms.get(index + 1).map_or(home, |&(next, _, _)| next);
            let (_, last) = &mut self.cuts[combination as usize];
            *last = (*last).max(until);
        }
    }
}

/// Candidate boundaries and their costs for one gate placement.
struct Costs {
    /// The places a page may end at, each as the gates of the circuit's
    /// own before it: none, then one gate of each stretch of the
    /// circuit's gates, the one a cut before which carries least among
    /// those that split no routine, then all of them.
    places: Vec<usize>,
    /// For each place, what a cut there carries: the distinct linear
    /// combinations, up to scale, that the constraints past it name of the
    /// circuit's own gates before it.
    carried: Vec<i64>,
}

impl Costs {
    /// Counts them for `recording` with its gates in `placement`'s order.
    fn of<F: Field>(recording: &Recording<F>, placement: &Placement, stages: &Stages) -> Self {
        let own_start = stages.own_start();
        let own = recording.num_gates.saturating_sub(own_start);
        let place = |gate: usize| placement.place(gate).map(|place| place - own_start);

        // What each constraint names of the circuit's own gates before
        // each cut it is past. Its home is the page of the last gate it
        // names; one that names a stage's wires alone carries nothing.
        let mut carried = Carried::new::<F>();
        let mut named = Vec::new();
        let mut name = |terms: &[(u32, F)], home: Option<usize>| {
            named.clear();
            named.extend(
                terms
                    .iter()
                    .filter_map(|&(wire, coeff)| Some((place((wire / 4) as usize)?, wire, coeff))),
            );
            named.sort_unstable_by_key(|&(place, wire, _)| (place, wire));
            if let Some(&(last, _, _)) = named.last() {
                carried.name(&named, home.unwrap_or(last));
            }
        };
        for (_, terms) in &recording.constraints {
            name(terms, None);
        }
        // The public output is the last page's (see `arrange`), so each of
        // its wires is named at the end of the circuit: what it has of an
        // earlier page is carried to the last.
        for terms in &recording.outputs {
            name(terms, Some(own));
        }

        // For a cut before each gate, the combinations it carries, and
        // whether it splits a routine: falls after one of its gates and
        // not after all of them.
        let mut across = vec![0i64; own + 2];
        for &(first, last) in &carried.cuts {
            if first <= last {
                across[first] += 1;
                across[last + 1] -= 1;
            }
        }
        let mut split = vec![0i64; own + 2];
        for routine in recording.routines() {
            let gates = routine.clone().filter_map(place);
            if let (Some(first), Some(last)) = (gates.clone().min(), gates.max()) {
                split[first + 1] += 1;
                split[last + 1] -= 1;
            }
        }
        for gate in 1..across.len() {
            across[gate] += across[gate - 1];
            split[gate] += split[gate - 1];
        }

        // The places a page may end at: of each stretch of `step` gates,
        // the gate a cut before which carries least among those that
        // split no routine, the last such gate if several do as well; and
        // the end of the circuit's gates.
        let step = own.div_ceil(GRID).max(1);
        let mut places = vec![0];
        let mut start = 0;
        for end in (step..own).step_by(step).chain(core::iter::once(own)) {
            let found = (start + 1..=end.min(own.saturating_sub(1)))
                .filter(|&gate| split[gate] == 0)
                .min_by_key(|&gate| (across[gate], core::cmp::Reverse(gate)));
            places.extend(found);
            start = end;
        }
        if own > 0 {
            places.push(own);
        }
        let carried = places.iter().map(|&gates| across[gates]).collect();
        Costs { places, carried }
    }

    /// What the page from place `start` to place `end` adds to what the
    /// pages carry: what the cut at its end carries, unless the page holds
    /// no gate or ends the circuit.
    fn cost(&self, start: usize, end: usize) -> u64 {
        if start == end || end + 1 == self.places.len() {
            return 0;
        }
        self.carried[end] as u64
    }
}

impl Layout {
    /// The layout that cuts `recording` into the pages of `stages`, in
    /// polynomials of `limit` gates, so that the pages carry little by
    /// `costs`. The cuts are looked for on a grid whose candidates
    /// preserve whole routines. The costs only estimate carry: a
    /// combination carried across several cuts is counted at each, and
    /// takes one slot. `arrange` counts the actual slots, and the cut is
    /// taken only if those fit the carry stage.
    fn fit(costs: &Costs, num_gates: usize, stages: &Stages, limit: usize) -> Result<Self> {
        let short = || Error::GateBoundExceeded { limit };
        let pages = stages.num_pages();
        let own_start = stages.own_start();
        let own = num_gates.saturating_sub(own_start);
        let carry = stages.carry_gates();
        let room = limit.checked_sub(carry.end).ok_or_else(short)?;

        // The places a page may end at, as gates of the circuit's own
        // before them.
        let places = &costs.places;
        assert_eq!(places.last().copied().unwrap_or(0), own);
        let before = |place: usize| places[place];
        let places = places.len() - 1;

        // The least a cut of the gates before each place into the pages so
        // far carries, and where the last of those pages then starts.
        const NONE: u64 = u64::MAX;
        let mut least = vec![NONE; places + 1];
        least[0] = 0;
        let mut cuts: Vec<Vec<usize>> = Vec::with_capacity(pages);
        for _ in 0..pages {
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
                    let carried = least[start] + costs.cost(start, end);
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
            carry,
            limit,
            starts,
        })
    }
}

/// A combination nothing has asked a page for yet: a wire no recording
/// names (see [`DERIVED_LIMIT`]).
const UNSEEN: u32 = DERIVED | (DERIVED_LIMIT + 1);

/// A combination that has nothing of what a page was asked for, likewise.
const NOTHING: u32 = DERIVED | DERIVED_LIMIT;

/// A carry slot a constraint reads off its home page.
#[derive(Clone, Debug)]
pub(super) struct Link<F> {
    /// The page whose wires the slot combines, which holds the slot to
    /// them.
    pub(super) exporter: u32,
    pub(super) slot: u32,
    /// The constraint names `scale` times the slot's combination.
    pub(super) scale: F,
    /// Whether this constraint is the first to name the slot: the one its
    /// exporter holds the slot to.
    pub(super) defines: bool,
}

/// The pager's working plan: each constraint's home page and carry slots,
/// fixed by one walk of the circuit, the layout it chose, and what each
/// page replays. Only [`finish`](Self::finish) leaves this module.
#[derive(Clone, Debug)]
pub(super) struct Draft<F: Field> {
    pub(super) layout: Layout,
    /// The home page of each constraint, in emission order.
    pub(super) homes: Vec<u32>,
    /// The slots of the constraints that read any, by constraint.
    pub(super) links: BTreeMap<u32, Vec<Link<F>>>,
    /// The slots of each wire of the public output, in traversal order;
    /// their home is the last page.
    pub(super) outputs: Vec<Vec<Link<F>>>,
    /// For each routine the circuit calls, in the order of the calls, the
    /// page that calls it and the slots of each wire of its input.
    pub(super) calls: Vec<(u32, Vec<Vec<Link<F>>>)>,
    /// Each slot's combination, over wires named `4 * gate + kind` with
    /// the gate counted over the unpaged circuit.
    pub(super) slots: Vec<Vec<(u32, F)>>,
    /// For each gate of the circuit's own, in the order it allocates them,
    /// the page that holds it and the gate's index among the gates the
    /// page allocates, after the SYSTEM gate and the stages'.
    pub(super) places: Vec<(u32, u32)>,
    /// For each page, the gates of the circuit's own it holds, counted
    /// over the unpaged circuit, in the order the page allocates them:
    /// those no routine allocates, then those of each routine it calls.
    pub(super) held: Vec<Vec<u32>>,
    /// For each page, how many of them no routine allocates.
    pub(super) root: Vec<usize>,
    /// What each page allocates and enforces, once the plan is
    /// [compiled](Self::compile).
    pub(super) programs: Vec<Program<F>>,
    /// The linear combinations the circuit makes, likewise.
    pub(super) sums: usize,
}

impl<F: Field> Draft<F> {
    fn pages(&self) -> usize {
        self.layout.starts.len()
    }

    /// The page that holds a gate of the circuit's own, counted over the
    /// unpaged circuit, and the gate's index among the gates that page
    /// allocates.
    pub(super) fn place(&self, gate: usize) -> Option<(usize, usize)> {
        let (page, local) = *self.places.get(gate.checked_sub(self.layout.own_start)?)?;
        Some((page as usize, local as usize))
    }

    /// What the pager hands over of a compiled draft.
    pub(super) fn finish(self) -> Plan<F> {
        Plan {
            limit: self.layout.limit,
            held: self.held,
            slots: self.slots,
            programs: self.programs,
            sums: self.sums,
            constraints: self.homes.len(),
        }
    }
}

impl<F: Field> Draft<F> {
    /// Compiles each page into what it allocates and enforces, off
    /// `recording`, the walk the plan was made from: its own constraints
    /// with each slot in place of what they name off the page, a
    /// constraint for each slot the page holds to its wires, and a call
    /// for each routine it holds, in the order the circuit emits them. The
    /// layout is final by then.
    ///
    /// The circuit's linear combinations stay combinations: a page makes
    /// what each one it needs has of its wires, over what the ones before
    /// have, so it enforces no more terms than the circuit does.
    pub(super) fn compile(&mut self, recording: &Recording<F>) {
        let mut compiler = Compiler::new(self, recording);
        let mut calls = recording.calls.iter().enumerate().peekable();
        let mut within = 0;
        for (index, (_, terms)) in recording.raw.iter().enumerate() {
            // A routine is called where the circuit calls it, and what it
            // enforces is its body's.
            while let Some((call, called)) =
                calls.next_if(|(_, called)| called.constraints.start == index)
            {
                compiler.call(call, called);
                within = called.constraints.end;
            }
            if index < within {
                continue;
            }
            let links = u32::try_from(index)
                .ok()
                .and_then(|index| self.links.get(&index))
                .map_or(&[][..], Vec::as_slice);
            let home = self.homes[index] as usize;
            let named = compiler.named(home, terms, links);
            compiler.programs[home].enforce(coeffs(named));
            compiler.define(terms, links);
        }
        for (call, called) in calls {
            compiler.call(call, called);
        }
        // The public output's wires are the last page's: the others only
        // hold slots to what it reads of them.
        let last = self.pages() - 1;
        for (&wire, links) in recording.raw_outputs.iter().zip(&self.outputs) {
            let terms = [(wire, F::ONE)];
            let named = compiler.named(last, &terms, links);
            compiler.programs[last].outputs.push(coeffs(named));
            compiler.define(&terms, links);
        }
        self.programs = compiler.programs;
        self.sums = recording.adds;
    }
}

/// Terms as a page runs them.
fn coeffs<F: Field>(terms: Vec<(u32, F)>) -> Terms<F> {
    terms
        .into_iter()
        .map(|(wire, coeff)| {
            let coeff = if coeff == F::ONE {
                Coeff::One
            } else if coeff == -F::ONE {
                Coeff::NegativeOne
            } else {
                Coeff::Arbitrary(coeff)
            };
            (wire, coeff)
        })
        .collect()
}

/// A wire of the output of a routine the circuit calls, as the pages have
/// it. The wire is what the routine's own gates give, which only the page
/// that calls the routine holds, plus what the routine passes through of
/// its inputs and of `ONE`, which is a combination like any other.
struct Given<F> {
    /// The call, by its place among the circuit's.
    call: usize,
    /// The wire's place in the call's output.
    place: usize,
    /// What the wire has of the call's inputs, each by the call's name
    /// for it, and of `ONE`.
    passed: Vec<(u32, F)>,
    /// Whether it has anything of the routine's own gates.
    own: bool,
}

/// Compiles a draft's pages ([`Draft::compile`]).
struct Compiler<'a, F: Field> {
    draft: &'a Draft<F>,
    recording: &'a Recording<F>,
    programs: Vec<Program<F>>,
    /// For a page and the wires asked of it, those of its own gates or all
    /// it has: the wire each of the circuit's combinations is there.
    seen: BTreeMap<(usize, bool), Vec<u32>>,
    /// Each wire a routine the circuit calls gives, by the circuit's name
    /// for it.
    given: BTreeMap<u32, Given<F>>,
    /// For each call a page has made, the wires it named for the call's
    /// input and the first wire of the call's output.
    called: Vec<Option<(Vec<u32>, u32)>>,
    /// What the gates of a routine give of a wire of its output, on the
    /// page that calls it: by the circuit's name for the wire.
    own: BTreeMap<u32, u32>,
}

impl<'a, F: Field> Compiler<'a, F> {
    fn new(draft: &'a Draft<F>, recording: &'a Recording<F>) -> Self {
        let mut given = BTreeMap::new();
        for (call, called) in recording.calls.iter().enumerate() {
            for (place, name) in called.outputs.clone().enumerate() {
                // What the wire is within the call, over the call's gates,
                // its inputs and `ONE`.
                let within = recording.expand_to(recording.derived[name].clone(), &called.inputs);
                let (passed, own): (Vec<_>, Vec<_>) = within
                    .into_iter()
                    .partition(|&(wire, _)| wire & DERIVED != 0 || wire == ONE);
                given.insert(
                    u32::try_from(name).expect("combinations fit a wire"),
                    Given {
                        call,
                        place,
                        passed,
                        own: !own.is_empty(),
                    },
                );
            }
        }
        Compiler {
            draft,
            recording,
            programs: (0..draft.pages())
                .map(|page| Program::new(draft.root[page]))
                .collect(),
            seen: BTreeMap::new(),
            given,
            called: vec![None; recording.calls.len()],
            own: BTreeMap::new(),
        }
    }

    /// A wire of the circuit, as page `page` has it: `ONE` or a wire of a
    /// stage, which every page has where the circuit does, or one of the
    /// gates the page allocates outside any routine.
    fn local(&self, page: usize, wire: u32) -> Option<u32> {
        let (gate, kind) = ((wire / 4) as usize, wire % 4);
        if gate < self.draft.layout.own_start {
            return Some(wire);
        }
        let (holder, at) = self.draft.place(gate)?;
        (holder == page).then_some(4 * at as u32 + kind)
    }

    /// Whether a wire is of a page's own gates: what a slot the page holds
    /// combines.
    fn of(&self, page: u32, wire: u32) -> bool {
        self.draft
            .place((wire / 4) as usize)
            .is_some_and(|(holder, _)| holder == page as usize)
    }

    /// The wire of the carry stage that holds a slot.
    fn slot(&self, link: &Link<F>) -> u32 {
        let kind = if link.slot.is_multiple_of(2) { 0 } else { 3 };
        4 * (self.draft.layout.carry.start + (link.slot / 2) as usize) as u32 + kind
    }

    /// What the routine's own gates give of a wire of its output, on the
    /// page that calls the routine: the wire, less what it passes through.
    fn own(&mut self, name: u32) -> u32 {
        if let Some(&wire) = self.own.get(&name) {
            return wire;
        }
        let given = &self.given[&name];
        let (page, _) = self.draft.calls[given.call];
        let (inputs, first) = self.called[given.call]
            .as_ref()
            .expect("a wire is given by a call the page has made");
        let first_input = self.recording.calls[given.call].inputs.start as u32;
        let mut terms = vec![(first + given.place as u32, F::ONE)];
        terms.extend(given.passed.iter().map(|&(wire, coeff)| {
            let wire = if wire == ONE {
                ONE
            } else {
                inputs[((wire ^ DERIVED) - first_input) as usize]
            };
            (wire, -coeff)
        }));
        let wire = match terms[..] {
            [(wire, _)] => wire,
            _ => self.programs[page as usize].sum(coeffs(terms)),
        };
        self.own.insert(name, wire);
        wire
    }

    /// What `terms` have on `page`, of its own gates alone if `source`
    /// names it: the page's wires and the combinations it makes of them.
    fn held(&mut self, page: usize, source: Option<u32>, terms: &[(u32, F)]) -> Vec<(u32, F)> {
        let recording = self.recording;
        let key = (page, source.is_some());
        let mut known = self
            .seen
            .remove(&key)
            .unwrap_or_else(|| vec![UNSEEN; recording.derived.len()]);
        // The combinations the terms reach that the page has not made,
        // each after those it names. What a routine gives is reached as
        // what it passes through: its own gates are not the page's to
        // name.
        let mut reached = BTreeSet::new();
        let mut pending = inner(terms);
        while let Some(index) = pending.pop() {
            if known[index as usize] == UNSEEN && reached.insert(index) {
                pending.extend(inner(match self.given.get(&index) {
                    Some(given) => &given.passed,
                    None => &recording.derived[index as usize],
                }));
            }
        }
        for index in reached {
            let sum = match self.given.get(&index) {
                None => self.resolve(page, source, &known, &recording.derived[index as usize]),
                Some(given) => {
                    let here = given.own && self.draft.calls[given.call].0 as usize == page;
                    let mut sum = self.resolve(page, source, &known, &self.given[&index].passed);
                    if here {
                        sum.push((self.own(index), F::ONE));
                    }
                    sum
                }
            };
            known[index as usize] = match sum[..] {
                [] => NOTHING,
                [(wire, coeff)] if coeff == F::ONE => wire,
                _ => self.programs[page].sum(coeffs(sum)),
            };
        }
        let held = self.resolve(page, source, &known, terms);
        self.seen.insert(key, known);
        held
    }

    /// `terms` over the wires of `page`, with each combination as `known`
    /// has it.
    fn resolve(
        &self,
        page: usize,
        source: Option<u32>,
        known: &[u32],
        terms: &[(u32, F)],
    ) -> Vec<(u32, F)> {
        terms
            .iter()
            .filter_map(|&(wire, coeff)| {
                let wire = if wire & DERIVED != 0 {
                    Some(known[(wire ^ DERIVED) as usize]).filter(|&at| at != NOTHING)?
                } else {
                    source
                        .is_none_or(|source| self.of(source, wire))
                        .then(|| self.local(page, wire))??
                };
                Some((wire, coeff))
            })
            .collect()
    }

    /// `terms` in full on `page`: what it holds of them, and a slot for
    /// what each other page does.
    fn named(&mut self, page: usize, terms: &[(u32, F)], links: &[Link<F>]) -> Vec<(u32, F)> {
        let mut named = self.held(page, None, terms);
        named.extend(links.iter().map(|link| (self.slot(link), link.scale)));
        named
    }

    /// Holds each slot that `terms` are the first to name to what its page
    /// has of them.
    fn define(&mut self, terms: &[(u32, F)], links: &[Link<F>]) {
        for link in links.iter().filter(|link| link.defines) {
            let exporter = link.exporter as usize;
            let mut named = self.held(exporter, Some(link.exporter), terms);
            named.push((self.slot(link), -link.scale));
            self.programs[exporter].enforce(coeffs(named));
        }
    }

    /// Calls a routine on the page that holds it: the page makes each wire
    /// of the routine's input in full, and the routine's body is the
    /// recording's.
    fn call(&mut self, call: usize, called: &Call) {
        let draft = self.draft;
        let (page, links) = &draft.calls[call];
        let page = *page as usize;
        let mut inputs = Vec::with_capacity(called.inputs.len());
        for (name, links) in called.inputs.clone().zip(links) {
            let terms = [(DERIVED | name as u32, F::ONE)];
            let named = self.named(page, &terms, links);
            inputs.push(match named[..] {
                [(wire, coeff)] if coeff == F::ONE => wire,
                _ => self.programs[page].sum(coeffs(named)),
            });
            self.define(&terms, links);
        }
        let body = Arc::new(body(self.recording, called));
        let first = self.programs[page].call(body, inputs.clone());
        self.called[call] = Some((inputs, first));
    }
}

/// The combinations `terms` name.
fn inner<F>(terms: &[(u32, F)]) -> Vec<u32> {
    terms
        .iter()
        .filter(|(wire, _)| wire & DERIVED != 0)
        .map(|(wire, _)| wire ^ DERIVED)
        .collect()
}

/// What a routine the circuit calls runs, off the recording of the call:
/// its own gates, the combinations it makes, its constraints and the calls
/// it makes, each stream in the order the circuit emits it, and over the
/// routine's own names.
fn body<F: Field>(recording: &Recording<F>, call: &Call) -> Body<F> {
    // The routine's name for each of the circuit's names it may use: its
    // inputs, then what it makes. One it has no name for is left as a wire
    // no routine holds, and a page that calls the routine is refused.
    let names = call.inputs.start..call.outputs.start;
    let mut made: Vec<u32> = (0..names.len())
        .map(|name| {
            if name < call.inputs.len() {
                DERIVED | name as u32
            } else {
                NOTHING
            }
        })
        .collect();
    let mut next = call.inputs.len() as u32;
    // Its own gates, counted apart from those of the calls it makes.
    let mut gates: Vec<u32> = vec![u32::MAX; call.gates.len()];
    let mut own = 0;
    fn local<F: Field>(
        terms: &[(u32, F)],
        call: &Call,
        made: &[u32],
        gates: &[u32],
    ) -> Vec<(u32, F)> {
        let name = |wire: u32| -> Option<u32> {
            if wire == ONE {
                return Some(ONE);
            }
            if wire & DERIVED != 0 {
                let name = ((wire ^ DERIVED) as usize).checked_sub(call.inputs.start)?;
                return made.get(name).copied();
            }
            let gate = ((wire / 4) as usize).checked_sub(call.gates.start)?;
            let own = *gates.get(gate)?;
            (own != u32::MAX).then(|| 4 * (own + 1) + wire % 4)
        };
        terms
            .iter()
            .map(|&(wire, coeff)| (name(wire).unwrap_or(NOTHING), coeff))
            .collect()
    }

    let mut steps = Vec::new();
    // What the routine emits itself up to a call it makes, or to its end:
    // its gates, then its combinations, then its constraints. Each names
    // only what is emitted before it.
    let (mut gate, mut sum, mut constraint) =
        (call.gates.start, call.sums.start, call.constraints.start);
    let mut emit = |steps: &mut Vec<Step<F>>,
                    made: &mut Vec<u32>,
                    next: &mut u32,
                    gates: &mut Vec<u32>,
                    until: (usize, usize, usize),
                    resume: (usize, usize, usize)| {
        if until.0 > gate {
            steps.push(Step::Gates(until.0 - gate));
            for gate in gate..until.0 {
                gates[gate - call.gates.start] = own;
                own += 1;
            }
        }
        for sum in sum..until.1 {
            let terms = local(&recording.derived[sum], call, made, gates);
            steps.push(Step::Sum(coeffs(terms)));
            made[sum - call.inputs.start] = DERIVED | *next;
            *next += 1;
        }
        for constraint in constraint..until.2 {
            let terms = local(&recording.raw[constraint].1, call, made, gates);
            steps.push(Step::Enforce(coeffs(terms)));
        }
        (gate, sum, constraint) = resume;
    };
    for within in &call.calls {
        emit(
            &mut steps,
            &mut made,
            &mut next,
            &mut gates,
            (
                within.gates.start,
                within.inputs.start,
                within.constraints.start,
            ),
            (within.gates.end, within.outputs.end, within.constraints.end),
        );
        // The wires it is called on are the caller's, and what it gives
        // are the next the caller names.
        let inputs = within
            .inputs
            .clone()
            .map(|name| local(&recording.derived[name], call, &made, &gates)[0].0)
            .collect();
        steps.push(Step::Call(Arc::new(body(recording, within)), inputs));
        for name in within.outputs.clone() {
            made[name - call.inputs.start] = DERIVED | next;
            next += 1;
        }
    }
    let end = (call.gates.end, call.sums.end, call.constraints.end);
    emit(&mut steps, &mut made, &mut next, &mut gates, end, end);
    let outputs = call
        .outputs
        .clone()
        .map(|name| local(&recording.derived[name], call, &made, &gates)[0].0)
        .collect();
    Body::new(call.inputs.len(), steps, outputs)
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
/// allocated before it. The wires of the circuit's public output are read
/// in the last stretch: a stage's wire that a circuit returns is read,
/// though no constraint of its body names it.
///
/// # Errors
///
/// Fails if the circuit cannot be walked.
#[cfg(any(test, feature = "test-utils"))]
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
    for &(wire, _) in recording.outputs.iter().flatten() {
        if let Some((stage, _)) = stages.stage_of((wire / 4) as usize) {
            read[parts - 1][stage].insert(wire);
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
/// the order the circuit allocates its gates in first, and in each of
/// these orders only where that cut does not fit the carry stage: placing
/// the gates is most of a cut's work, and most circuits cut as allocated.
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
        assert_eq!(
            placed as usize, own,
            "every gate feeds one that feeds nothing"
        );
        let mut placement = Placement { own_start, rank };
        let routines: Vec<_> = recording.routines().cloned().collect();
        placement.gather(&routines);
        placement
    }

    /// Brings the gates of each of `routines` together, in the order the
    /// circuit allocates them, at the place of the last of them: a routine
    /// is cut whole, and its last gates are beside what reads it.
    fn gather(&mut self, routines: &[Range<usize>]) {
        if routines.is_empty() {
            return;
        }
        let own = self.rank.len();
        let within = |routine: &Range<usize>| {
            let start = routine.start.saturating_sub(self.own_start).min(own);
            start..routine.end.saturating_sub(self.own_start).min(own)
        };
        // The routine each gate is of, and the last place of each
        // routine's gates.
        let mut of = vec![usize::MAX; own];
        let mut last = vec![0u32; routines.len()];
        for (index, routine) in routines.iter().enumerate() {
            for gate in within(routine) {
                of[gate] = index;
                last[index] = last[index].max(self.rank[gate]);
            }
        }
        let mut order = vec![0usize; own];
        for (gate, &rank) in self.rank.iter().enumerate() {
            order[rank as usize] = gate;
        }
        let mut rank = vec![u32::MAX; own];
        let mut placed = 0;
        for gate in order {
            let gates = match of[gate] {
                usize::MAX => gate..gate + 1,
                index if self.rank[gate] == last[index] => within(&routines[index]),
                _ => continue,
            };
            for gate in gates {
                rank[gate] = placed;
                placed += 1;
            }
        }
        assert_eq!(placed as usize, own, "every gate is placed once");
        self.rank = rank;
    }

    /// The place of a gate counted over the unpaged circuit, counted from
    /// the first of the circuit's own likewise.
    fn place(&self, gate: usize) -> Option<usize> {
        let rank = *self.rank.get(gate.checked_sub(self.own_start)?)?;
        Some(self.own_start + rank as usize)
    }
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
    slots: Vec<Vec<(u32, F)>>,
    slot_keys: BTreeMap<Vec<u8>, u32>,
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

    /// Homes a constraint emitted with `at` gates allocated, on `home` or
    /// else on the last page it names a wire of, and gives the slots it
    /// reads off that page.
    fn home(&mut self, lc: &[(u32, F)], home: Option<usize>, at: usize) -> (usize, Vec<Link<F>>) {
        let (home, links) = self.read(lc, home, at);
        self.pages[home].constraints += 1;
        if !links.is_empty() {
            self.cross_constraints += 1;
        }
        (home, links)
    }

    /// Notes a constraint a routine enforces, on the page that calls the
    /// routine: it reads no slot, and what it names of the stages it
    /// names through the routine's inputs.
    fn within(&mut self, lc: &[(u32, F)], caller: usize) {
        let own_start = self.own_start;
        let acc = &mut self.pages[caller];
        acc.constraints += 1;
        acc.stage_wires.extend(
            lc.iter()
                .map(|&(wire, _)| wire)
                .filter(|&wire| (1..own_start).contains(&((wire / 4) as usize))),
        );
    }

    /// The page that calls a routine, and the slots it reads for each wire
    /// of the routine's input, which are added to `calls`.
    fn call(
        &mut self,
        recording: &Recording<F>,
        call: &Call,
        calls: &mut Vec<(u32, Vec<Vec<Link<F>>>)>,
    ) -> usize {
        let on = if call.gates.is_empty() {
            call.gates.start.checked_sub(1)
        } else {
            Some(call.gates.start)
        };
        let caller = on.and_then(|gate| self.page_of(gate)).unwrap_or(0);
        let links = call
            .inputs
            .clone()
            .map(|name| {
                let wire = recording.expand(vec![(DERIVED | name as u32, F::ONE)]);
                self.read(&wire, Some(caller), call.gates.start).1
            })
            .collect();
        calls.push((u32::try_from(caller).expect("pages fit a u32"), links));
        caller
    }

    /// As [`home`](Self::home), for what need not be a constraint: a wire
    /// a page is to hold in full reads the same slots.
    fn read(&mut self, lc: &[(u32, F)], home: Option<usize>, at: usize) -> (usize, Vec<Link<F>>) {
        let mut own: BTreeMap<usize, Vec<(u32, F)>> = BTreeMap::new();
        let mut staged: Vec<u32> = Vec::new();
        for &(wire, coeff) in lc {
            let gate = (wire / 4) as usize;
            if gate == 0 {
                continue;
            }
            match self.page_of(gate) {
                Some(page) => own.entry(page).or_default().push((wire, coeff)),
                // A stage's wire, which every page has.
                None => staged.push(wire),
            }
        }

        let home = match (home, own.keys().next_back()) {
            (Some(home), _) => home,
            (None, Some(&page)) => page,
            // Only stages' wires: the page the walk is on.
            (None, None) => at
                .checked_sub(1)
                .and_then(|gate| self.page_of(gate))
                .unwrap_or(0),
        };
        self.pages[home].stage_wires.extend(staged);

        let mut links = Vec::new();
        for (exporter, component) in own.into_iter().filter(|(page, _)| *page != home) {
            let (scale, normalized, key) = normalized(&component);
            for &(wire, _) in &normalized {
                let last = self.carried.entry(wire).or_insert(home);
                *last = (*last).max(home);
                self.pages[home].imported_wires.insert(wire);
                self.pages[exporter].exported_wires.insert(wire);
            }
            let next = u32::try_from(self.slots.len()).expect("slots fit a u32");
            let (slot, defines) = match self.slot_keys.entry(key) {
                Entry::Vacant(entry) => {
                    entry.insert(next);
                    self.slots.push(normalized);
                    (next, true)
                }
                Entry::Occupied(entry) => (*entry.get(), false),
            };
            self.pages[home].imported_slots.insert(slot);
            links.push(Link {
                exporter: u32::try_from(exporter).expect("pages fit a u32"),
                slot,
                scale,
                defines,
            });
        }
        (home, links)
    }
}

/// Homes `recording`'s constraints on the pages of `layout`.
fn arrange<F: Field>(
    recording: &Recording<F>,
    placement: &Placement,
    stages: &Stages,
    layout: Layout,
) -> Result<(Draft<F>, PagingReport)> {
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
        || layout.starts[0] != layout.own_start
        || layout.starts.windows(2).any(|pair| pair[0] > pair[1])
        || layout.starts[pages - 1] > num_gates
    {
        return refuse(format!(
            "a layout of {} pages does not cut the circuit's gates into its {pages} pages",
            layout.starts.len()
        ));
    }
    for page in 0..pages {
        let end = layout.starts.get(page + 1).copied().unwrap_or(num_gates);
        let gates = end - layout.starts[page];
        if gates > layout.room() {
            return refuse(format!(
                "page {page} holds {gates} gates of the circuit's own, which the stages and \
                 the carry stage, up to gate {}, leave no room for before gate {}",
                layout.carry.end, layout.limit,
            ));
        }
    }

    // Each gate's page, and its index there. A page allocates the gates
    // no routine allocates first, in the order the circuit allocates them,
    // and then calls its routines, each of which allocates its own.
    let own = num_gates - layout.own_start;
    let mut routine = vec![false; own];
    for gates in recording.routines() {
        for gate in gates
            .clone()
            .filter_map(|gate| gate.checked_sub(layout.own_start))
        {
            routine[gate] = true;
        }
    }
    let mut held: Vec<Vec<u32>> = vec![Vec::new(); pages];
    let mut root = vec![0; pages];
    let mut places = vec![(0, 0); own];
    for within in [false, true] {
        for gate in
            (layout.own_start..num_gates).filter(|gate| routine[gate - layout.own_start] == within)
        {
            let page = placement
                .place(gate)
                .and_then(|place| layout.page_of(place))
                .expect("a gate of the circuit's own has a place");
            places[gate - layout.own_start] =
                (page as u32, (layout.carry.end + held[page].len()) as u32);
            held[page].push(gate as u32);
        }
        if !within {
            root = held.iter().map(Vec::len).collect();
        }
    }
    // A routine the circuit calls stays whole, by what the check holds the
    // pages to.
    let placed = |gate: usize| {
        let &(page, at) = places.get(gate.checked_sub(layout.own_start)?)?;
        Some((page as usize, at as usize))
    };
    if let Some(routine) = recording.split_routine(placed) {
        return refuse(format!(
            "the layout splits a routine the circuit calls, at gates {routine:?}"
        ));
    }

    let mut arranger = Arranger {
        own_start: layout.own_start,
        places: &places,
        slots: Vec::new(),
        slot_keys: BTreeMap::new(),
        pages: (0..pages).map(|_| PageAcc::default()).collect(),
        cross_constraints: 0,
        carried: BTreeMap::new(),
    };
    let mut homes = Vec::with_capacity(recording.constraints.len());
    let mut links = BTreeMap::new();
    let mut calls = Vec::with_capacity(recording.calls.len());
    let mut next = recording.calls.iter().peekable();
    let mut within = 0..0;
    let mut caller = 0;
    for (index, (at, terms)) in recording.constraints.iter().enumerate() {
        // A routine is called on one page, which holds its gates: the
        // page the walk is on, for a routine without gates. That page
        // makes each wire of the routine's input in full, as the last
        // page does each wire of the public output, and what the routine
        // enforces is over its inputs and its own gates, so it reads no
        // slot itself.
        while let Some(call) = next.next_if(|call| call.constraints.start == index) {
            caller = arranger.call(recording, call, &mut calls);
            within = call.constraints.clone();
        }
        if within.contains(&index) {
            arranger.within(terms, caller);
            homes.push(u32::try_from(caller).expect("pages fit a u32"));
            continue;
        }
        let index = u32::try_from(index).expect("constraints fit a u32");
        let (home, read) = arranger.home(terms, None, *at);
        homes.push(u32::try_from(home).expect("pages fit a u32"));
        if !read.is_empty() {
            links.insert(index, read);
        }
    }
    for call in next {
        arranger.call(recording, call, &mut calls);
    }
    // The public output binds one instance polynomial, so one page holds
    // every wire of it: the last.
    let mut outputs = Vec::with_capacity(recording.outputs.len());
    for terms in &recording.outputs {
        outputs.push(arranger.home(terms, Some(pages - 1), num_gates).1);
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
    };
    let slots = arranger.slots;
    let plan = Draft {
        layout,
        homes,
        links,
        outputs,
        calls,
        slots,
        places,
        held,
        root,
        programs: Vec::new(),
        sums: 0,
    };
    Ok((plan, report))
}

impl<F: Field, R: Rank, S: Pageable<F, R>> Pages<F, R, S> {
    /// Cuts `circuit` into `pages` pages, in polynomials of rank `R`: each
    /// page holds what it has room for past the circuit's stages and its
    /// carry stage, and the cuts are placed where the pages then carry
    /// little. The pages are not yet held to the circuit
    /// ([`check`](Self::check)).
    ///
    /// # Errors
    ///
    /// Fails if the circuit cannot be walked, if its stages do not follow
    /// one another, if the pages do not have the room, or if they carry
    /// more values than the carry stage holds.
    pub fn cut(circuit: impl Into<Arc<MultiStage<F, R, S>>>, pages: usize) -> Result<Self> {
        Self::cut_at(circuit.into(), pages, R::blind_gate())
    }

    /// As [`cut`](Self::cut), in polynomials of `limit` gates, which need
    /// not be those of rank `R`: a registry of rank `R` takes the pages
    /// only if they are. It is for sizing a circuit that does not cut.
    ///
    /// # Errors
    ///
    /// As [`cut`](Self::cut).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn cut_within(
        circuit: impl Into<Arc<MultiStage<F, R, S>>>,
        pages: usize,
        limit: usize,
    ) -> Result<Self> {
        Self::cut_at(circuit.into(), pages, limit)
    }

    fn cut_at(circuit: Arc<MultiStage<F, R, S>>, pages: usize, limit: usize) -> Result<Self> {
        let (mut draft, report, recording) = Self::drafted(&circuit, pages, limit)?;
        draft.compile(&recording);
        Ok(Self::over(circuit, Arc::new(draft.finish()), report))
    }

    /// The pager's choice for `circuit`, before it is compiled into what
    /// each page runs, and the walk it was made from.
    pub(super) fn drafted(
        circuit: &MultiStage<F, R, S>,
        pages: usize,
        limit: usize,
    ) -> Result<(Draft<F>, PagingReport, Recording<F>)> {
        let stages = &Stages::of::<F, R, S>().pages(pages);
        stages.check()?;
        let recording = Recording::of(circuit)?;
        if recording.num_gates < stages.own_start() {
            return refuse(format!(
                "the circuit's {} gates do not follow its stages', which end at gate {}",
                recording.num_gates,
                stages.own_start()
            ));
        }

        let own_start = stages.own_start();
        let cut = |placement: Placement| -> Result<_> {
            let costs = Costs::of(&recording, &placement, stages);
            let layout = Layout::fit(&costs, recording.num_gates, stages, limit)?;
            let planned = arrange(&recording, &placement, stages, layout)?;
            let slots = planned.1.slots;
            // An over-capacity placement contributes only its slot count.
            Ok((slots, (slots <= stages.carry).then_some(planned)))
        };
        // With every gate where the circuit allocates it, first: a cut that
        // fits so is taken, and no other order is looked at.
        let allocated = cut(Placement::allocated(&recording, own_start));
        if let Ok((_, Some((draft, report)))) = allocated {
            return Ok((draft, report, recording));
        }
        // Otherwise with the gates that wait placed beside their use,
        // either way: whichever carries least.
        let (deepest, latest) = maybe_rayon::join(
            || cut(Placement::of(&recording, own_start, Feeders::Deepest)),
            || cut(Placement::of(&recording, own_start, Feeders::Latest)),
        );
        // Fixed order breaks ties even when the placements run in parallel.
        let (needed, cut) = [deepest, latest, allocated]
            .into_iter()
            .reduce(|a, b| match (&a, &b) {
                (Ok((first, _)), Ok((next, _))) if next < first => b,
                (Err(_), Ok(_)) => b,
                _ => a,
            })
            .expect("three placements")?;
        if let Some((draft, report)) = cut {
            return Ok((draft, report, recording));
        }
        refuse(format!(
            "the circuit carries {needed} values between pages, more than the {} their carry stage holds",
            stages.carry
        ))
    }
}
