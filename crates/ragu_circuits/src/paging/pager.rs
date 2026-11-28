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
    DERIVED, Layout, PageReport, Pageable, Pages, PagingReport, Plan, Program, Stages,
    record::{DERIVED_LIMIT, Recording},
    refuse,
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
        for routine in &recording.routines {
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
    /// Each slot's combination, over wires named `4 * gate + kind` with
    /// the gate counted over the unpaged circuit.
    pub(super) slots: Vec<Vec<(u32, F)>>,
    /// For each gate of the circuit's own, in the order it allocates them,
    /// the page that holds it and the gate's index in that page's
    /// polynomial.
    pub(super) places: Vec<(u32, u32)>,
    /// For each page, the gates of the circuit's own it holds, counted
    /// over the unpaged circuit, in the order of the page's polynomial.
    pub(super) held: Vec<Vec<u32>>,
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
    /// unpaged circuit, and the gate's index in that page's polynomial.
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
    /// with each slot in place of what they name off the page, then a
    /// constraint for each slot the page holds to its wires. The layout is
    /// final by then.
    ///
    /// The circuit's linear combinations stay combinations: a page makes
    /// what each one it needs has of its wires, over what the ones before
    /// have, so it enforces no more terms than the circuit does.
    pub(super) fn compile(&mut self, recording: &Recording<F>) {
        let pages = self.pages();
        // A wire of the circuit, as page `page` has it: `ONE` or a wire
        // of a stage, which every page has where the circuit does, or one
        // of the page's own gates.
        let own_start = self.layout.own_start;
        let local = |page: usize, wire: u32| -> Option<u32> {
            let (gate, kind) = ((wire / 4) as usize, wire % 4);
            if gate < own_start {
                return Some(wire);
            }
            let (holder, at) = self.place(gate)?;
            (holder == page).then_some(4 * at as u32 + kind)
        };
        // The wire of the carry stage that holds a slot.
        let slot = |link: &Link<F>| -> u32 {
            let kind = if link.slot.is_multiple_of(2) { 0 } else { 3 };
            4 * (self.layout.carry.start + (link.slot / 2) as usize) as u32 + kind
        };
        // Whether a wire is of a page's own gates: what a slot the page
        // holds combines.
        let of = |page: u32, wire: u32| -> bool {
            self.place((wire / 4) as usize)
                .is_some_and(|(holder, _)| holder == page as usize)
        };
        let coeffs = |terms: Vec<(u32, F)>| -> Vec<(u32, Coeff<F>)> {
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
        };

        let mut programs: Vec<Program<F>> = (0..pages)
            .map(|page| Program::new(self.held[page].len()))
            .collect();
        // For a page and the wires asked of it, those of its own gates
        // or all it has: the wire each of the circuit's combinations is
        // there.
        let mut seen: BTreeMap<(usize, bool), Vec<u32>> = BTreeMap::new();
        // What `terms` have on `page`, of its own gates alone if `source`
        // names it: the page's wires and the combinations it makes of
        // them.
        let mut held =
            |programs: &mut [Program<F>], page: usize, source: Option<u32>, terms: &[(u32, F)]| {
                let known = seen
                    .entry((page, source.is_some()))
                    .or_insert_with(|| vec![UNSEEN; recording.derived.len()]);
                let resolve = |known: &[u32], terms: &[(u32, F)]| -> Vec<(u32, F)> {
                    terms
                        .iter()
                        .filter_map(|&(wire, coeff)| {
                            let wire = if wire & DERIVED != 0 {
                                Some(known[(wire ^ DERIVED) as usize])
                                    .filter(|&at| at != NOTHING)?
                            } else {
                                source
                                    .is_none_or(|source| of(source, wire))
                                    .then(|| local(page, wire))??
                            };
                            Some((wire, coeff))
                        })
                        .collect()
                };
                // The combinations the terms reach that the page has not made,
                // each after those it names.
                let inner = |terms: &[(u32, F)]| -> Vec<u32> {
                    terms
                        .iter()
                        .filter(|(wire, _)| wire & DERIVED != 0)
                        .map(|(wire, _)| wire ^ DERIVED)
                        .collect()
                };
                let mut reached = BTreeSet::new();
                let mut pending = inner(terms);
                while let Some(index) = pending.pop() {
                    if known[index as usize] == UNSEEN && reached.insert(index) {
                        pending.extend(inner(&recording.derived[index as usize]));
                    }
                }
                for index in reached {
                    let sum = resolve(known, &recording.derived[index as usize]);
                    known[index as usize] = match sum[..] {
                        [] => NOTHING,
                        [(wire, coeff)] if coeff == F::ONE => wire,
                        _ => programs[page].sum(coeffs(sum)),
                    };
                }
                resolve(known, terms)
            };

        let none: &[Link<F>] = &[];
        let constraints = recording.raw.iter().zip(&self.homes).enumerate().map(
            |(index, ((_, terms), &home))| {
                let links = u32::try_from(index)
                    .ok()
                    .and_then(|index| self.links.get(&index))
                    .map_or(none, Vec::as_slice);
                (terms.clone(), Some(home as usize), links)
            },
        );
        // The public output's wires are the last page's: the others only
        // hold slots to what it reads of them.
        let outputs = recording
            .raw_outputs
            .iter()
            .zip(&self.outputs)
            .map(|(&wire, links)| (vec![(wire, F::ONE)], None, links.as_slice()));
        for (terms, home, links) in constraints.chain(outputs) {
            let page = home.unwrap_or(pages - 1);
            let mut named = held(&mut programs, page, None, &terms);
            named.extend(links.iter().map(|link| (slot(link), link.scale)));
            let program = &mut programs[page];
            match home {
                Some(_) => program.enforce(coeffs(named)),
                None => program.outputs.push(coeffs(named)),
            }
            for link in links.iter().filter(|link| link.defines) {
                let exporter = link.exporter as usize;
                let mut named = held(&mut programs, exporter, Some(link.exporter), &terms);
                named.push((slot(link), -link.scale));
                programs[exporter].enforce(coeffs(named));
            }
        }
        self.programs = programs;
        self.sums = recording.adds;
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
        placement.gather(&recording.routines);
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
        let acc = &mut self.pages[home];
        acc.constraints += 1;
        acc.stage_wires.extend(staged);

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
        if !links.is_empty() {
            self.cross_constraints += 1;
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

    // Each gate's page, and its index there: a page's polynomial holds
    // its gates in the order the circuit allocates them.
    let mut held: Vec<Vec<u32>> = vec![Vec::new(); pages];
    let mut places = Vec::with_capacity(num_gates - layout.own_start);
    for gate in layout.own_start..num_gates {
        let page = placement
            .place(gate)
            .and_then(|place| layout.page_of(place))
            .expect("a gate of the circuit's own has a place");
        places.push((page as u32, (layout.carry.end + held[page].len()) as u32));
        held[page].push(gate as u32);
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
    for (index, (at, terms)) in recording.constraints.iter().enumerate() {
        let index = u32::try_from(index).expect("constraints fit a u32");
        let (home, read) = arranger.home(terms, None, *at);
        homes.push(u32::try_from(home).expect("pages fit a u32"));
        if !read.is_empty() {
            links.insert(index, read);
        }
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
        slots,
        places,
        held,
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
