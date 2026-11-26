//! Choosing the cuts: where a circuit's gates go, which page is each
//! constraint's home, what the carry stages hold, and what each page
//! replays.
//!
//! Nothing here is trusted. What this module produces is a [`Plan`], and
//! [`Paged::check`] holds the pages a plan gives to the circuit they were
//! cut from, whatever chose them: a profile's registrar runs it before it
//! registers a page.

use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    format,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::ops::Range;

use ragu_core::{
    Coeff, Error, Result,
    convert::WireMap,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::{Bound, Gadget},
    maybe::Empty,
    routines::Routine,
};
use udon::field::Field;

#[cfg(feature = "std")]
use super::Planned;
use super::{
    DERIVED, Layout, Link, ONE, PageReport, Paged, PagingReport, Plan, Program, Source, Stages,
    refuse,
};
use crate::{
    Circuit,
    raw::{CircuitAdapterRef, RawCircuit},
};

/// The places among a circuit's gates at which a cut is looked for, at
/// most: the circuit's gates are shared into as many stretches, and a cut
/// may fall at one gate of each.
pub(super) const GRID: usize = 1024;

/// What a value on the circuit's carry stage, which every page loads,
/// counts for against one on a carry stage that a group of pages shares,
/// where the cuts are looked for.
const SHARED: u64 = 4;

/// The rounds a cut's carry stages are sized halfway to what they turned
/// out to hold before they only grow.
const SETTLING: usize = 24;

/// How far a carry stage's size moves toward what its cuts held, while the
/// sizes settle: a part of the way, which shrinks each time the size turns
/// from too small to too large or back.
#[derive(Clone, Copy, Debug)]
struct Damping {
    /// The part of the way the size moves: a half, a quarter or an eighth.
    parts: usize,
    /// The smallest part it moves: a half where the sizes are not damped.
    most: usize,
    /// Whether the cuts last held more than the size, if they have held
    /// anything other than it.
    short: Option<bool>,
}

impl Damping {
    /// Halfway at first, and at most `most` parts of the way.
    fn new(most: usize) -> Self {
        Damping {
            parts: 2,
            most,
            short: None,
        }
    }

    /// Notes whether the cuts now hold more than the size, and whether
    /// that turned since the last time.
    fn turned(&mut self, short: bool) -> bool {
        self.short.replace(short).is_some_and(|was| was != short)
    }
}

/// What a carried value counts for where the cuts are looked for: a
/// stage's wire that several stretches of the circuit read counts for a
/// part of it in each.
const UNIT: u64 = 1 << 10;

/// What the cuts of a circuit are weighed by, for one order of its gates:
/// the same whatever the carry stages' sizes, so it is counted once and
/// the cuts looked for under each size off it.
struct Costs {
    /// The places a page may end at, each as the gates of the circuit's
    /// own before it: none, then one gate of each stretch of the
    /// circuit's gates, the one fewest wires are named across among those
    /// that split no routine, then all of them.
    places: Vec<usize>,
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
        let place = |gate: usize| placement.place(gate).map(|place| place - own_start);

        // For each wire of the circuit's own, the last gate a constraint
        // that names it is homed at; and each wire of a stage with the
        // gate a constraint that names it is homed at.
        let mut read: Vec<(u32, usize)> = Vec::new();
        let mut named: BTreeMap<u32, usize> = BTreeMap::new();
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
                    Some(_) => read.push((wire, position)),
                    None if wire >= 4 => {
                        let last = named.entry(wire).or_insert(position);
                        *last = (*last).max(position);
                    }
                    None => {}
                }
            }
        }

        // For a cut before each gate, the wires of the circuit's own
        // allocated before it that a constraint past it names, and
        // whether it splits a routine: falls after one of its gates and
        // not after all of them.
        let mut across = vec![0i64; own + 2];
        for (&wire, &last) in &named {
            let gate = place((wire / 4) as usize).expect("a gate of the circuit's own");
            if gate < last {
                across[gate + 1] += 1;
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
        // the gate fewest wires are named across among those that split
        // no routine, the last such gate if several do as well; and the
        // end of the circuit's gates.
        let step = own.div_ceil(GRID).max(1);
        let mut places = vec![0];
        for stretch in (0..own).step_by(step) {
            let found = (stretch + 1..=(stretch + step).min(own.saturating_sub(1)))
                .filter(|&gate| split[gate] == 0)
                .min_by_key(|&gate| (across[gate], core::cmp::Reverse(gate)));
            places.extend(found);
        }
        if own > 0 {
            places.push(own);
        }
        let last = places.len() - 1;

        // What each stretch between two places reads of each stage. A
        // stage's wire is carried once however many constraints name it,
        // so it counts for one [`UNIT`] over all the stretches that read
        // it.
        let read: BTreeSet<(u32, usize)> = read
            .into_iter()
            .map(|(wire, position)| (wire, places.partition_point(|&gates| gates <= position)))
            .collect();
        let mut reads = vec![vec![0u64; last + 1]; stages.spans.len()];
        let mut stretches: BTreeMap<u32, u64> = BTreeMap::new();
        for &(wire, _) in &read {
            *stretches.entry(wire).or_default() += 1;
        }
        for &(wire, stretch) in &read {
            let (stage, _) = stages
                .stage_of((wire / 4) as usize)
                .expect("a stage's wire");
            reads[stage][stretch.min(last)] += (UNIT / stretches[&wire]).max(1);
        }
        for stage in &mut reads {
            for place in 1..=last {
                stage[place] += stage[place - 1];
            }
        }
        let crossing = places.iter().map(|&gates| across[gates]).collect();

        Costs {
            places,
            reads,
            crossing,
        }
    }
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
    /// of the stages it does not load. The cuts are looked for at
    /// [`GRID`] places at most, none of which splits a routine the
    /// circuit calls, and what a cut carries is counted with repeats, so
    /// the layout is a good one rather than the best. The
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
        // before them.
        let Costs {
            places,
            reads,
            crossing,
        } = costs;
        debug_assert_eq!(places.last().copied().unwrap_or(0), own);
        let before = |place: usize| places[place];
        let places = places.len() - 1;

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
}

/// A combination nothing has asked a page for yet.
const UNSEEN: u32 = u32::MAX;

/// A combination that has nothing of what a page was asked for.
const NOTHING: u32 = u32::MAX - 1;

impl<F: Field> Plan<F> {
    /// Compiles each page into what it allocates and enforces, off
    /// `recording`, the walk the plan was made from: its own constraints
    /// with each slot in place of what they name off the page, then a
    /// constraint for each slot the page holds to its wires or to those
    /// of a stage it loads. The layout is final by then.
    ///
    /// The circuit's linear combinations stay combinations: a page makes
    /// what each one it needs has of its wires, over what the ones before
    /// have, so it enforces no more terms than the circuit does.
    pub(super) fn compile(&mut self, recording: &Recording<F>) {
        let pages = self.pages();
        // A wire of the circuit, as page `page` has it: `ONE`, a wire of
        // a stage the page loads, or one of the page's own gates.
        let local = |page: usize, wire: u32| -> Option<u32> {
            let (gate, kind) = ((wire / 4) as usize, wire % 4);
            if gate == 0 {
                return Some(wire);
            }
            let at = match self.stages.stage_of(gate) {
                Some((stage, offset)) => self
                    .stages
                    .loaded(page, stage)
                    .then(|| self.stages.spans[stage].start + offset)?,
                None => {
                    let (holder, at) = self.place(gate)?;
                    (holder == page).then_some(at)?
                }
            };
            Some(4 * at as u32 + kind)
        };
        // The wire of a carry stage page `page` loads that holds a slot.
        let slot = |page: usize, link: &Link<F>| -> u32 {
            let carry = if link.local {
                self.layout
                    .local_of(page)
                    .expect("a slot of the carry stage the page shares with its group")
            } else {
                self.layout.carry_of(page)
            };
            let kind = if link.slot.is_multiple_of(2) { 0 } else { 3 };
            4 * (carry.start + (link.slot / 2) as usize) as u32 + kind
        };
        // Whether a wire is among those a slot's source has.
        let of = |source: Source, wire: u32| -> bool {
            let gate = (wire / 4) as usize;
            match (source, self.stages.stage_of(gate)) {
                (Source::Stage(stage), Some((of, _))) => of == stage as usize,
                (Source::Page(page), None) => self
                    .place(gate)
                    .is_some_and(|(holder, _)| holder == page as usize),
                _ => false,
            }
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
            .map(|page| {
                let first = self.layout.firsts[page];
                let own = first..first + self.held[page].len();
                let carries = [self.layout.local_of(page), Some(self.layout.carry_of(page))];
                let end = carries
                    .into_iter()
                    .flatten()
                    .filter(|carry| !carry.is_empty())
                    .map(|carry| carry.end)
                    .fold(own.end, usize::max);
                Program {
                    gates: end - 1,
                    own,
                    sums: Vec::new(),
                    constraints: Vec::new(),
                    outputs: Vec::new(),
                }
            })
            .collect();
        // For a page and the wires asked of it, a source's or all it has:
        // the wire each of the circuit's combinations is there.
        let mut seen: BTreeMap<(usize, Option<(bool, u32)>), Vec<u32>> = BTreeMap::new();
        // What `terms` have on `page`, of `source` if one is given: the
        // page's wires and the combinations it makes of them.
        let mut held = |programs: &mut [Program<F>],
                        page: usize,
                        source: Option<Source>,
                        terms: &[(u32, F)]| {
            let key = source.map(|source| match source {
                Source::Page(page) => (false, page),
                Source::Stage(stage) => (true, stage),
            });
            let known = seen
                .entry((page, key))
                .or_insert_with(|| vec![UNSEEN; recording.derived.len()]);
            let resolve = |known: &[u32], terms: &[(u32, F)]| -> Vec<(u32, F)> {
                terms
                    .iter()
                    .filter_map(|&(wire, coeff)| {
                        let wire = if wire & DERIVED != 0 {
                            Some(known[(wire ^ DERIVED) as usize]).filter(|&at| at != NOTHING)?
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
                    _ => {
                        let sums = &mut programs[page].sums;
                        sums.push(coeffs(sum));
                        DERIVED | (sums.len() - 1) as u32
                    }
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
            named.extend(links.iter().map(|link| (slot(page, link), link.scale)));
            let program = &mut programs[page];
            match home {
                Some(_) => program.constraints.push(coeffs(named)),
                None => program.outputs.push(coeffs(named)),
            }
            for link in links.iter().filter(|link| link.defines) {
                let exporter = link.exporter as usize;
                let mut named = held(&mut programs, exporter, Some(link.source), &terms);
                named.push((slot(exporter, link), -link.scale));
                programs[exporter].constraints.push(coeffs(named));
            }
        }
        self.programs = programs;
        self.sums = recording.derived.len();
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

/// What one walk of a circuit emits: as emitted, over the gates' wires and
/// the linear combinations the circuit makes of them, and with every wire
/// followed back to the gates' wires.
pub(super) struct Recording<F> {
    /// The gates the circuit allocates, the SYSTEM gate included.
    num_gates: usize,
    /// The linear combinations [`Driver::add`] made, each over gates'
    /// wires and the combinations made before it, which a wire names by
    /// [`DERIVED`] and an index here.
    derived: Vec<Vec<(u32, F)>>,
    /// Each constraint as emitted, with the gates allocated by then.
    raw: Vec<(usize, Vec<(u32, F)>)>,
    /// Each wire of the public output as emitted, in traversal order.
    raw_outputs: Vec<u32>,
    /// The gates each routine the circuit calls allocates, in the order
    /// of the calls: those of a routine called within another are among
    /// the outer one's.
    pub(super) routines: Vec<Range<usize>>,
    /// Each constraint over the gates' wires, with the gates allocated
    /// when it was emitted: empty until the recording is
    /// [expanded](Self::expanded).
    constraints: Vec<(usize, Vec<(u32, F)>)>,
    /// Each wire of the public output over the gates' wires, likewise.
    outputs: Vec<Vec<(u32, F)>>,
}

/// The cuts made in this process, by a digest of what each was made of: a
/// circuit of a kind registered before, in this process, is not cut
/// again.
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
    /// A digest of the recording as emitted, the stages its pages load and
    /// the gates their polynomials hold: what a cut is a function of.
    #[cfg(feature = "std")]
    fn digest(&self, stages: &Stages, limit: usize) -> [u8; 32] {
        let mut state = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ragu_paging_cut_")
            .to_state();
        state.update(core::any::type_name::<F>().as_bytes());
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
        word(self.derived.len());
        word(self.raw.len());
        word(self.raw_outputs.len());
        let lists = self
            .derived
            .iter()
            .map(|terms| (0, terms))
            .chain(self.raw.iter().map(|(at, terms)| (*at, terms)));
        for (at, terms) in lists {
            state.update(&(at as u64).to_le_bytes());
            state.update(&(terms.len() as u64).to_le_bytes());
            for (wire, coeff) in terms {
                state.update(&wire.to_le_bytes());
                state.update(coeff.to_bytes().as_ref());
            }
        }
        for wire in &self.raw_outputs {
            state.update(&wire.to_le_bytes());
        }
        state.update(&(self.routines.len() as u64).to_le_bytes());
        for routine in &self.routines {
            state.update(&(routine.start as u64).to_le_bytes());
            state.update(&(routine.end as u64).to_le_bytes());
        }
        let mut digest = [0; 32];
        digest.copy_from_slice(state.finalize().as_bytes());
        digest
    }

    /// Walks `circuit` for what it emits, as emitted.
    fn raw_of<C: Circuit<F>>(circuit: &C) -> Result<Self> {
        let mut dr = Prober {
            recording: Recording {
                num_gates: 0,
                derived: Vec::new(),
                raw: Vec::new(),
                raw_outputs: Vec::new(),
                routines: Vec::new(),
                constraints: Vec::new(),
                outputs: Vec::new(),
            },
            depth: 0,
        };
        walk(&mut dr, &CircuitAdapterRef(circuit))?;
        Ok(dr.recording)
    }

    /// Walks `circuit`, and follows every wire back to the gates' wires.
    pub(super) fn of<C: Circuit<F>>(circuit: &C) -> Result<Self> {
        Ok(Self::raw_of(circuit)?.expanded())
    }

    /// The recording with every constraint and every wire of the public
    /// output followed back to the gates' wires.
    fn expanded(mut self) -> Self {
        use maybe_rayon::prelude::*;

        // Each is followed back on its own.
        let constraints = (0..self.raw.len())
            .into_par_iter()
            .map(|index| {
                let (at, terms) = &self.raw[index];
                (*at, self.expand(terms.clone()))
            })
            .collect();
        let outputs = self
            .raw_outputs
            .iter()
            .map(|&wire| self.expand(vec![(wire, F::ONE)]))
            .collect();
        self.constraints = constraints;
        self.outputs = outputs;
        self
    }

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
        debug_assert_eq!(placed as usize, own, "every gate is placed once");
        self.rank = rank;
    }

    /// The place of a gate counted over the whole circuit, counted from
    /// the first of the circuit's own likewise.
    fn place(&self, gate: usize) -> Option<usize> {
        let rank = *self.rank.get(gate.checked_sub(self.own_start)?)?;
        Some(self.own_start + rank as usize)
    }
}

/// The planning driver: its wires are the gates' wires or the linear
/// combinations the circuit makes of them, each kept as made.
struct Prober<F> {
    recording: Recording<F>,
    /// The routines the walk is within.
    depth: usize,
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
        // Every call makes a combination, so that a walk which only
        // counts the calls names the same ones.
        let derived = &mut self.recording.derived;
        let index = u32::try_from(derived.len()).expect("combinations fit a wire");
        assert!(index < NOTHING ^ DERIVED, "combinations fit a wire");
        derived.push(lc(Terms::new()).terms);
        DERIVED | index
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let at = self.recording.num_gates;
        self.recording.raw.push((at, lc(Terms::new()).terms));
        Ok(())
    }

    fn routine<Ro: Routine<F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        // Run where it is called, as a driver that knows no routines
        // runs it, and noted for the gates it allocates: a page holds
        // all of them or none.
        let start = self.recording.num_gates;
        self.depth += 1;
        let output = Emulator::predict(&routine, &input)
            .and_then(|predicted| routine.execute(self, input, predicted.into_aux()));
        self.depth -= 1;
        let gates = start..self.recording.num_gates;
        if self.depth == 0 && !gates.is_empty() {
            self.recording.routines.push(gates);
        }
        output
    }
}

/// Records each wire of the public output.
struct Recorder<'a, F: Field>(&'a mut Prober<F>);

impl<F: Field> WireMap<F> for Recorder<'_, F> {
    type Src = Prober<F>;
    type Dst = Prober<F>;

    fn convert_wire(&mut self, wire: &u32) -> Result<u32> {
        self.0.recording.raw_outputs.push(*wire);
        Ok(*wire)
    }
}

/// Walks `circuit` on the planning driver.
fn walk<'dr, F: Field, RC: RawCircuit<F> + 'dr>(dr: &mut Prober<F>, circuit: &RC) -> Result<()> {
    // The SYSTEM gate, which a page's driver has already allocated.
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
        programs: Vec::new(),
        sums: 0,
    };
    Ok((plan, report))
}

impl<F: Field, C: Circuit<F>> Paged<F, C> {
    fn cut_as(circuit: impl Into<Arc<C>>, (plan, report): (Plan<F>, PagingReport)) -> Self {
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
        let mut planned = arrange(&recording, &placement, stages, layout, &related)?;
        planned.0.fits()?;
        planned.0.compile(&recording);
        Ok(Self::cut_as(circuit, planned))
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
        let recording = Recording::raw_of(&*circuit)?;
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
        if let Some(planned) = memo::get::<Planned<F>>(&key) {
            return Ok(Self::planned(circuit, &planned));
        }
        // A circuit cut before is not followed back to its gates' wires
        // again.
        let recording = recording.expanded();

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
        let placements: [&(dyn Fn() -> Placement + Sync); 3] = [
            &|| Placement::of(&recording, stages.own_start(), Feeders::Deepest),
            &|| Placement::of(&recording, stages.own_start(), Feeders::Latest),
            &|| Placement::allocated(&recording, stages.own_start()),
        ];
        let cut = |placement: &(dyn Fn() -> Placement + Sync)| {
            let placement = &placement();
            let costs = Costs::of(&recording, placement, stages, &related);
            // A larger carry stage shrinks the pages, which moves the cuts
            // and may change what they carry: grow each until it holds.
            // A carry stage is first sized halfway to what the cuts last
            // made it hold: the pages of a group that shares one fill the
            // room a smaller stage leaves them and then read more off it,
            // so the size that holds is between the two. If the sizes do
            // not settle so, they only grow, by an eighth at least.
            //
            // The sizes of two groups that share carry stages can swing
            // instead, each round's cuts moving work from one group to the
            // other and back. Where they do not settle, the cuts are looked
            // for again with each size moving a smaller part of the way
            // each time it turns: a half, then a quarter, down to an
            // eighth ([`Damping`]).
            let sized = |rounds: usize, needed: usize, gates: usize, damping: &mut Damping| {
                if rounds <= SETTLING {
                    let short = needed > gates;
                    if damping.turned(short) {
                        damping.parts = (2 * damping.parts).min(damping.most);
                    }
                    let step = gates.abs_diff(needed) / damping.parts;
                    match (damping.parts, short) {
                        (2, _) => match (needed + gates).div_ceil(2) {
                            0 => 0,
                            halfway => halfway + 1,
                        },
                        (_, true) => gates + step + 1,
                        (_, false) => gates - step,
                    }
                } else if needed > gates {
                    needed.max(gates + gates / 8 + 1)
                } else {
                    gates
                }
            };
            let settle = |damped: bool| -> Result<(Plan<F>, PagingReport)> {
                let damping = Damping::new(if damped { 8 } else { 2 });
                let mut rounds = 0;
                let mut carry_gates = 0;
                let mut local_gates = vec![0; stages.local.len()];
                let mut carry_damping = damping;
                let mut local_damping = vec![damping; stages.local.len()];
                loop {
                    let sizes = (carry_gates, &local_gates[..]);
                    let fit =
                        Layout::fit(&costs, recording.num_gates, stages, limit, sizes, &related);
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
                        for ((_, gates), needed) in
                            planned.0.layout.local.iter_mut().zip(&needed_local)
                        {
                            *gates = start - needed..start;
                        }
                        return Ok(planned);
                    }
                    rounds += 1;
                    carry_gates = sized(rounds, needed, carry_gates, &mut carry_damping);
                    for ((gates, &needed), damping) in local_gates
                        .iter_mut()
                        .zip(&needed_local)
                        .zip(&mut local_damping)
                    {
                        *gates = sized(rounds, needed, *gates, damping);
                    }
                }
            };
            settle(false).or_else(|_| settle(true))
        };
        // Each order is cut on its own, so the three are cut at once.
        let (first, (second, third)) = maybe_rayon::join(
            || cut(placements[0]),
            || maybe_rayon::join(|| cut(placements[1]), || cut(placements[2])),
        );
        let mut least: Option<Result<(Plan<F>, PagingReport)>> = None;
        for cut in [first, second, third] {
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
        let mut planned = least.expect("an order")?;
        planned.0.compile(&recording);
        let paged = Self::cut_as(circuit, planned);
        #[cfg(feature = "std")]
        memo::put(key, paged.plan());
        Ok(paged)
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
        plan.compile(&recording);
        Ok(Self::cut_as(circuit, (plan, report)))
    }
}
