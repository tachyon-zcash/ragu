//! Structural check of a page plan against the circuit it splits.

use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    format, vec,
    vec::Vec,
};
use core::ops::Range;

use ragu_core::{Error, Result};
use udon::field::Field;

use super::{Carry, Layout, Pageable, Pages, Plan, Stages, record::Recording, refuse};
use crate::{
    Circuit,
    metrics::{self, DeepFingerprint, RoutineIdentity},
    polynomials::Rank,
    staging::Stage,
};

/// A wire of the unpaged circuit, or one of the independent carry values
/// the pages load. A page gate outside the stages, its own gates and the
/// carry stage gets a distinct symbol, so a constraint cannot quietly use
/// it as an original wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Symbol {
    One,
    Wire(u32),
    Slot(usize),
    Unused(usize, usize, u32),
}

impl Symbol {
    fn wire(gate: usize, kind: u32) -> Result<Self> {
        if gate == 0 {
            return Ok(Self::One);
        }
        let wire = u32::try_from(gate)
            .ok()
            .and_then(|gate| gate.checked_mul(4))
            .and_then(|wire| wire.checked_add(kind))
            .ok_or_else(|| Error::Initialization("a paged circuit has too many gates".into()))?;
        Ok(Self::Wire(wire))
    }

    fn original(wire: u32) -> Self {
        if wire == 3 {
            Self::One
        } else {
            Self::Wire(wire)
        }
    }
}

/// A canonical linear form over the symbols above. Zero coefficients are
/// removed, including those obtained when the circuit names a wire twice.
#[derive(Clone, Debug)]
struct Form<F: Field>(BTreeMap<Symbol, F>);

type Key = Vec<(Symbol, Vec<u8>)>;

impl<F: Field> Default for Form<F> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<F: Field> Form<F> {
    fn add(&mut self, symbol: Symbol, coefficient: F) {
        if coefficient == F::ZERO {
            return;
        }
        match self.0.entry(symbol) {
            Entry::Vacant(entry) => {
                entry.insert(coefficient);
            }
            Entry::Occupied(mut entry) => {
                let value = *entry.get() + coefficient;
                if value == F::ZERO {
                    entry.remove();
                } else {
                    *entry.get_mut() = value;
                }
            }
        }
    }

    fn add_scaled(&mut self, other: &Self, scale: F) {
        for (&symbol, &coefficient) in &other.0 {
            self.add(symbol, coefficient * scale);
        }
    }

    fn from_original(terms: &[(u32, F)]) -> Self {
        let mut form = Self::default();
        for &(wire, coefficient) in terms {
            form.add(Symbol::original(wire), coefficient);
        }
        form
    }

    fn from_page(
        terms: &[(u32, F)],
        mut symbol: impl FnMut(u32) -> Result<Symbol>,
    ) -> Result<Self> {
        let mut form = Self::default();
        for &(wire, coefficient) in terms {
            form.add(symbol(wire)?, coefficient);
        }
        Ok(form)
    }

    fn substitute(&self, slots: &BTreeMap<Symbol, Self>) -> Self {
        let mut form = Self::default();
        for (&symbol, &coefficient) in &self.0 {
            match slots.get(&symbol) {
                Some(source) => form.add_scaled(source, coefficient),
                None => form.add(symbol, coefficient),
            }
        }
        form
    }

    fn key_with(&self, scale: F) -> Key {
        self.0
            .iter()
            .map(|(&symbol, &coefficient)| {
                (symbol, (coefficient * scale).to_bytes().as_ref().to_vec())
            })
            .collect()
    }

    fn key(&self) -> Key {
        self.key_with(F::ONE)
    }

    /// Constraints enforce zero, so a nonzero multiple is the same
    /// definition. Only the carry definitions are matched up to scale; the
    /// circuit's own constraints are compared with their exact coefficients.
    fn definition_key(&self) -> Key {
        let scale = self
            .0
            .values()
            .next()
            .and_then(|coefficient| coefficient.invert())
            .unwrap_or(F::ONE);
        self.key_with(scale)
    }

    fn one() -> Self {
        let mut form = Self::default();
        form.add(Symbol::One, F::ONE);
        form
    }
}

fn multiset<F: Field>(forms: impl IntoIterator<Item = Form<F>>) -> BTreeMap<Key, usize> {
    let mut counts = BTreeMap::new();
    for form in forms {
        *counts.entry(form.key()).or_insert(0) += 1;
    }
    counts
}

/// Checks that every gate of the circuit's own is on exactly one page and
/// that each page allocates the gates it holds, and gives where each gate
/// is: for each, in the order the circuit allocates them, its page and its
/// index in that page's polynomial. The symbolic comparison below relies on
/// this map, which is derived here and is not the pager's.
///
/// Where the stages and the carry stage lie is not checked: `layout` is
/// derived from the circuit's type, and the plan does not say.
fn places<F: Field>(
    plan: &Plan<F>,
    stages: &Stages,
    layout: &Layout,
    body_gates: usize,
) -> Result<Vec<(usize, usize)>> {
    stages.check()?;
    let pages = plan.pages();
    let Some(own) = body_gates.checked_sub(stages.own_start()) else {
        return refuse("the circuit has fewer gates than its stages".into());
    };
    if plan.programs.len() != pages || plan.own() != own {
        return refuse("the pages' layout does not cover the circuit".into());
    }
    let first = layout.carry.end;
    let mut places = vec![None; own];
    for (page, held) in plan.held.iter().enumerate() {
        let Some(own_end) = first.checked_add(held.len()) else {
            return refuse("a page's gate range overflows".into());
        };
        if own_end > layout.limit {
            return refuse(format!(
                "page {page} holds more gates than a polynomial has"
            ));
        }
        for (offset, &gate) in held.iter().enumerate() {
            let gate = gate as usize;
            if gate < stages.own_start() || gate >= body_gates {
                return refuse(format!("page {page} holds a gate outside the circuit"));
            }
            let place = &mut places[gate - stages.own_start()];
            if place.is_some() {
                return refuse(format!("page {page} duplicates a gate"));
            }
            *place = Some((page, first + offset));
        }
        if plan.programs[page].gates() != held.len() {
            return refuse(format!("page {page} allocates other gates than it holds"));
        }
    }
    if plan.slots.len() > stages.carry {
        return refuse(format!(
            "the circuit carries {} values between pages, more than the {} their carry stage \
             holds",
            plan.slots.len(),
            stages.carry,
        ));
    }
    // As many places as gates, none twice: every gate has one.
    places
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::Initialization("the pages omit a gate of the circuit".into()))
}

fn carry_symbol(page: usize, gate: usize, kind: u32, range: &Range<usize>) -> Option<Symbol> {
    if !range.contains(&gate) {
        return None;
    }
    Some(match kind {
        0 | 3 => Symbol::Slot(2 * (gate - range.start) + usize::from(kind == 3)),
        _ => Symbol::Unused(page, gate, kind),
    })
}

/// The original wire, carry slot, or unused wire a page's local wire names.
/// `page_body` is the gate after the last the page's steps allocate: the
/// caller counts it once for the page, and not for each wire.
fn page_symbol<F: Field>(
    plan: &Plan<F>,
    layout: &Layout,
    page: usize,
    wire: u32,
    body_gates: usize,
    page_body: usize,
) -> Result<Symbol> {
    let (gate, kind) = ((wire / 4) as usize, wire % 4);
    if gate == 0 {
        return Ok(Symbol::One);
    }
    if gate >= page_body {
        // Only the last page writes the public output. Its extra gates are
        // allocated in the same order as the unpaged circuit's output gates.
        if page + 1 != plan.pages() {
            return refuse("a page before the last writes extra gates".into());
        }
        let global = body_gates
            .checked_add(gate - page_body)
            .ok_or_else(|| Error::Initialization("the output has too many gates".into()))?;
        return Symbol::wire(global, kind);
    }

    if let Some(symbol) = carry_symbol(page, gate, kind, &layout.carry) {
        return Ok(symbol);
    }
    // A stage's gate is the circuit's, at the same place.
    if gate < layout.own_start {
        return Symbol::wire(gate, kind);
    }
    if let Some(offset) = gate.checked_sub(layout.carry.end)
        && let Some(&original) = plan.held[page].get(offset)
    {
        return Symbol::wire(original as usize, kind);
    }
    Ok(Symbol::Unused(page, gate, kind))
}

/// The fingerprint of each routine `circuit` calls, those called within
/// another included, in the order the walk meets the calls: what a driver
/// tells one routine from another by.
fn routines<F: Field, C: Circuit<F>>(circuit: &C) -> Result<Vec<DeepFingerprint>> {
    Ok(metrics::eval(circuit)?
        .segments
        .iter()
        .filter_map(|segment| match segment.identity() {
            RoutineIdentity::Routine(fingerprint) => Some(*fingerprint),
            RoutineIdentity::Root => None,
        })
        .collect())
}

/// Checks that the pages call the routines the circuit calls: between
/// them, routines with the fingerprints of the circuit's, each as many
/// times.
///
/// A fingerprint is of a routine's own gates and constraints, of the wires
/// it gives and of the routines it calls, so a page that holds a routine's
/// gates and enforces its constraints as its own, outside any routine, or
/// in another order, has not called it. This is not what holds the pages
/// to the circuit's relation: the constraints are compared whole, whatever
/// routine emits them. It holds a page's segments to the circuit's, which
/// a driver that keeps what a routine emits relies on.
fn check_routines<F: Field, R: Rank, S: Pageable<F, R>>(paged: &Pages<F, R, S>) -> Result<()> {
    let mut called = routines(&*paged.circuit)?;
    let last = paged.plan.pages() - 1;
    let mut found = routines(&paged.last())?;
    for page in 0..last {
        found.extend(routines(&paged.page(page))?);
    }
    called.sort_unstable();
    found.sort_unstable();
    if called != found {
        return refuse(format!(
            "the pages call {} routines, which are not the {} the circuit calls",
            found.len(),
            called.len()
        ));
    }
    Ok(())
}

/// Checks the complete emitted relations, treating carry slots as
/// independent wires until their defining equations have been found. Gives
/// whether the circuit ends its public output with a constant zero
/// ([`Checked::ends_in_zero`](super::Checked::ends_in_zero)).
pub(super) fn check<F: Field, R: Rank, S: Pageable<F, R>>(paged: &Pages<F, R, S>) -> Result<bool> {
    let (plan, stages, layout) = (&*paged.plan, &paged.stages, &paged.layout);
    // The stages and the layout are derived from the circuit's type, not
    // taken from the plan. A page reads the carry stage where the stage's
    // type lays it, which is right after the circuit's stages.
    let carry = <Carry<F, R, S> as Stage<F, R>>::skip_gates();
    if carry != stages.own_start() {
        return refuse("the carry stage is not laid after the circuit's stages".into());
    }
    // The circuit's body, before it writes its public output and the final
    // `ONE` constraint.
    let body = Recording::<F>::raw_of(&*paged.circuit)?;
    let (body_gates, body_constraints) = (body.num_gates, body.raw.len());
    let places = places(plan, stages, layout, body_gates)?;
    // A routine the circuit calls has its gates on one page, together,
    // and that page calls it.
    let place = |gate: usize| places.get(gate.checked_sub(stages.own_start())?).copied();
    if let Some(routine) = body.split_routine(place) {
        return refuse(format!(
            "the pages split a routine the circuit calls, at gates {routine:?}"
        ));
    }
    check_routines(paged)?;
    let (all_gates, original) = Recording::<F>::all_of(&*paged.circuit)?;
    let Some(output_gates) = all_gates.checked_sub(body_gates) else {
        return refuse("the circuit's output gates precede its body".into());
    };
    if original.len() <= body_constraints {
        return refuse("the circuit lacks its public output's final constraint".into());
    }
    let (original_body, original_output) = original.split_at(body_constraints);

    let mut found_body = Vec::new();
    let mut found_output = Vec::new();
    for page in 0..plan.pages() {
        let (gates, constraints) = if page + 1 == plan.pages() {
            Recording::<F>::all_of(&paged.last())?
        } else {
            Recording::<F>::all_of(&paged.page(page))?
        };
        let page_body = layout.carry.end + plan.programs[page].gates();
        let expected_gates = page_body
            + if page + 1 == plan.pages() {
                output_gates
            } else {
                0
            };
        if gates != expected_gates {
            return refuse(format!(
                "page {page} allocates other output gates than the circuit"
            ));
        }
        let body_len = plan.programs[page].constraints();
        if constraints.len() <= body_len
            || (page + 1 != plan.pages() && constraints.len() != body_len + 2)
        {
            return refuse(format!("page {page} has an inconsistent constraint layout"));
        }
        let (body, output) = constraints.split_at(body_len);
        for terms in body {
            found_body.push(Form::from_page(terms, |wire| {
                page_symbol(plan, layout, page, wire, body_gates, page_body)
            })?);
        }
        let output: Vec<_> = output
            .iter()
            .map(|terms| {
                Form::from_page(terms, |wire| {
                    page_symbol(plan, layout, page, wire, body_gates, page_body)
                })
            })
            .collect::<Result<_>>()?;
        if page + 1 == plan.pages() {
            found_output = output;
        } else if output[0].key() != Form::<F>::default().key()
            || output[1].key() != Form::<F>::one().key()
        {
            // A page before the last writes a zero and nothing else: its
            // output is the zero suffix and the final `ONE`.
            return refuse(format!(
                "page {page} writes another output than a zero and its final ONE"
            ));
        }
    }

    let mut slots = BTreeMap::new();
    let mut required = BTreeMap::<Key, usize>::new();
    for (index, combination) in plan.slots.iter().enumerate() {
        let symbol = Symbol::Slot(index);
        let source = Form::from_original(combination);
        let mut definition = source.clone();
        definition.add(symbol, -F::ONE);
        *required.entry(definition.definition_key()).or_insert(0) += 1;
        slots.insert(symbol, source);
    }

    let mut remaining = Vec::new();
    for form in found_body {
        let key = form.definition_key();
        if let Some(left) = required.get_mut(&key)
            && *left > 0
        {
            *left -= 1;
            continue;
        }
        remaining.push(form);
    }
    if required.values().any(|&left| left != 0) {
        return refuse("a carry slot lacks its defining constraint".into());
    }

    // Body constraints may move between pages. Each extra page's ONE was
    // checked above; the last page's output-write constraints, public
    // bindings and ONE must retain their original order.
    let expected: Vec<_> = original_body
        .iter()
        .map(|terms| Form::from_original(terms))
        .collect();
    let actual: Vec<_> = remaining
        .iter()
        .map(|form| form.substitute(&slots))
        .collect();
    let (expected_len, actual_len) = (expected.len(), actual.len());
    if multiset(expected) != multiset(actual) {
        return refuse(format!(
            "the pages' {actual_len} constraints are not the circuit's {expected_len} after \
             defining the carry slots"
        ));
    }
    let expected_output: Vec<_> = original_output
        .iter()
        .map(|terms| Form::from_original(terms).key())
        .collect();
    let actual_output: Vec<_> = found_output
        .iter()
        .map(|form| form.substitute(&slots).key())
        .collect();
    if actual_output != expected_output {
        return refuse("the pages change the public output's constraints or their order".into());
    }
    // The public output's constraints end with one for each wire the
    // circuit writes, in order, and the final `ONE`: the last wire's names
    // no wire where the circuit writes a constant zero there.
    Ok(original_output
        .len()
        .checked_sub(2)
        .is_some_and(|last| Form::from_original(&original_output[last]).0.is_empty()))
}
