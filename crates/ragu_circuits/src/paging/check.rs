//! Structural check of a page plan against the circuit it splits.

use alloc::{
    collections::{BTreeMap, btree_map::Entry},
    format, vec,
    vec::Vec,
};
use core::ops::Range;

use ragu_core::{Error, Result};
use udon::field::Field;

use super::{Paged, Plan, record::Recording, refuse};
use crate::Circuit;

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

/// Checks that every original gate has exactly one place, that the page
/// programs allocate the layout's gates, and that the stages, a page's own
/// gates and the carry stage occupy disjoint gates. The symbolic comparison below relies on this map.
fn layout<F: Field>(plan: &Plan<F>, body_gates: usize) -> Result<()> {
    let (stages, layout) = (&plan.stages, &plan.layout);
    stages.check()?;
    let pages = stages.num_pages();
    let Some(own) = body_gates.checked_sub(stages.own_start()) else {
        return refuse("the circuit has fewer gates than its stages".into());
    };
    if layout.own_start != stages.own_start()
        || plan.num_gates != body_gates
        || layout.starts.len() != pages
        || plan.held.len() != pages
        || plan.programs.len() != pages
        || plan.places.len() != own
    {
        return refuse("the pages' layout does not cover the circuit".into());
    }
    let carry = &layout.carry;
    if carry.start > carry.end {
        return refuse("the carry stage has an inverted gate range".into());
    }

    let mut seen = vec![false; own];
    let mut next = stages.own_start();
    for page in 0..pages {
        let held = &plan.held[page];
        let first = stages.own_start();
        let Some(own_end) = first.checked_add(held.len()) else {
            return refuse("a page's gate range overflows".into());
        };
        if layout.starts[page] != next {
            return refuse(format!("page {page} has an inconsistent gate layout"));
        }
        next = next
            .checked_add(held.len())
            .ok_or_else(|| Error::Initialization("the pages have too many gates".into()))?;
        for (offset, &gate) in held.iter().enumerate() {
            let gate = gate as usize;
            if gate < stages.own_start() || gate >= body_gates {
                return refuse(format!("page {page} holds a gate outside the circuit"));
            }
            let index = gate - stages.own_start();
            if seen[index] || plan.places[index] != (page as u32, (first + offset) as u32) {
                return refuse(format!("page {page} duplicates or misplaces a gate"));
            }
            seen[index] = true;
        }

        if carry.start < own_end {
            return refuse(format!("page {page} overlaps the carry stage"));
        }
        let end = if carry.is_empty() {
            own_end
        } else {
            own_end.max(carry.end)
        };
        let program = &plan.programs[page];
        if program.own != (first..own_end) || program.gates.checked_add(1) != Some(end) {
            return refuse(format!("page {page} allocates other gates than its layout"));
        }
    }
    if next != body_gates || seen.iter().any(|&seen| !seen) {
        return refuse("the pages omit a gate of the circuit".into());
    }
    plan.fits()
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
fn page_symbol<F: Field>(
    plan: &Plan<F>,
    page: usize,
    wire: u32,
    body_gates: usize,
) -> Result<Symbol> {
    let (gate, kind) = ((wire / 4) as usize, wire % 4);
    if gate == 0 {
        return Ok(Symbol::One);
    }
    let page_body = plan.programs[page].gates + 1;
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

    if let Some(symbol) = carry_symbol(page, gate, kind, &plan.layout.carry) {
        return Ok(symbol);
    }
    // A stage's gate is the circuit's, at the same place.
    if gate < plan.layout.own_start {
        return Symbol::wire(gate, kind);
    }
    if let Some(offset) = gate.checked_sub(plan.layout.own_start)
        && let Some(&original) = plan.held[page].get(offset)
    {
        return Symbol::wire(original as usize, kind);
    }
    Ok(Symbol::Unused(page, gate, kind))
}

/// Checks the complete emitted relations, treating carry slots as
/// independent wires until their defining equations have been found.
pub(super) fn check<F: Field, C: Circuit<F>>(paged: &Paged<F, C>) -> Result<()> {
    let plan = &*paged.plan;
    // Every wire a page names in a stage is read where the plan lays the
    // stage, which is where the stage's polynomial holds it only if the
    // plan's stages are the ones the circuit was cut over.
    if plan.stages != paged.stages {
        return refuse(
            "the plan lays its pages over other stages than the circuit was cut over".into(),
        );
    }
    let (body_gates, body_constraints) = Recording::<F>::body_shape(&*paged.circuit)?;
    layout(plan, body_gates)?;
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
        let page_body = plan.programs[page].gates + 1;
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
        let body_len = plan.programs[page].constraints.len();
        if constraints.len() <= body_len
            || (page + 1 != plan.pages() && constraints.len() != body_len + 1)
        {
            return refuse(format!("page {page} has an inconsistent constraint layout"));
        }
        let (body, output) = constraints.split_at(body_len);
        for terms in body {
            found_body.push(Form::from_page(terms, |wire| {
                page_symbol(plan, page, wire, body_gates)
            })?);
        }
        let output: Vec<_> = output
            .iter()
            .map(|terms| Form::from_page(terms, |wire| page_symbol(plan, page, wire, body_gates)))
            .collect::<Result<_>>()?;
        if page + 1 == plan.pages() {
            found_output = output;
        } else if output[0].key() != Form::<F>::one().key() {
            return refuse(format!("page {page} lacks its final ONE constraint"));
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
    Ok(())
}
