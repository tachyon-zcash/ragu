//! Recording a circuit: one walk of it on a driver that keeps what it
//! emits, the gates it allocates, the linear combinations it makes and the
//! constraints it enforces, each over the gates' wires.
//!
//! [`Pages::check`](super::Pages::check) rests on this module: it compares
//! the recording of a circuit with the recordings of its pages, so a
//! constraint this driver did not keep is one the check does not hold the
//! pages to, and it holds the pages to the routines this driver noted
//! ([`Recording::split_routine`]). The pager reads the same recording to
//! choose its cuts, and takes nothing else of the circuit: the routines the
//! circuit calls, each with what it emits ([`Call`]), are for the pager to
//! compile what a page runs.

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::ops::Range;

use ragu_core::{
    Coeff, Result,
    convert::WireMap,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::{Bound, Gadget, GadgetKind},
    maybe::Empty,
    routines::Routine,
};
use udon::field::Field;

use super::{DERIVED, ONE};
use crate::{
    Circuit,
    raw::{self, CircuitAdapterRef, RawCircuit},
};

/// A recording names fewer combinations than this: the two wires past them
/// are left to whoever reads it to mark with.
pub(super) const DERIVED_LIMIT: u32 = DERIVED - 2;

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

/// A routine the circuit calls, as the walk passes through it.
///
/// The walk names a routine's input wires afresh as it enters the routine,
/// and its output wires afresh as it leaves: each new name is a combination
/// of the one wire it stands for. What the routine emits then names its
/// inputs by names that are its own, and what its caller emits names the
/// routine's outputs likewise, whatever wires they are. So what a routine
/// emits is over its own gates' wires, its own combinations, its inputs,
/// the outputs of the calls it makes, and `ONE`: it names nothing else,
/// and nothing outside it names what is within.
///
/// The names are combinations ([`Recording::derived`]), in the order the
/// walk makes them: the call's inputs, then what is made within it, then
/// its outputs.
#[derive(Clone, Debug)]
pub(super) struct Call {
    /// The gates the call allocates, those of the calls within it
    /// included.
    pub(super) gates: Range<usize>,
    /// The call's name for each wire of its input, in the order the input
    /// gadget gives its wires: each a combination of the caller's wire
    /// alone.
    pub(super) inputs: Range<usize>,
    /// The combinations made within the call, the names of the calls
    /// within it included.
    pub(super) sums: Range<usize>,
    /// The caller's name for each wire of the call's output, in the order
    /// the output gadget gives its wires: each a combination of the wire
    /// within the call alone.
    pub(super) outputs: Range<usize>,
    /// The constraints emitted within the call, those of the calls within
    /// it included, by their place among the recording's.
    pub(super) constraints: Range<usize>,
    /// The calls made within the call, in order.
    pub(super) calls: Vec<Call>,
}

/// What one walk of a circuit emits: as emitted, over the gates' wires and
/// the linear combinations the circuit makes of them, and with every wire
/// followed back to the gates' wires.
pub(super) struct Recording<F> {
    /// The gates the circuit allocates, the SYSTEM gate included.
    pub(super) num_gates: usize,
    /// The linear combinations [`Driver::add`] made, and the names the
    /// walk gave the inputs and the outputs of each routine ([`Call`]),
    /// each over gates' wires and the combinations made before it, which a
    /// wire names by [`DERIVED`] and an index here.
    pub(super) derived: Vec<Vec<(u32, F)>>,
    /// How many of them [`Driver::add`] made: what a walk that only counts
    /// its calls counts.
    pub(super) adds: usize,
    /// Each constraint as emitted, with the gates allocated by then.
    pub(super) raw: Vec<(usize, Vec<(u32, F)>)>,
    /// Each wire of the public output as emitted, in traversal order.
    pub(super) raw_outputs: Vec<u32>,
    /// The routines the circuit calls, in the order of the calls, each
    /// with the calls made within it.
    pub(super) calls: Vec<Call>,
    /// Each constraint over the gates' wires, with the gates allocated
    /// when it was emitted: empty until the recording is
    /// [expanded](Self::expanded).
    pub(super) constraints: Vec<(usize, Vec<(u32, F)>)>,
    /// Each wire of the public output over the gates' wires, likewise.
    pub(super) outputs: Vec<Vec<(u32, F)>>,
}

impl<F: Field> Recording<F> {
    /// Walks `circuit` whole: every constraint it emits, those made while
    /// writing its public output and the final `ONE` constraint included,
    /// followed back to the gates' wires. Unlike the pager's recording,
    /// this walk follows the complete relation that a registered circuit
    /// enforces.
    pub(super) fn whole_of<C: Circuit<F>>(circuit: &C) -> Result<Self> {
        let mut dr = Prober::new();
        raw::orchestrate(&mut dr, &CircuitAdapterRef(circuit), Empty)?;
        Ok(dr.recording.expanded())
    }

    /// The gates each routine the circuit calls allocates, in the order
    /// of the calls. Those of a routine called within another are among
    /// the outer one's, and a routine that allocates none is not given:
    /// it has no gate to place.
    pub(super) fn routines(&self) -> impl Iterator<Item = &Range<usize>> {
        self.calls
            .iter()
            .map(|call| &call.gates)
            .filter(|gates| !gates.is_empty())
    }

    /// The first routine the circuit calls that `place` does not keep
    /// whole, by its gates. `place` gives a gate of the circuit's its page
    /// and its place there, and a routine is whole where its gates are on
    /// one page, next to one another in the order the circuit allocates
    /// them: what a page needs to call it as a routine of its own.
    ///
    /// The pager refuses a layout by this, and the check a plan.
    pub(super) fn split_routine(
        &self,
        place: impl Fn(usize) -> Option<(usize, usize)>,
    ) -> Option<Range<usize>> {
        self.routines()
            .find(|routine| {
                let mut places = (routine.start..routine.end).map(&place);
                let Some(Some((page, first))) = places.next() else {
                    return true;
                };
                !places
                    .enumerate()
                    .all(|(gate, at)| at == Some((page, first + gate + 1)))
            })
            .cloned()
    }

    /// Walks `circuit` for what it emits, as emitted.
    pub(super) fn raw_of<C: Circuit<F>>(circuit: &C) -> Result<Self> {
        let mut dr = Prober::new();
        walk(&mut dr, &CircuitAdapterRef(circuit))?;
        Ok(dr.recording)
    }

    /// Walks `circuit`, and follows every wire back to the gates' wires.
    pub(super) fn of<C: Circuit<F>>(circuit: &C) -> Result<Self> {
        Ok(Self::raw_of(circuit)?.expanded())
    }

    /// The recording with every constraint and every wire of the public
    /// output followed back to the gates' wires.
    pub(super) fn expanded(mut self) -> Self {
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
    pub(super) fn expand(&self, terms: Vec<(u32, F)>) -> Vec<(u32, F)> {
        self.expand_to(terms, &(0..0))
    }

    /// As [`expand`](Self::expand), and no further than the combinations
    /// of `kept`, which are left as the terms name them: with a call's
    /// inputs kept, what the call makes is over its own gates' wires, its
    /// inputs and `ONE`.
    pub(super) fn expand_to(&self, terms: Vec<(u32, F)>, kept: &Range<usize>) -> Vec<(u32, F)> {
        let mut sum: BTreeMap<u32, F> = BTreeMap::new();
        let mut pending: BTreeMap<u32, F> = BTreeMap::new();
        let mut take = |pending: &mut BTreeMap<u32, F>, wire: u32, coeff: F| {
            let (into, key) = if wire & DERIVED == 0 || kept.contains(&((wire ^ DERIVED) as usize))
            {
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

/// The planning driver: its wires are the gates' wires or the linear
/// combinations the circuit makes of them, each kept as made.
struct Prober<F> {
    recording: Recording<F>,
    /// For each routine the walk is within, outermost first, the calls
    /// made within it so far.
    open: Vec<Vec<Call>>,
}

impl<F: Field> Prober<F> {
    fn new() -> Self {
        Prober {
            recording: Recording {
                num_gates: 0,
                derived: Vec::new(),
                adds: 0,
                raw: Vec::new(),
                raw_outputs: Vec::new(),
                calls: Vec::new(),
                constraints: Vec::new(),
                outputs: Vec::new(),
            },
            open: Vec::new(),
        }
    }
}

/// Names each wire of a gadget afresh: a combination of that wire alone.
struct Renamer<'a, F>(&'a mut Vec<Vec<(u32, F)>>);

impl<F: Field> WireMap<F> for Renamer<'_, F> {
    type Src = Prober<F>;
    type Dst = Prober<F>;

    fn convert_wire(&mut self, wire: &u32) -> Result<u32> {
        let index = u32::try_from(self.0.len()).expect("combinations fit a wire");
        assert!(index < DERIVED_LIMIT, "combinations fit a wire");
        self.0.push(vec![(*wire, F::ONE)]);
        Ok(DERIVED | index)
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
        // Every call makes a combination, so that a walk which only
        // counts the calls names the same ones.
        let derived = &mut self.recording.derived;
        let index = u32::try_from(derived.len()).expect("combinations fit a wire");
        assert!(index < DERIVED_LIMIT, "combinations fit a wire");
        derived.push(lc(Terms::new()).terms);
        self.recording.adds += 1;
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
        // runs it, and noted for what it emits: a page holds all of its
        // gates or none. Its inputs are named afresh as the walk enters
        // it, and its outputs as the walk leaves.
        let recording = &mut self.recording;
        let gates = recording.num_gates;
        let inputs = recording.derived.len();
        let input = Ro::Input::map_gadget(&input, &mut Renamer(&mut recording.derived))?;
        let sums = recording.derived.len();
        let constraints = recording.raw.len();

        self.open.push(Vec::new());
        let output = Emulator::predict(&routine, &input)
            .and_then(|predicted| routine.execute(self, input, predicted.into_aux()));
        let calls = self.open.pop().expect("the call was opened");
        let output = output?;

        let recording = &mut self.recording;
        let outputs = recording.derived.len();
        let output = Ro::Output::map_gadget(&output, &mut Renamer(&mut recording.derived))?;
        let call = Call {
            gates: gates..recording.num_gates,
            inputs: inputs..sums,
            sums: sums..outputs,
            outputs: outputs..recording.derived.len(),
            constraints: constraints..recording.raw.len(),
            calls,
        };
        match self.open.last_mut() {
            Some(within) => within.push(call),
            None => recording.calls.push(call),
        }
        Ok(output)
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
