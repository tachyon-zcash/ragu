//! Recording a circuit: one walk of it on a driver that keeps what it
//! emits, the gates it allocates, the linear combinations it makes and the
//! constraints it enforces, each over the gates' wires.
//!
//! [`Paged::check`](super::Paged::check) rests on this module: it compares
//! the recording of a circuit with the recordings of its pages, so a
//! constraint this driver did not keep is one the check does not hold the
//! pages to. The planner reads the same recording to choose its cuts, and
//! takes nothing else of the circuit.

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::ops::Range;

use ragu_core::{
    Coeff, Result,
    convert::WireMap,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::{Bound, Gadget},
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

/// What one walk of a circuit emits: as emitted, over the gates' wires and
/// the linear combinations the circuit makes of them, and with every wire
/// followed back to the gates' wires.
pub(super) struct Recording<F> {
    /// The gates the circuit allocates, the SYSTEM gate included.
    pub(super) num_gates: usize,
    /// The linear combinations [`Driver::add`] made, each over gates'
    /// wires and the combinations made before it, which a wire names by
    /// [`DERIVED`] and an index here.
    pub(super) derived: Vec<Vec<(u32, F)>>,
    /// Each constraint as emitted, with the gates allocated by then.
    pub(super) raw: Vec<(usize, Vec<(u32, F)>)>,
    /// Each wire of the public output as emitted, in traversal order.
    pub(super) raw_outputs: Vec<u32>,
    /// The gates each routine the circuit calls allocates, in the order
    /// of the calls: those of a routine called within another are among
    /// the outer one's.
    pub(super) routines: Vec<Range<usize>>,
    /// Each constraint over the gates' wires, with the gates allocated
    /// when it was emitted: empty until the recording is
    /// [expanded](Self::expanded).
    pub(super) constraints: Vec<(usize, Vec<(u32, F)>)>,
    /// Each wire of the public output over the gates' wires, likewise.
    pub(super) outputs: Vec<Vec<(u32, F)>>,
}

impl<F: Field> Recording<F> {
    /// Every constraint emitted by `circuit`, including those made while
    /// writing its public output and the final `ONE` constraint, expanded to
    /// gate wires. Unlike the planner's recording, this walk follows the
    /// complete relation that a registered circuit enforces.
    pub(super) fn all_of<C: Circuit<F>>(circuit: &C) -> Result<(usize, Vec<Vec<(u32, F)>>)> {
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
        raw::orchestrate(&mut dr, &CircuitAdapterRef(circuit), Empty)?;
        let recording = dr.recording.expanded();
        Ok((
            recording.num_gates,
            recording
                .constraints
                .into_iter()
                .map(|(_, terms)| terms)
                .collect(),
        ))
    }

    /// The gates and constraints of the circuit body, before writing its
    /// public output and the final `ONE` constraint.
    pub(super) fn body_shape<C: Circuit<F>>(circuit: &C) -> Result<(usize, usize)> {
        let recording = Self::raw_of(circuit)?;
        Ok((recording.num_gates, recording.raw.len()))
    }

    /// Walks `circuit` for what it emits, as emitted.
    pub(super) fn raw_of<C: Circuit<F>>(circuit: &C) -> Result<Self> {
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
        assert!(index < DERIVED_LIMIT, "combinations fit a wire");
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
