//! Circuit constraint analysis and metrics collection.
//!
//! This module provides constraint system analysis by simulating circuit
//! execution without computing actual values, counting the number of
//! multiplication and linear constraints a circuit requires. It also captures
//! a synthesis trace for efficient polynomial evaluation.

use alloc::vec::Vec;
use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::GadgetKind,
    maybe::Empty,
    routines::Routine,
};
use ragu_primitives::GadgetExt;

use crate::s::DriverExt;

use super::Circuit;

/// Constraint counts and synthesis trace for a circuit.
pub struct CircuitMetrics {
    /// The number of linear constraints, including those for public inputs.
    pub num_linear_constraints: usize,

    /// The number of multiplication constraints, including those used for allocations.
    pub num_multiplication_constraints: usize,
}

/// The ONE wire index in the trace.
const ONE_WIRE: usize = 2;

/// A `coefficient * wire` term.
#[derive(Clone, Debug)]
pub(crate) struct TraceTerm<F> {
    pub coeff: F,
    pub wire: usize,
}

/// A linear combination of [`TraceTerm`]s.
pub(crate) type TraceLC<F> = Vec<TraceTerm<F>>;

/// Recorded circuit structure for polynomial evaluation replay.
#[derive(Clone, Debug, Default)]
pub(crate) struct SynthesisTrace<F: Field> {
    /// (a, b, c) wire IDs for each multiplication gate.
    pub mul_wire_ids: Vec<(usize, usize, usize)>,
    /// Add wire definitions: (wire_id, linear_combination).
    pub add_wires: Vec<(usize, TraceLC<F>)>,
    /// Linear constraints.
    pub constraints: Vec<TraceLC<F>>,
}

/// Builder for [`TraceLC`].
struct TraceLCBuilder<F: Field> {
    terms: Vec<TraceTerm<F>>,
    current_gain: Coeff<F>,
}

impl<F: Field> Default for TraceLCBuilder<F> {
    fn default() -> Self {
        Self {
            terms: Vec::new(),
            current_gain: Coeff::One,
        }
    }
}

impl<F: Field> TraceLCBuilder<F> {
    fn build(f: impl Fn(Self) -> Self) -> TraceLC<F> {
        f(Self::default()).terms
    }
}

impl<F: Field> LinearExpression<usize, F> for TraceLCBuilder<F> {
    fn add_term(mut self, wire: &usize, coeff: Coeff<F>) -> Self {
        let effective_coeff = (coeff * self.current_gain).value();
        self.terms.push(TraceTerm {
            coeff: effective_coeff,
            wire: *wire,
        });
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.current_gain = self.current_gain * coeff;
        self
    }
}

#[derive(Default)]
struct Counter<F: Field> {
    next_wire_id: usize,
    mul_wire_ids: Vec<(usize, usize, usize)>,
    add_wires: Vec<(usize, TraceLC<F>)>,
    constraints: Vec<TraceLC<F>>,
    available_b: Option<usize>,
}

impl<F: Field> Counter<F> {
    fn alloc_wire(&mut self) -> usize {
        let id = self.next_wire_id;
        self.next_wire_id += 1;
        id
    }
}

impl<F: Field> DriverTypes for Counter<F> {
    type MaybeKind = Empty;
    type ImplField = F;
    type ImplWire = usize;
    type LCadd = TraceLCBuilder<F>;
    type LCenforce = TraceLCBuilder<F>;
}

impl<'dr, F: Field> Driver<'dr> for Counter<F> {
    type F = F;
    type Wire = usize;
    const ONE: Self::Wire = ONE_WIRE;

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        if let Some(wire) = self.available_b.take() {
            return Ok(wire);
        }
        let (a, b, _) = self.mul(|| unreachable!())?;
        self.available_b = Some(b);
        Ok(a)
    }

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let a_id = self.alloc_wire();
        let b_id = self.alloc_wire();
        let c_id = self.alloc_wire();
        self.mul_wire_ids.push((a_id, b_id, c_id));
        Ok((a_id, b_id, c_id))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let id = self.alloc_wire();
        self.add_wires.push((id, TraceLCBuilder::build(lc)));
        id
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        self.constraints.push(TraceLCBuilder::build(lc));
        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: <Ro::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<Ro::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
        let tmp = self.available_b.take();
        let mut dummy = Emulator::wireless();
        let dummy_input = Ro::Input::map_gadget(&input, &mut dummy)?;
        let aux = routine.predict(&mut dummy, &dummy_input)?.into_aux();
        let result = routine.execute(self, input, aux)?;
        self.available_b = tmp;
        Ok(result)
    }
}

/// Evaluates circuit metrics and captures synthesis trace in one pass.
pub fn eval<F: Field, C: Circuit<F>>(circuit: &C) -> Result<(CircuitMetrics, SynthesisTrace<F>)> {
    let mut counter = Counter::default();

    // Allocate key and ONE wires; key constraint is inlined at eval time.
    let (_key_wire, _, _one) = counter.mul(|| unreachable!())?;

    let mut outputs = Vec::new();
    let (io, _) = circuit.witness(&mut counter, Empty)?;
    io.write(&mut counter, &mut outputs)?;

    // Enforcing public inputs
    counter.enforce_public_outputs(outputs.iter().map(|output| output.wire()))?;
    counter.enforce_one()?;

    let trace = SynthesisTrace {
        mul_wire_ids: counter.mul_wire_ids,
        add_wires: counter.add_wires,
        constraints: counter.constraints,
    };

    let metrics = CircuitMetrics {
        num_multiplication_constraints: trace.mul_wire_ids.len(),
        num_linear_constraints: trace.constraints.len() + 1,
    };

    Ok((metrics, trace))
}
