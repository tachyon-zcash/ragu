//! Internal circuit abstraction with access to the SYSTEM gate wires.
//!
//! External circuits implement [`Circuit`](crate::Circuit), which hides
//! the SYSTEM gate (gate 0) behind the framework. Internally, the evaluation
//! drivers ([`sx`](crate::s::sx), [`sy`](crate::s::sy),
//! [`sxy`](crate::s::sxy), [`metrics`](crate::metrics),
//! [`trace`](crate::trace)) need to allocate the SYSTEM gate and then run
//! the circuit body. This module provides:
//!
//! - [`GateWires`]: a named wrapper for the four wires of a gate allocation.
//! - [`RawCircuit`]: like [`Circuit`](crate::Circuit) but receives the
//!   SYSTEM gate wires, allowing implementations to reference them.
//! - [`CircuitAdapter`]: wraps any `Circuit` into a `RawCircuit` by ignoring
//!   the SYSTEM gate wires.
//! - [`orchestrate`]: the shared synthesis sequence that every driver executes.
//!
//! # Orchestration
//!
//! Every driver performs the same sequence around the circuit body:
//!
//! 1. **SYSTEM gate** — Allocate the SYSTEM gate (gate 0). Its $b$ wire
//!    carries the constant $1$ (the `Driver::ONE` wire) and its $d$ wire
//!    carries the blinding factor $\alpha$. The $a$ and $c$ wires are zero.
//! 2. **Witness** — Run the circuit's [`witness`](RawCircuit::witness) method,
//!    passing the SYSTEM gate wires so that internal implementations (e.g.
//!    [`StageMask`](crate::staging::mask::StageMask)) can reference them.
//! 3. **Public outputs** — Write the output gadget to collect
//!    [`Element`](ragu_primitives::Element) wires, then enforce each against
//!    the corresponding coefficient of the instance polynomial $k(Y)$.
//! 4. **ONE constraint** — Enforce that `Driver::ONE` equals the constant
//!    term of $k(Y)$. This is the final constraint emitted by synthesis and
//!    occupies the $Y^0$ position.

use ff::Field;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::Bound,
};
use ragu_primitives::{GadgetExt as _, io::Write};

use alloc::vec::Vec;

use crate::WithAux;

/// The four wires of a single gate allocation.
///
/// Wraps the `(a, b, c, d)` tuple returned by
/// [`DriverTypes::gate`](ragu_core::drivers::DriverTypes::gate) with named
/// fields for readability.
#[allow(dead_code)] // TODO: this is only used by tests...
pub(crate) struct GateWires<W> {
    /// The $a$ wire (left input).
    pub a: W,
    /// The $b$ wire (right input).
    pub b: W,
    /// The $c$ wire (output, constrained by $a \cdot b = c$).
    pub c: W,
    /// The $d$ wire (auxiliary, constrained by $c \cdot d = 0$).
    pub d: W,
}

impl<W> From<(W, W, W, W)> for GateWires<W> {
    fn from((a, b, c, d): (W, W, W, W)) -> Self {
        Self { a, b, c, d }
    }
}

/// Internal circuit trait that receives the SYSTEM gate wires.
///
/// Unlike [`Circuit`](crate::Circuit), which is the public API for circuit
/// authors, `RawCircuit` is used internally by the evaluation drivers.
/// It receives the four SYSTEM gate (gate 0) wires so that implementations
/// can directly reference them in constraints — something the public
/// `Circuit` API deliberately hides.
pub(crate) trait RawCircuit<F: Field>: Sized + Send + Sync {
    /// The type of data that is needed to compute a satisfying witness.
    type Witness<'source>: Send;

    /// The circuit's public output, serialized into the $k(Y)$ instance
    /// polynomial.
    type Output: Write<F>;

    /// Auxiliary data produced during witness computation.
    type Aux<'source>: Send;

    /// Synthesize the circuit body with access to the SYSTEM gate wires.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        system_gate: GateWires<D::Wire>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr;
}

/// Adapts a [`Circuit`](crate::Circuit) into a [`RawCircuit`] by discarding
/// the SYSTEM gate wires.
///
/// Owns the circuit. Used by [`into_circuit_object`](crate::into_circuit_object)
/// to store the circuit inside a [`CircuitObject`](crate::CircuitObject).
pub(crate) struct CircuitAdapter<C>(pub C);

impl<F: Field, C: crate::Circuit<F>> RawCircuit<F> for CircuitAdapter<C> {
    type Witness<'source> = C::Witness<'source>;
    type Output = C::Output;
    type Aux<'source> = C::Aux<'source>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        _system_gate: GateWires<D::Wire>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        self.0.witness(dr, witness)
    }
}

/// Borrows a [`Circuit`](crate::Circuit) and adapts it into a [`RawCircuit`]
/// by discarding the SYSTEM gate wires.
///
/// Used by [`metrics::eval`](crate::metrics::eval) where the circuit is
/// borrowed.
pub(crate) struct CircuitAdapterRef<'a, C: ?Sized>(pub &'a C);

impl<F: Field, C: crate::Circuit<F>> RawCircuit<F> for CircuitAdapterRef<'_, C> {
    type Witness<'source> = C::Witness<'source>;
    type Output = C::Output;
    type Aux<'source> = C::Aux<'source>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        _system_gate: GateWires<D::Wire>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        self.0.witness(dr, witness)
    }
}

/// Runs the shared synthesis sequence that every driver executes around the
/// circuit body.
///
/// This function allocates the SYSTEM gate (gate 0), runs the circuit's
/// witness method (passing the SYSTEM gate wires), writes public outputs,
/// enforces them against the $k(Y)$ instance polynomial, and enforces the
/// ONE constraint.
///
/// # SYSTEM gate
///
/// The SYSTEM gate is allocated with zero-valued coefficients. For drivers with
/// `MaybeKind = Empty` (polynomial evaluators, metrics), the gate closure is
/// never called. For the trace driver (`MaybeKind = Always`), the zeros serve
/// as placeholders that [`Trace::assemble`](crate::Trace::assemble) later
/// overwrites with $b_0 = 1$ and $d_0 = \alpha$.
///
/// # Public output enforcement
///
/// After writing the output gadget, each output wire is constrained against the
/// corresponding coefficient of $k(Y)$ via `enforce_zero`. This binds the
/// circuit's computed outputs to the public instance polynomial.
///
/// # ONE constraint
///
/// The final constraint enforces `Driver::ONE` (the $b$ wire of the SYSTEM gate, which
/// evaluates to $x^{2n}$) against the constant term of $k(Y)$. This ensures
/// that $k(0) = 1$ for well-formed circuits. The result of [`orchestrate`]: the
/// degree of $k(Y)$.
pub(crate) struct Orchestrated {
    /// The number of public output elements (degree of $k(Y)$).
    pub degree_ky: usize,
}

/// Runs the circuit witness, writes public outputs, and enforces the ONE
/// constraint. See [`Orchestrated`] for details on each step.
pub(crate) fn orchestrate<'dr, 'source: 'dr, F, D, RC>(
    dr: &mut D,
    raw_circuit: &RC,
    witness: DriverValue<D, RC::Witness<'source>>,
) -> Result<Orchestrated>
where
    F: Field,
    D: Driver<'dr, F = F>,
    RC: RawCircuit<F> + 'dr,
{
    // 1. Allocate the SYSTEM gate (gate 0).
    let system_gate =
        GateWires::from(dr.gate(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero, Coeff::Zero)))?);

    // 2. Run the circuit body with the SYSTEM gate wires.
    let output = raw_circuit.witness(dr, system_gate, witness)?.into_output();

    // 3. Write outputs and enforce public bindings.
    let mut outputs: Vec<ragu_primitives::Element<'dr, D>> = Vec::new();
    output.write(dr, &mut outputs)?;

    let degree_ky = outputs.len();
    for output in &outputs {
        dr.enforce_zero(|lc| lc.add(output.wire()))?;
    }

    // 4. ONE constraint: enforce that Driver::ONE equals the constant
    //    term of k(Y).
    dr.enforce_zero(|lc| lc.add(&D::ONE))?;

    Ok(Orchestrated { degree_ky })
}
