//! Internal circuit abstraction shared by all evaluation drivers.
//!
//! External circuits implement [`Circuit`](crate::Circuit), which hides
//! the SYSTEM gate (gate 0) behind the framework. Internally, the evaluation
//! drivers ([`sx`](crate::wiring::sx), [`sy`](crate::wiring::sy),
//! [`sxy`](crate::wiring::sxy), [`metrics`](crate::metrics)) need to
//! allocate the SYSTEM gate and then run the circuit body. This module
//! provides:
//!
//! - [`RawCircuit`]: like [`Circuit`](crate::Circuit) but called from inside
//!   [`orchestrate`], after the SYSTEM gate has already been allocated.
//! - [`CircuitAdapter`]: wraps any `Circuit` into a `RawCircuit`.
//! - [`orchestrate`]: the shared synthesis sequence that every driver executes.
//!
//! # Orchestration
//!
//! Every driver performs the same sequence around the circuit body:
//!
//! 1. **SYSTEM gate** — Allocate gate 0 with zero placeholder values. The
//!    actual SYSTEM-gate wire values ($d_0 = 1$ as the [`Driver::ONE`] wire,
//!    $a_0 = \alpha$ as the blinding factor) are filled in later by
//!    [`Trace::assemble`](crate::Trace::assemble); evaluator drivers don't
//!    need them filled to compute their results.
//! 2. **Witness** — Run the circuit's [`witness`](RawCircuit::witness) method.
//! 3. **Public outputs** — Write the output gadget to collect
//!    [`Element`](ragu_primitives::Element) wires, then enforce each against
//!    the corresponding coefficient of the instance polynomial $k(Y)$.
//! 4. **ONE constraint** — Enforce that [`Driver::ONE`] equals the constant
//!    term of $k(Y)$. This is the final constraint emitted by synthesis and
//!    occupies the $Y^0$ position.
//!
//! [`Driver::ONE`]: ragu_core::drivers::Driver::ONE

use alloc::vec::Vec;

use ragu_arithmetic::{Coeff, ff::Field};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::Bound,
};
use ragu_primitives::{GadgetExt as _, io::Write};

use crate::WithAux;

/// Internal circuit trait used by the shared [`orchestrate`] flow.
///
/// Unlike [`Circuit`](crate::Circuit), which is the public API for circuit
/// authors, `RawCircuit` is an internal seam between [`orchestrate`] and the
/// circuit body. It exists to let test-only synthesis logic (e.g.
/// [`StageMask`](crate::staging::mask::StageMask)) share the same SYSTEM-gate
/// allocation and ONE-constraint enforcement steps as production circuits.
pub(crate) trait RawCircuit<F: Field>: Sized + Send + Sync {
    /// The type of data that is needed to compute a satisfying witness.
    type Witness<'source>: Send;

    /// The circuit's public output, serialized into the $k(Y)$ instance
    /// polynomial.
    type Output: Write<F>;

    /// Auxiliary data produced during witness computation.
    type Aux<'source>: Send;

    /// Synthesize the circuit body.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr;
}

/// Adapts a [`Circuit`](crate::Circuit) into a [`RawCircuit`].
///
/// Owns the circuit. Used by [`into_wiring_object`](crate::into_wiring_object)
/// to store the circuit inside a [`WiringObject`](crate::WiringObject).
pub(crate) struct CircuitAdapter<C>(pub C);

impl<F: Field, C: crate::Circuit<F>> RawCircuit<F> for CircuitAdapter<C> {
    type Witness<'source> = C::Witness<'source>;
    type Output = C::Output;
    type Aux<'source> = C::Aux<'source>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        self.0.witness(dr, witness)
    }
}

/// Borrows a [`Circuit`](crate::Circuit) and adapts it into a [`RawCircuit`].
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
/// witness method, writes public outputs, enforces them against the $k(Y)$
/// instance polynomial, and enforces the ONE constraint.
///
/// # SYSTEM gate
///
/// Gate 0 is allocated with zero-valued coefficients so that the driver's
/// internal counters and view buffers stay aligned with the canonical layout
/// (e.g. the trace driver populates `view.d[0]` as a placeholder that
/// [`Trace::assemble`](crate::Trace::assemble) later overwrites with $d_0 =
/// 1$ and $a_0 = \alpha$). For evaluator drivers (`MaybeKind = Empty`), the
/// gate closure is never called and the placeholder values are inert.
///
/// # Public output enforcement
///
/// After writing the output gadget, each output wire is constrained against the
/// corresponding coefficient of $k(Y)$ via `enforce_zero`. This binds the
/// circuit's computed outputs to the public instance polynomial.
///
/// # ONE constraint
///
/// The final constraint enforces [`Driver::ONE`] (the $d$ wire of the SYSTEM
/// gate, which evaluates to $1$) against the constant term of $k(Y)$. This
/// ensures that $k(0) = 1$ for well-formed circuits. The result of
/// [`orchestrate`]: the degree of $k(Y)$.
///
/// [`Driver::ONE`]: ragu_core::drivers::Driver::ONE
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
    // 1. Allocate the SYSTEM gate (gate 0). The wires are discarded —
    //    `Driver::ONE` references gate 0's d-wire by convention, and circuit
    //    bodies never need direct handles to the other SYSTEM-gate wires.
    let (_, _, _, extra) = dr.gate(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
    let _ = dr.assign_extra(extra, || Ok(Coeff::Zero))?;

    // 2. Run the circuit body.
    let output = raw_circuit.witness(dr, witness)?.into_output();

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
