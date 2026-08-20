//! # `ragu_circuits`
//!
//! This crate contains traits and utilities for reducing arithmetic-circuit
//! constraints to polynomials for the Ragu project. This API is re-exported
//! as necessary in other crates and so this crate is only intended to be used
//! internally by Ragu.

#![no_std]
#![forbid(unsafe_code)]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

#[cfg(not(feature = "alloc"))]
compile_error!("`ragu_circuits` requires the `alloc` feature to be enabled.");
extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod analytic;
pub mod floor_planner;
pub mod horner;
mod ky;
mod metrics;
pub mod polynomials;
mod raw;
pub mod registry;
pub mod staging;
/// Test-only circuit analysis utilities.
#[cfg(feature = "test-utils")]
pub mod testing;
mod trace;
mod trivial;
mod wiring;

pub use metrics::{BaseFingerprint, DeepFingerprint, RoutineIdentity, SegmentRecord};
pub use trace::Trace;

#[cfg(test)]
mod tests;

use alloc::boxed::Box;

use polynomials::{Rank, sparse};
use ragu_arithmetic::ff::{Field, FromUniformBytes};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
};
use ragu_primitives::io::Write;

/// Bundles a primary value with auxiliary data.
///
/// Returned by [`Circuit::witness`] and [`CircuitExt::trace`] to pair the
/// circuit's output with any auxiliary data produced during witness generation.
/// Most circuits set `Aux = ()` and callers can use [`into_output`] to
/// discard the auxiliary component, [`into_aux`] to discard the output,
/// or [`into_parts`] to destructure both.
///
/// [`into_output`]: WithAux::into_output
/// [`into_aux`]: WithAux::into_aux
/// [`into_parts`]: WithAux::into_parts
pub struct WithAux<O, A> {
    /// The primary output value.
    pub(crate) output: O,
    /// Auxiliary data produced alongside the output.
    pub(crate) aux: A,
}

impl<O, A> WithAux<O, A> {
    /// Creates a new `WithAux` from an output and auxiliary data.
    pub fn new(output: O, aux: A) -> Self {
        Self { output, aux }
    }

    /// Discards auxiliary data, returning only the output.
    pub fn into_output(self) -> O {
        self.output
    }

    /// Discards the output, returning only auxiliary data.
    pub fn into_aux(self) -> A {
        self.aux
    }

    /// Destructures into both components.
    pub fn into_parts(self) -> (O, A) {
        (self.output, self.aux)
    }
}

/// A trait for drivers that carry per-routine state which must be saved and
/// restored across routine boundaries.
///
/// Provides [`with_scope`](Self::with_scope), which saves
/// [`scope`](Self::scope), replaces it with a caller-provided value, runs a
/// closure with `&mut self`, then restores the original value. This isolates
/// driver state within routines.
pub(crate) trait DriverScope<S> {
    /// Returns a mutable reference to the scoped state.
    fn scope(&mut self) -> &mut S;

    /// Runs `f` with [`scope`](Self::scope) temporarily replaced by `init`, then
    /// restores the original value.
    fn with_scope<R>(&mut self, init: S, f: impl FnOnce(&mut Self) -> R) -> R {
        let saved = core::mem::replace(self.scope(), init);
        let result = f(self);
        *self.scope() = saved;
        result
    }
}

/// Core trait for arithmetic circuits.
///
/// Implementations must emit constraints deterministically from ordinary input
/// such as type parameters, constants, and iterator lengths. Values carried
/// through [`DriverValue`] may determine witness generation and auxiliary data,
/// but not which constraints are emitted.
pub trait Circuit<F: Field>: Sized + Send + Sync {
    /// The type of data that is needed to construct the expected output of this
    /// circuit.
    type Instance<'source>: Send;

    /// The type of data that is needed to compute a satisfying witness for this
    /// circuit.
    type Witness<'source>: Send;

    /// The circuit's public instance, serialized into the $k(Y)$ instance
    /// polynomial that the verifier checks.
    type Output: Write<F>;

    /// Auxiliary data produced during the computation of the
    /// [`witness`](Circuit::witness) method that may be useful, such as
    /// interstitial witness data needed by later computations.
    type Aux<'source>: Send;

    /// Given public instance data for this circuit, uses the provided
    /// [`Driver`] to return the verifier-visible `Self::Output` gadget.
    ///
    /// This method describes the public output that a corresponding
    /// [`witness`](Circuit::witness) call must produce, without requiring
    /// the private witness input itself.
    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr;

    /// Given witness input for this circuit, emits constraints using the
    /// provided [`Driver`] and returns the verifier-visible `Self::Output`
    /// gadget plus auxiliary witness data.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr;

    /// Supplies a closed form for this circuit's wiring polynomial, replacing
    /// synthesis when evaluating $s(X, Y)$.
    ///
    /// Returning `None` — the default — leaves Ragu synthesizing the circuit,
    /// which is always correct. Override this only when the circuit's
    /// constraints are regular enough to evaluate directly, and read
    /// [`AnalyticWiring`](analytic::AnalyticWiring)'s correctness obligations
    /// first: a closed form that disagrees with the circuit yields a wiring
    /// polynomial that does not describe it.
    fn analytic_wiring<R: polynomials::Rank>(
        &self,
    ) -> Option<Box<dyn analytic::AnalyticWiring<F, R>>> {
        None
    }
}

/// Extension trait blanket-implemented for all [`Circuit<F>`](Circuit) types.
pub trait CircuitExt<F: Field>: Circuit<F> {
    /// Computes the trace for this circuit from a witness.
    ///
    /// The returned [`Trace`] can be assembled into a polynomial
    /// via [`Registry::assemble`](registry::Registry::assemble).
    ///
    /// # Errors
    ///
    /// Propagates any error from evaluating the circuit trace.
    fn trace<'witness>(
        &self,
        witness: Self::Witness<'witness>,
    ) -> Result<WithAux<trace::Trace<F>, Self::Aux<'witness>>> {
        trace::eval(self, witness)
    }

    /// Evaluates the instance polynomial $k(y)$ for the given instance at
    /// a point $y \in \mathbb{F}$.
    ///
    /// # Errors
    ///
    /// Propagates any error from evaluating the instance polynomial.
    fn ky(&self, instance: Self::Instance<'_>, y: F) -> Result<F> {
        ky::eval(self, instance, y)
    }
}

impl<F: Field, C: Circuit<F>> CircuitExt<F> for C {}

/// A trait for (partially) evaluating $s(X, Y)$ for some circuit.
///
/// Constructed internally from a [`Circuit`] implementation.
///
/// The registry key constraint is **not** part of these evaluations; it is
/// injected at the [`Registry`] level at the fixed $Y^{4n-1}$ position.
///
/// [`Registry`]: registry::Registry
pub(crate) trait WiringObject<F: Field, R: Rank>: Send + Sync {
    /// Evaluates the polynomial $s(x, y)$ for some $x, y \in \mathbb{F}$.
    fn sxy(&self, x: F, y: F, floor_plan: &[floor_planner::ConstraintSegment]) -> F;

    /// Computes the polynomial restriction $s(x, Y)$ for some $x \in \mathbb{F}$.
    fn sx(&self, x: F, floor_plan: &[floor_planner::ConstraintSegment])
    -> sparse::Polynomial<F, R>;

    /// Computes the polynomial restriction $s(X, y)$ for some $y \in \mathbb{F}$.
    fn sy(&self, y: F, floor_plan: &[floor_planner::ConstraintSegment])
    -> sparse::Polynomial<F, R>;

    /// Returns per-segment constraint records in DFS emission order.
    ///
    /// These records serve as input to [`floor_planner::floor_plan`] for
    /// computing absolute constraint offsets.
    fn segment_records(&self) -> &[SegmentRecord];

    /// Returns `true` if this circuit is a masking polynomial whose
    /// `sxy`/`sx`/`sy` return only the $-\text{notch}$ term, expecting
    /// the [`Registry`] to add the shared $S\_{\text{global}}$ once.
    ///
    /// [`Registry`]: registry::Registry
    fn is_mask(&self) -> bool {
        false
    }
}

/// Wraps a circuit into a boxed [`WiringObject`] that can evaluate the
/// $s(X, Y)$ polynomial.
pub(crate) fn into_wiring_object<'a, F, C, R>(
    circuit: C,
) -> Result<Box<dyn WiringObject<F, R> + 'a>>
where
    F: FromUniformBytes<64>,
    C: Circuit<F> + 'a,
    R: Rank,
{
    let metrics = metrics::eval(&circuit)?;

    // Reserve the last coefficient slot (Y^{4n-1}) for the registry key
    // constraint, which is injected at the registry level.
    if metrics.num_constraints >= R::num_coeffs() {
        return Err(Error::ConstraintBoundExceeded {
            limit: R::num_coeffs() - 1,
        });
    }

    if metrics.num_gates > R::n() {
        return Err(Error::GateBoundExceeded { limit: R::n() });
    }

    // Taken before the circuit is consumed below. Ragu keeps the synthesized
    // object either way: the bounds above, the segment records, and the floor
    // plan derived from them stay Ragu's, and debug builds cross-check the
    // closed form against it.
    let analytic = circuit.analytic_wiring::<R>();
    let reference = into_raw_wiring_object(raw::CircuitAdapter(circuit), metrics)?;

    Ok(match analytic {
        Some(analytic) => Box::new(analytic::Analytic::new(analytic, reference)),
        None => reference,
    })
}

/// Like [`into_wiring_object`] but accepts a [`RawCircuit`](raw::RawCircuit)
/// directly. Metrics must have been pre-computed and validated by the caller.
pub(crate) fn into_raw_wiring_object<'a, F, RC, R>(
    circuit: RC,
    metrics: metrics::CircuitMetrics,
) -> Result<Box<dyn WiringObject<F, R> + 'a>>
where
    F: Field,
    RC: raw::RawCircuit<F> + 'a,
    R: Rank,
{
    struct Processed<RC> {
        circuit: RC,
        metrics: metrics::CircuitMetrics,
    }

    impl<F: Field, RC: raw::RawCircuit<F>, R: Rank> WiringObject<F, R> for Processed<RC> {
        fn sxy(&self, x: F, y: F, floor_plan: &[floor_planner::ConstraintSegment]) -> F {
            wiring::sxy::eval::<_, _, R>(&self.circuit, x, y, floor_plan)
                .expect("should succeed if metrics succeeded")
        }
        fn sx(
            &self,
            x: F,
            floor_plan: &[floor_planner::ConstraintSegment],
        ) -> sparse::Polynomial<F, R> {
            wiring::sx::eval(&self.circuit, x, floor_plan)
                .expect("should succeed if metrics succeeded")
        }
        fn sy(
            &self,
            y: F,
            floor_plan: &[floor_planner::ConstraintSegment],
        ) -> sparse::Polynomial<F, R> {
            wiring::sy::eval(&self.circuit, y, floor_plan)
                .expect("should succeed if metrics succeeded")
        }
        fn segment_records(&self) -> &[SegmentRecord] {
            &self.metrics.segments
        }
    }

    Ok(Box::new(Processed { circuit, metrics }))
}

/// An evaluable bonding object $s(X, Y)$ used to enforce well-formedness of a
/// staged trace.
///
/// Bonding polynomials are wiring polynomials of a circuit that has only
/// constraints (no gates) and is satisfied by an empty instance vector. This
/// gives bonding polynomials three properties that circuit wiring polynomials
/// lack:
///
/// 1. **No dilation term.** Because the underlying circuit has no gates there
///    is no $t(z)$, and the revdot identity simplifies to
///    $\langle\kern-0.5em\langle \kern0.1em \mathbf{r}, \mathbf{s} \kern0.1em
///    \rangle\kern-0.5em\rangle = 0$.
/// 2. **Batchable.** Without gates the revdot identity is linear in the trace,
///    so multiple traces can be folded with a random challenge and verified in
///    a single claim.
/// 3. **$k(Y) \equiv 0$.** Achieved by `Output = ()` and stripping the `ONE`
///    constraint to give $s(X, 0) = 0$. A circuit wiring polynomial instead has
///    $s(X, 0) = 1$, because the verifier sets $\mathbf{k}_0 = 1$ in any
///    circuit wiring claim regardless of public inputs. This distinction can be
///    used to prevent substitution attacks (a bonding polynomial used where a
///    circuit wiring polynomial is expected) when the verifier does not have a
///    fixed choice of the wiring polynomial.
///
/// Constructed via [`StageExt::mask`] and [`StageExt::final_mask`]; the
/// underlying implementation is private to this crate.
///
/// [`StageExt::mask`]: crate::staging::StageExt::mask
/// [`StageExt::final_mask`]: crate::staging::StageExt::final_mask
pub struct BondingObject<'a, F: Field, R: Rank> {
    inner: Box<dyn WiringObject<F, R> + 'a>,
}

impl<'a, F: Field, R: Rank> BondingObject<'a, F, R> {
    pub(crate) fn new(inner: Box<dyn WiringObject<F, R> + 'a>) -> Self {
        Self { inner }
    }

    pub(crate) fn into_inner(self) -> Box<dyn WiringObject<F, R> + 'a> {
        self.inner
    }
}
