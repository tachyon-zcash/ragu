//! Framework-side state surfaced to [`Step::witness`](crate::step::Step::witness) impls.
//!
//! [`FrameworkHooks`] bundles the framework's hook-specific state that a step
//! body interacts with through [`StepCtx`](crate::step::StepCtx). It carries two
//! hooks:
//!
//! * [`enforce_polynomial_query`](FrameworkHooks::enforce_polynomial_query) — a
//!   polynomial-query claim sink: steps that need to verify a
//!   polynomial-commitment opening — i.e. that the polynomial committed to by
//!   `com` evaluates to `y` at point `x` — reach it via
//!   [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query),
//!   which delegates here.
//! * [`derive_challenge`](FrameworkHooks::derive_challenge) — derives a
//!   challenge from any gadget entirely outside the circuit and returns two
//!   gadgets: a nested-curve `point` (a Pedersen commitment to the gadget's
//!   wires) and the derived challenge as an `Element` (the Poseidon hash of that
//!   point). Each call *induces a stage*: the gadget's wires become a
//!   partial-trace polynomial that `fuse()` commits to independently, turning
//!   the application circuit into a multi-stage circuit (see the staging chapter
//!   of the book). The succinct commitment is hashed to derive the challenge.
//!   The simple model is one stage per call; batching consecutive calls into a
//!   single stage is a future optimization. See [`InducedStage`].
//!
//! The framework collects the resulting outputs through the adapter's `Aux` for
//! later fuse-time processing. New framework hooks (e.g. transcript threading)
//! belong on this type as well.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, Point};

/// A single stage induced by a [`FrameworkHooks::derive_challenge`] call.
///
/// Under the simple model there is exactly one stage per call: the wires of the
/// gadget handed to `derive_challenge` become this stage's partial-trace
/// polynomial `a(X)`, which `fuse()` commits to independently. The succinct
/// commitment is hashed to derive the challenge.
///
/// This records only the *shape* of the induced stage. The actual derivation —
/// committing the slice, hashing the commitment in-circuit (à la the
/// `internal/native/circuits/hashes_1.rs` circuit), and resolving the derived
/// outputs — is future framework work.
pub struct InducedStage {
    /// Width of this stage's trace slice (the gadget's wire count), used by the
    /// discovery pass to reserve the partial-trace layout — the same quantity
    /// the staging builder derives via [`Gadget::num_wires`].
    pub num_wires: usize,
    // TODO: capture the gadget's actual wire handles (via a `WireMap`
    // collector) so fuse can commit to exactly this slice, not just its width.
    // TODO: hold the deferred output handles — the nested-curve commitment
    // `point` and the derived challenge — that fuse resolves once the stage is
    // committed. Adding these will parameterize this struct by `<'dr, D, C>`,
    // matching [`FrameworkHooks`].
}

/// Container for framework-side state threaded through a
/// [`Step::witness`](crate::step::Step::witness) invocation.
///
/// Holds the polynomial-commitment opening-claim sink and the stages induced by
/// [`derive_challenge`](Self::derive_challenge) calls. The framework's adapter
/// constructs this, passes it to the step, then surfaces
/// [`into_outputs`](Self::into_outputs) through its `Aux` for later fuse-time
/// processing.
pub struct FrameworkHooks<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    poly_query_claims: Vec<DriverValue<D, (C, D::F, D::F)>>,
    /// Stages induced by [`FrameworkHooks::derive_challenge`] calls — one per
    /// call under the simple model. Tracked here so `fuse()` can reserve each
    /// slice, commit to its partial trace, and resolve the derived values.
    derived_challenges: Vec<InducedStage>,
}

/// Aggregate of every hook's accumulated output, returned by
/// [`FrameworkHooks::into_outputs`]. Adding a new hook means adding a field
/// here, which forces every drain site to acknowledge it.
pub struct FrameworkHookOutputs<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Polynomial-commitment opening claims raised via
    /// [`FrameworkHooks::enforce_polynomial_query`].
    pub poly_query_claims: DriverValue<D, Vec<(C, D::F, D::F)>>,
    /// Stages induced by [`FrameworkHooks::derive_challenge`] calls, in call
    /// order. `fuse()` consumes these to build the per-call partial traces.
    pub derived_challenges: Vec<InducedStage>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> FrameworkHooks<'dr, D, C> {
    /// Creates a new, empty hook container.
    pub fn new() -> Self {
        Self {
            poly_query_claims: Vec::new(),
            derived_challenges: Vec::new(),
        }
    }

    /// Records a claim that the polynomial committed to by `com` evaluates to
    /// `y` at the point `x`.
    pub fn enforce_polynomial_query(
        &mut self,
        _dr: &mut D,
        com: Point<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        let triple =
            D::try_just(|| Ok((com.value().take(), *x.value().take(), *y.value().take())))?;
        self.poly_query_claims.push(triple);
        Ok(())
    }

    /// Derives a challenge from `gadget`. The real derivation happens entirely
    /// in the framework, *outside the circuit*; the step author only reasons
    /// about the two returned gadgets — a nested-curve `point` (a Pedersen
    /// commitment to the gadget's wires) and the derived challenge as an
    /// `Element` (the Poseidon hash of that point) — and trusts the framework to
    /// derive them.
    ///
    /// Each call induces one stage (simple model: one stage per call): the
    /// gadget's wires become a partial-trace polynomial that `fuse()` commits to
    /// independently, hashing the commitment to obtain the challenge. The
    /// induced stage is recorded on this container; see [`InducedStage`].
    pub fn derive_challenge<G: Gadget<'dr, D>>(
        &mut self,
        _dr: &mut D,
        gadget: G,
    ) -> Result<(Point<'dr, D, C>, Element<'dr, D>)> {
        // Record the induced stage's width now — that's what the discovery pass
        // needs to reserve the partial-trace slice.
        let num_wires = gadget.num_wires()?;
        self.derived_challenges.push(InducedStage { num_wires });

        // TODO: capture the gadget's actual wire handles (via a `WireMap`
        // collector) and store them on the recorded `InducedStage`, so fuse
        // commits to exactly this slice rather than just knowing its width.
        // TODO: allocate the two outputs — the nested-curve commitment `point`
        // and the derived challenge — against deferred witnesses, store their
        // handles on the recorded `InducedStage`, and return them. This needs
        // the staging transform plus the deferred-value mechanism (the
        // in-circuit hash of the stage commitment, à la
        // `internal/native/circuits/hashes_1.rs`), which is future framework
        // work.
        todo!("allocate and return deferred (point, challenge)")
    }

    /// Consumes the container and returns every hook's accumulated output.
    pub fn into_outputs(self) -> FrameworkHookOutputs<'dr, D, C> {
        let poly_query_claims =
            self.poly_query_claims
                .into_iter()
                .fold(D::just(Vec::new), |acc, triple| {
                    acc.and_then(|mut v| {
                        triple.map(|t| {
                            v.push(t);
                            v
                        })
                    })
                });
        FrameworkHookOutputs {
            poly_query_claims,
            // Induced stages carry no witness values yet (the deferred outputs
            // are resolved by fuse), so they pass through unchanged.
            derived_challenges: self.derived_challenges,
        }
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Default for FrameworkHooks<'dr, D, C> {
    fn default() -> Self {
        Self::new()
    }
}
