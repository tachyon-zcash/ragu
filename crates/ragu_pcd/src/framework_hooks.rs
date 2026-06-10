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
//! ## Induced stage layout
//!
//! The stages induced by `derive_challenge` are not known at Rust compile
//! time — they depend on how many calls the step body makes and how wide each
//! gadget is. They *are* known at registration time, because circuit structure
//! is witness-independent: the adapter dry-runs the step body once (with an
//! [`Empty`](ragu_core::maybe::Empty) witness, on a counting emulator) and
//! records each call's gadget width, producing an
//! [`InducedStages`](ragu_circuits::staging::InducedStages) layout. The
//! adapter then reserves one region per stage at the head of the trace before
//! running the body for real, and passes the reserved regions to this
//! container via [`with_reserved`](FrameworkHooks::with_reserved). Each
//! `derive_challenge` call binds its gadget into the next reserved region with
//! one equality constraint per wire — that copy is what makes the stage
//! commitment (and hence the challenge) binding.
//!
//! A container created with [`new`](FrameworkHooks::new) has no reservations
//! and performs no binding: that is **discovery mode**, used only for the
//! registration-time dry run that produces the layout in the first place.
//!
//! The framework collects the resulting outputs through the adapter's `Aux` for
//! later fuse-time processing. New framework hooks (e.g. transcript threading)
//! belong on this type as well.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, Point, allocator::Standard};

/// A single stage induced by a [`FrameworkHooks::derive_challenge`] call.
///
/// Under the simple model there is exactly one stage per call: the wires of the
/// gadget handed to `derive_challenge` become this stage's partial-trace
/// polynomial `a(X)`, which `fuse()` commits to independently. The succinct
/// commitment is hashed to derive the challenge.
///
/// This records the induced stage's wire slice. The remaining derivation —
/// committing the slice, hashing the commitment in-circuit (à la the
/// `internal/native/circuits/hashes_1.rs` circuit), and resolving the derived
/// outputs — is future framework work.
pub struct InducedStage<'dr, D: Driver<'dr>> {
    /// Width of this stage's trace slice (the gadget's wire count) — the same
    /// quantity the registration-time discovery pass records in the
    /// [`InducedStages`](ragu_circuits::staging::InducedStages) layout, and
    /// the quantity the per-call determinism guard checks against it.
    pub num_wires: usize,
    /// The gadget's actual wire handles, in canonical traversal order, captured
    /// via [`Gadget::collect_wires`]. Each is bound by an equality constraint
    /// to the corresponding wire of the stage's reserved region, so the stage
    /// slice that `fuse()` commits to carries exactly these values. Always
    /// `wires.len() == num_wires`.
    pub wires: Vec<D::Wire>,
    // TODO: hold the deferred output handles — the nested-curve commitment
    // `point` and the derived challenge — that fuse resolves once the stage is
    // committed. Adding these will further parameterize this struct by `C`,
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
    /// call under the simple model. Tracked here so `fuse()` can commit to each
    /// partial trace and resolve the derived values.
    derived_challenges: Vec<InducedStage<'dr, D>>,
    /// The reserved stage regions, one per induced stage in the layout
    /// discovered at registration time, in stage order. `None` in discovery
    /// mode (see the [module documentation](self)).
    reserved: Option<Vec<Vec<D::Wire>>>,
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
    pub derived_challenges: Vec<InducedStage<'dr, D>>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> FrameworkHooks<'dr, D, C> {
    /// Creates a new, empty hook container in **discovery mode**: no stage
    /// regions are reserved and [`derive_challenge`](Self::derive_challenge)
    /// only records gadget widths without binding them. Used by the
    /// registration-time dry run that discovers the induced stage layout; real
    /// synthesis goes through [`with_reserved`](Self::with_reserved).
    pub fn new() -> Self {
        Self {
            poly_query_claims: Vec::new(),
            derived_challenges: Vec::new(),
            reserved: None,
        }
    }

    /// Creates a hook container with the reserved stage regions for the
    /// induced stage layout discovered at registration time, one region per
    /// stage in stage order. Each [`derive_challenge`](Self::derive_challenge)
    /// call consumes the next region, binding the gadget's wires to it.
    pub fn with_reserved(reserved: Vec<Vec<D::Wire>>) -> Self {
        Self {
            poly_query_claims: Vec::new(),
            derived_challenges: Vec::new(),
            reserved: Some(reserved),
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
    /// independently, hashing the commitment to obtain the challenge. The call
    /// binds the gadget into the stage's reserved region (one equality
    /// constraint per wire) and records the induced stage on this container;
    /// see [`InducedStage`] and the [module documentation](self).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if the call sequence diverges from
    /// the layout discovered at registration time — more calls than discovered
    /// stages, or a gadget whose width differs from the discovered width. An
    /// honest step body cannot trip this: circuit structure must not depend on
    /// witness values, so the dry run and the real run make identical calls.
    pub fn derive_challenge<G: Gadget<'dr, D>>(
        &mut self,
        dr: &mut D,
        gadget: G,
    ) -> Result<(Point<'dr, D, C>, Element<'dr, D>)> {
        // Capture the gadget's actual wire handles now — the stage's partial
        // trace carries exactly these values.
        let wires = gadget.collect_wires()?;

        // Bind the gadget into its reserved stage region. Skipped in
        // discovery mode, which only records widths.
        if let Some(reserved) = &self.reserved {
            let stage = self.derived_challenges.len();
            let region = reserved.get(stage).ok_or_else(|| {
                Error::InvalidWitness(
                    "derive_challenge called more times than the discovered stage layout; \
                     circuit structure must not depend on witness values"
                        .into(),
                )
            })?;
            if region.len() != wires.len() {
                return Err(Error::InvalidWitness(
                    "derive_challenge gadget width diverged from the discovered stage layout; \
                     circuit structure must not depend on witness values"
                        .into(),
                ));
            }

            // The stage polynomial coefficient at each reserved position must
            // equal the corresponding gadget wire: this copy is what makes
            // the stage commitment (and hence the challenge) binding. The
            // reserved wires carry zero in the final trace; the stage
            // polynomial supplies the actual values, so the constraint holds
            // over their sum.
            for (user, stage_wire) in wires.iter().zip(region.iter()) {
                dr.enforce_zero(|lc| lc.add(user).sub(stage_wire))?;
            }
        }

        self.derived_challenges.push(InducedStage {
            num_wires: wires.len(),
            wires,
        });

        // Allocate the two deferred outputs — the nested-curve commitment
        // `point` and the derived challenge. Their wires exist now (so the
        // step body can compute over them and fuse can later constrain them
        // via the in-circuit hash of the stage commitment, à la
        // `internal/native/circuits/hashes_1.rs`), but resolving their
        // *values* is future framework work: the value closures only run on
        // value-carrying drivers, so structure-only passes (registration,
        // discovery, metrics) complete while proving still hits the todo.
        let point_value: DriverValue<D, C> =
            D::just(|| todo!("resolve the deferred stage commitment in fuse"));
        let point = Point::alloc(dr, point_value)?;

        let challenge_value: DriverValue<D, D::F> =
            D::just(|| todo!("resolve the deferred challenge in fuse"));
        let challenge = Element::alloc(dr, &mut Standard::new(), challenge_value)?;

        Ok((point, challenge))
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
