//! Context object threaded through
//! [`Step::witness`](crate::step::Step::witness)
//! — mirrors `ragu_pcd::step::StepCtx`.
//!
//! Real ragu's `StepCtx` bundles the circuit driver (its public `dr` field)
//! with the framework hooks. The mock has no driver, so it carries only the
//! crate-private `FrameworkHooks` sink and exposes the four hooks a step body reaches
//! for, taking and returning plain field values where the real methods take
//! driver values and gadget elements.

use ragu_core::Result;
use ragu_pasta::Fp;

use crate::{framework_hooks::FrameworkHooks, poly_commitment::PolyHandle, polynomial::Polynomial};

/// Framework-side state threaded through
/// [`Step::witness`](crate::step::Step::witness).
pub struct StepCtx<'a> {
    hooks: &'a mut FrameworkHooks,
}

impl<'a> StepCtx<'a> {
    pub(crate) fn new(hooks: &'a mut FrameworkHooks) -> Self {
        Self { hooks }
    }

    /// Commits `polynomial` on the framework side and hands back its handle.
    /// Mirrors `StepCtx::witness_polynomial`; costs one of the layout's
    /// polynomial-witness slots. Over-budget use is not rejected here — it
    /// surfaces when the enclosing `seed`/`fuse` assembles the transcript.
    pub fn witness_polynomial(&mut self, polynomial: Polynomial) -> Result<PolyHandle> {
        self.hooks.witness_polynomial(polynomial)
    }

    /// The polynomial behind `handle` evaluated at `x` — prover-only, records
    /// and enforces nothing. Mirrors `StepCtx::evaluate`. Fails with
    /// [`Error::InvalidWitness`](ragu_core::Error::InvalidWitness) if `handle`
    /// was not witnessed by this step.
    pub fn evaluate(&mut self, handle: &PolyHandle, x: Fp) -> Result<Fp> {
        self.hooks.evaluate(handle, x)
    }

    /// Records the poly-query `p(x) = y` for the polynomial behind `handle`.
    /// Mirrors `StepCtx::enforce_poly_query`; costs one of the layout's query
    /// slots (a repeat opening of the same polynomial costs a query, not a
    /// polynomial). Fails immediately with
    /// [`Error::InvalidWitness`](ragu_core::Error::InvalidWitness) if `handle`
    /// was not witnessed by this step or the polynomial does not evaluate to
    /// `y` at `x`.
    pub fn enforce_poly_query(&mut self, handle: &PolyHandle, x: Fp, y: Fp) -> Result<()> {
        self.hooks.enforce_poly_query(handle, x, y)
    }

    /// Derives a Fiat–Shamir challenge from `inputs`, padding empty positions
    /// up to the layout's challenge width with a fixed sentinel. Mirrors
    /// `StepCtx::derive_challenge`, which takes any `Write`-able gadget; the
    /// mock takes the written wires directly (e.g. `&handle.wires()`).
    ///
    /// The caller's obligation is unchanged from real ragu: everything
    /// absorbed must already be pinned by the step — a challenge derived from
    /// unpinned values is grindable.
    pub fn derive_challenge(&mut self, inputs: &[Fp]) -> Result<Fp> {
        self.hooks.derive_challenge(inputs)
    }
}
