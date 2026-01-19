//! Common abstraction for orchestrating revdot claims.
//!
//! This module provides a unified interface for assembling `a` and `b`
//! polynomial vectors for revdot claim verification, used by both verification
//! and proving. The same abstraction is used to handle consistency evaluation
//! logic in the recursive circuit.
//!
//! The abstraction separates:
//! - [`Source`]: Provides rx values from proof sources
//! - [`Processor`]: Processes rx values into accumulated outputs
//! - [`build`]: Orchestrates claim building in unified order

use alloc::borrow::Cow;
use core::iter::{once, repeat_n};

use ff::PrimeField;
use ragu_circuits::{
    polynomials::{Rank, structured},
    registry::CircuitIndex,
};
use ragu_core::Result;
use ragu_core::drivers::Driver;
use ragu_primitives::Element;

use super::{Builder, Source};
use crate::circuits::{self, native::InternalCircuitIndex};

/// Number of circuits using unified k(y) in [`build`].
///
/// These circuits use [`unified::InternalOutputKind`]:
/// [`hashes_2`], [`partial_collapse`], [`full_collapse`], [`compute_v`],
/// [`endoscale_challenges`].
///
/// Note: [`hashes_1`] separately uses `unified_bridge_ky` because its public
/// inputs include child proof headers (see [`hashes_1::Output`]).
///
/// [`hashes_1`]: crate::circuits::native::hashes_1
/// [`hashes_1::Output`]: crate::circuits::native::hashes_1::Output
/// [`hashes_2`]: crate::circuits::native::hashes_2
/// [`partial_collapse`]: crate::circuits::native::partial_collapse
/// [`full_collapse`]: crate::circuits::native::full_collapse
/// [`compute_v`]: crate::circuits::native::compute_v
/// [`endoscale_challenges`]: crate::circuits::native::endoscale_challenges
/// [`unified::InternalOutputKind`]: crate::circuits::native::unified::InternalOutputKind
pub const NUM_UNIFIED_CIRCUITS: usize = 5;

/// Enum identifying which native field rx polynomial to retrieve from a proof.
#[derive(Clone, Copy, Debug)]
pub enum RxComponent {
    /// The `a` polynomial from the AB proof (revdot claim).
    AbA,
    /// The `b` polynomial from the AB proof (revdot claim).
    AbB,
    /// The application circuit rx polynomial.
    Application,
    /// The hashes_1 internal circuit rx polynomial.
    Hashes1,
    /// The hashes_2 internal circuit rx polynomial.
    Hashes2,
    /// The partial_collapse internal circuit rx polynomial.
    PartialCollapse,
    /// The full_collapse internal circuit rx polynomial.
    FullCollapse,
    /// The compute_v internal circuit rx polynomial.
    ComputeV,
    /// The preamble native rx polynomial.
    Preamble,
    /// The error_m native rx polynomial.
    ErrorM,
    /// The error_n native rx polynomial.
    ErrorN,
    /// The query native rx polynomial.
    Query,
    /// The eval native rx polynomial.
    Eval,
    /// The endoscale_challenges internal circuit rx polynomial.
    EndoscaleChallenges,
}

/// Trait that processes claim values into accumulated outputs.
///
/// Defines how to process `rx` values from a [`Source`]. Implementations handle
/// polynomial and evaluation contexts differently:
///
/// - **Polynomial context** ([`Builder`]): `Rx` is a polynomial
///   reference. The processor accumulates polynomials for error term
///   construction.
/// - **Evaluation context**: `Rx` carries a single evaluated field element at
///   $xz$. Both the `ax` and `bx` vectors derive from this shared evaluation:
///   `ax` uses $r\_i(xz)$ directly (since $A$ has no dilation), while `bx` adds
///   $s\_y + t(xz)$.
pub trait Processor<Rx, AppCircuitId> {
    /// Process a raw claim (a/b directly, k(y) = c).
    fn raw_claim(&mut self, a: Rx, b: Rx);

    /// Process an application circuit claim (k(y) = application_ky).
    fn circuit(&mut self, app_id: AppCircuitId, rx: Rx);

    /// Process an internal circuit claim (sum of rxs, k(y) = internal_ky).
    /// The processor looks up registry via InternalCircuitIndex from its stored context.
    fn internal_circuit(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>);

    /// Process a stage claim (fold of rxs, k(y) = 0).
    /// Returns `Result<()>` because evaluation context requires fallible fold operations.
    fn stage(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>) -> Result<()>;
}

impl<'m, 'rx, F: PrimeField, R: Rank> Processor<&'rx structured::Polynomial<F, R>, CircuitIndex>
    for Builder<'m, 'rx, F, R>
{
    fn raw_claim(
        &mut self,
        a: &'rx structured::Polynomial<F, R>,
        b: &'rx structured::Polynomial<F, R>,
    ) {
        self.a.push(Cow::Borrowed(a));
        self.b.push(Cow::Borrowed(b));
    }

    fn circuit(&mut self, circuit_id: CircuitIndex, rx: &'rx structured::Polynomial<F, R>) {
        self.circuit_impl(circuit_id, Cow::Borrowed(rx));
    }

    fn internal_circuit(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) {
        let circuit_id = id.circuit_index();
        let rx = super::sum_polynomials(rxs);
        self.circuit_impl(circuit_id, rx);
    }

    fn stage(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) -> Result<()> {
        let circuit_id = id.circuit_index();
        self.stage_impl(circuit_id, rxs)
    }
}

/// Build claims in unified interleaved order from a source.
///
/// The ordering is: for each claim type, add claims for all proofs before
/// moving to the next claim type. This produces an interleaved order:
/// `[L_raw, R_raw, L_app, R_app, L_h1, R_h1, ...]` for two-proof sources.
///
/// This ordering must match the ky_elements ordering in `partial_collapse.rs`
/// and `fuse.rs` `compute_errors_n`.
pub fn build<S, P>(source: &S, processor: &mut P) -> Result<()>
where
    S: Source<RxComponent = RxComponent>,
    P: Processor<S::Rx, S::AppCircuitId>,
{
    use RxComponent::*;

    // Raw claims (interleaved: iterate over all proofs for AbA/AbB)
    for (a, b) in source.rx(AbA).zip(source.rx(AbB)) {
        processor.raw_claim(a, b);
    }

    // App circuits (interleaved)
    for (app_id, rx) in source.app_circuits().zip(source.rx(Application)) {
        processor.circuit(app_id, rx);
    }

    // hashes_1: needs Hashes1 + Preamble + ErrorN for each proof
    for ((h1, pre), en) in source
        .rx(Hashes1)
        .zip(source.rx(Preamble))
        .zip(source.rx(ErrorN))
    {
        processor.internal_circuit(
            circuits::native::hashes_1::CIRCUIT_ID,
            [h1, pre, en].into_iter(),
        );
    }

    // hashes_2: needs Hashes2 + ErrorN for each proof
    for (h2, en) in source.rx(Hashes2).zip(source.rx(ErrorN)) {
        processor.internal_circuit(circuits::native::hashes_2::CIRCUIT_ID, [h2, en].into_iter());
    }

    // partial_collapse: needs PartialCollapse + Preamble + ErrorM + ErrorN
    for (((pc, pre), em), en) in source
        .rx(PartialCollapse)
        .zip(source.rx(Preamble))
        .zip(source.rx(ErrorM))
        .zip(source.rx(ErrorN))
    {
        processor.internal_circuit(
            circuits::native::partial_collapse::CIRCUIT_ID,
            [pc, pre, em, en].into_iter(),
        );
    }

    // full_collapse: needs FullCollapse + Preamble + ErrorN (no ErrorM)
    for ((fc, pre), en) in source
        .rx(FullCollapse)
        .zip(source.rx(Preamble))
        .zip(source.rx(ErrorN))
    {
        processor.internal_circuit(
            circuits::native::full_collapse::CIRCUIT_ID,
            [fc, pre, en].into_iter(),
        );
    }

    // compute_v: needs ComputeV + Preamble + Query + Eval
    for (((cv, pre), q), e) in source
        .rx(ComputeV)
        .zip(source.rx(Preamble))
        .zip(source.rx(Query))
        .zip(source.rx(Eval))
    {
        processor.internal_circuit(
            circuits::native::compute_v::CIRCUIT_ID,
            [cv, pre, q, e].into_iter(),
        );
    }

    // endoscale_challenges: staged on error_n for consistency
    for (ec, en) in source.rx(EndoscaleChallenges).zip(source.rx(ErrorN)) {
        processor.internal_circuit(
            circuits::native::endoscale_challenges::CIRCUIT_ID,
            [ec, en].into_iter(),
        );
    }

    // Stages (aggregated: collect all proofs' rxs together)

    // ErrorMFinalStaged: only partial_collapse uses error_m as final stage
    processor.stage(
        InternalCircuitIndex::ErrorMFinalStaged,
        source.rx(PartialCollapse),
    )?;

    // ErrorNFinalStaged: hashes_1, hashes_2, full_collapse, endoscale_challenges use error_n as final stage
    processor.stage(
        InternalCircuitIndex::ErrorNFinalStaged,
        source
            .rx(Hashes1)
            .chain(source.rx(Hashes2))
            .chain(source.rx(FullCollapse))
            .chain(source.rx(EndoscaleChallenges)),
    )?;

    // EvalFinalStaged: all compute_v rxs
    processor.stage(InternalCircuitIndex::EvalFinalStaged, source.rx(ComputeV))?;

    // Native stages (aggregated across all proofs)
    processor.stage(
        circuits::native::stages::preamble::STAGING_ID,
        source.rx(Preamble),
    )?;

    processor.stage(
        circuits::native::stages::error_m::STAGING_ID,
        source.rx(ErrorM),
    )?;

    processor.stage(
        circuits::native::stages::error_n::STAGING_ID,
        source.rx(ErrorN),
    )?;

    processor.stage(
        circuits::native::stages::query::STAGING_ID,
        source.rx(Query),
    )?;

    processor.stage(circuits::native::stages::eval::STAGING_ID, source.rx(Eval))?;

    Ok(())
}

/// Trait for providing k(y) values for claim verification.
pub trait KySource {
    /// The k(y) value type.
    type Ky: Clone;

    /// Iterator over raw_c values (the c from AB proof / preamble unified).
    fn raw_c(&self) -> impl Iterator<Item = Self::Ky>;

    /// Iterator over application circuit k(y) values.
    fn application_ky(&self) -> impl Iterator<Item = Self::Ky>;

    /// Iterator over unified bridge k(y) values.
    fn unified_bridge_ky(&self) -> impl Iterator<Item = Self::Ky>;

    /// Base iterator over unified k(y) values (will be repeated [`NUM_UNIFIED_CIRCUITS`] times).
    /// The `+ Clone` bound is required for `repeat_n` in [`ky_values`].
    fn unified_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone;

    /// The zero value for stage claims.
    fn zero(&self) -> Self::Ky;
}

/// Build an iterator over k(y) values in claim order.
///
/// Chains the k(y) sources in the order required by [`build`],
/// with `unified_ky` repeated [`NUM_UNIFIED_CIRCUITS`] times,
/// followed by infinite zeros for stage claims.
pub fn ky_values<S: KySource>(source: &S) -> impl Iterator<Item = S::Ky> {
    source
        .raw_c()
        .chain(source.application_ky())
        .chain(source.unified_bridge_ky())
        .chain(repeat_n(source.unified_ky(), NUM_UNIFIED_CIRCUITS).flatten())
        .chain(core::iter::repeat(source.zero()))
}

pub struct TwoProofKySource<'dr, D: Driver<'dr>> {
    pub left_raw_c: Element<'dr, D>,
    pub right_raw_c: Element<'dr, D>,
    pub left_app: Element<'dr, D>,
    pub right_app: Element<'dr, D>,
    pub left_bridge: Element<'dr, D>,
    pub right_bridge: Element<'dr, D>,
    pub left_unified: Element<'dr, D>,
    pub right_unified: Element<'dr, D>,
    pub zero: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> KySource for TwoProofKySource<'dr, D> {
    type Ky = Element<'dr, D>;

    fn raw_c(&self) -> impl Iterator<Item = Element<'dr, D>> {
        once(self.left_raw_c.clone()).chain(once(self.right_raw_c.clone()))
    }

    fn application_ky(&self) -> impl Iterator<Item = Element<'dr, D>> {
        once(self.left_app.clone()).chain(once(self.right_app.clone()))
    }

    fn unified_bridge_ky(&self) -> impl Iterator<Item = Element<'dr, D>> {
        once(self.left_bridge.clone()).chain(once(self.right_bridge.clone()))
    }

    fn unified_ky(&self) -> impl Iterator<Item = Element<'dr, D>> + Clone {
        once(self.left_unified.clone()).chain(once(self.right_unified.clone()))
    }

    fn zero(&self) -> Element<'dr, D> {
        self.zero.clone()
    }
}
