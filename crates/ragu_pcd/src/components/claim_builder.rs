//! Common abstraction for building revdot claim polynomial vectors.
//!
//! This module provides a unified interface for assembling `a` and `b` polynomial
//! vectors for revdot claim verification, used by both verification and proving.
//!
//! The abstraction separates:
//! - [`ClaimSource`]: Provides rx values from proof sources
//! - [`ClaimProcessor`]: Processes rx values into accumulated outputs
//! - [`build_claims`]: Orchestrates claim building in unified order

use alloc::{borrow::Cow, vec::Vec};
use ff::PrimeField;
use ragu_circuits::{
    mesh::{CircuitIndex, Mesh},
    polynomials::{Rank, structured},
};
use ragu_core::Result;

use crate::internal_circuits::{self, InternalCircuitIndex};

/// Enum identifying which rx polynomial to retrieve from a proof.
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
    /// The preamble stage rx polynomial.
    PreambleStage,
    /// The error_m stage rx polynomial.
    ErrorMStage,
    /// The error_n stage rx polynomial.
    ErrorNStage,
    /// The query stage rx polynomial.
    QueryStage,
    /// The eval stage rx polynomial.
    EvalStage,
}

/// Trait for providing claim component values from sources.
///
/// This trait abstracts over what a "source" provides. For polynomial contexts
/// (verify, fuse), it provides polynomial references. For evaluation contexts
/// (compute_v), it provides element evaluation tuples.
///
/// Implementors provide access to rx values for all proofs they manage.
/// For verification (single proof), iterators yield 1 item.
/// For fuse (two proofs), iterators yield 2 items (left, right).
pub trait ClaimSource {
    /// Opaque type for rx values. Could be:
    /// - `&Polynomial<F, R>` for polynomial context
    /// - `(&Element, &Element)` for evaluation context (at_x, at_xz)
    type Rx;

    /// Type for application circuit identifiers. Could be:
    /// - `CircuitIndex` for polynomial context
    /// - `(CircuitIndex, &Element)` for evaluation context (includes mesh eval)
    type AppCircuitId;

    /// Get an iterator over rx values for all proofs for the given component.
    fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx>;

    /// Get an iterator over application circuit info for all proofs.
    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId>;
}

/// Trait for processing claim values into accumulated outputs.
///
/// This trait defines how to process rx values from a [`ClaimSource`].
/// Different implementations handle polynomial vs evaluation contexts.
pub trait ClaimProcessor<Rx, AppCircuitId> {
    /// Process a raw claim (a/b directly, k(y) = c).
    fn raw_claim(&mut self, a: Rx, b: Rx);

    /// Process an application circuit claim (k(y) = application_ky).
    fn circuit(&mut self, app_id: AppCircuitId, rx: Rx);

    /// Process an internal circuit claim (sum of rxs, k(y) = internal_ky).
    /// The processor looks up mesh via InternalCircuitIndex from its stored context.
    fn internal_circuit(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>);

    /// Process a stage claim (fold of rxs, k(y) = 0).
    /// Returns `Result<()>` because evaluation context requires fallible fold operations.
    fn stage(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>) -> Result<()>;
}

/// Build claims in unified interleaved order from a source.
///
/// The ordering is: for each claim type, add claims for all proofs before
/// moving to the next claim type. This produces an interleaved order:
/// `[L_raw, R_raw, L_app, R_app, L_h1, R_h1, ...]` for two-proof sources.
///
/// This ordering must match the ky_elements ordering in `partial_collapse.rs`
/// and `fuse.rs` `compute_errors_n`.
pub fn build_claims<S, P>(source: &S, processor: &mut P) -> Result<()>
where
    S: ClaimSource,
    P: ClaimProcessor<S::Rx, S::AppCircuitId>,
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

    // hashes_1: needs Hashes1 + PreambleStage + ErrorNStage for each proof
    for ((h1, pre), en) in source
        .rx(Hashes1)
        .zip(source.rx(PreambleStage))
        .zip(source.rx(ErrorNStage))
    {
        processor.internal_circuit(
            internal_circuits::hashes_1::CIRCUIT_ID,
            [h1, pre, en].into_iter(),
        );
    }

    // hashes_2: needs Hashes2 + ErrorNStage for each proof
    for (h2, en) in source.rx(Hashes2).zip(source.rx(ErrorNStage)) {
        processor.internal_circuit(
            internal_circuits::hashes_2::CIRCUIT_ID,
            [h2, en].into_iter(),
        );
    }

    // partial_collapse: needs PartialCollapse + PreambleStage + ErrorMStage + ErrorNStage
    for (((pc, pre), em), en) in source
        .rx(PartialCollapse)
        .zip(source.rx(PreambleStage))
        .zip(source.rx(ErrorMStage))
        .zip(source.rx(ErrorNStage))
    {
        processor.internal_circuit(
            internal_circuits::partial_collapse::CIRCUIT_ID,
            [pc, pre, em, en].into_iter(),
        );
    }

    // full_collapse: needs FullCollapse + PreambleStage + ErrorMStage + ErrorNStage
    for (((fc, pre), em), en) in source
        .rx(FullCollapse)
        .zip(source.rx(PreambleStage))
        .zip(source.rx(ErrorMStage))
        .zip(source.rx(ErrorNStage))
    {
        processor.internal_circuit(
            internal_circuits::full_collapse::CIRCUIT_ID,
            [fc, pre, em, en].into_iter(),
        );
    }

    // compute_v: needs ComputeV + PreambleStage + QueryStage + EvalStage
    for (((cv, pre), q), e) in source
        .rx(ComputeV)
        .zip(source.rx(PreambleStage))
        .zip(source.rx(QueryStage))
        .zip(source.rx(EvalStage))
    {
        processor.internal_circuit(
            internal_circuits::compute_v::CIRCUIT_ID,
            [cv, pre, q, e].into_iter(),
        );
    }

    // Stages (aggregated: collect all proofs' rxs together)

    // ErrorNFinalStaged: all hashes and collapse rxs
    processor.stage(
        InternalCircuitIndex::ErrorNFinalStaged,
        source
            .rx(Hashes1)
            .chain(source.rx(Hashes2))
            .chain(source.rx(PartialCollapse))
            .chain(source.rx(FullCollapse)),
    )?;

    // EvalFinalStaged: all compute_v rxs
    processor.stage(InternalCircuitIndex::EvalFinalStaged, source.rx(ComputeV))?;

    // Native stages (aggregated across all proofs)
    processor.stage(
        internal_circuits::stages::native::preamble::STAGING_ID,
        source.rx(PreambleStage),
    )?;

    processor.stage(
        internal_circuits::stages::native::error_m::STAGING_ID,
        source.rx(ErrorMStage),
    )?;

    processor.stage(
        internal_circuits::stages::native::error_n::STAGING_ID,
        source.rx(ErrorNStage),
    )?;

    processor.stage(
        internal_circuits::stages::native::query::STAGING_ID,
        source.rx(QueryStage),
    )?;

    processor.stage(
        internal_circuits::stages::native::eval::STAGING_ID,
        source.rx(EvalStage),
    )?;

    Ok(())
}

/// Processor that builds polynomial vectors for revdot claims.
///
/// Accumulates (a, b) polynomial pairs for each claim type, using
/// the mesh polynomial to transform rx polynomials appropriately.
pub struct ClaimBuilder<'m, 'rx, F: PrimeField, R: Rank> {
    circuit_mesh: &'m Mesh<'m, F, R>,
    num_application_steps: usize,
    y: F,
    z: F,
    tz: structured::Polynomial<F, R>,
    /// The accumulated `a` polynomials for revdot claims.
    pub a: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
    /// The accumulated `b` polynomials for revdot claims.
    pub b: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
}

impl<'m, 'rx, F: PrimeField, R: Rank> ClaimBuilder<'m, 'rx, F, R> {
    /// Create a new claim builder.
    pub fn new(circuit_mesh: &'m Mesh<'m, F, R>, num_application_steps: usize, y: F, z: F) -> Self {
        Self {
            circuit_mesh,
            num_application_steps,
            y,
            z,
            tz: R::tz(z),
            a: Vec::new(),
            b: Vec::new(),
        }
    }

    fn circuit_impl(
        &mut self,
        circuit_id: CircuitIndex,
        rx: Cow<'rx, structured::Polynomial<F, R>>,
    ) {
        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);
        let mut b = rx.as_ref().clone();
        b.dilate(self.z);
        b.add_assign(&sy);
        b.add_assign(&self.tz);

        self.a.push(rx);
        self.b.push(Cow::Owned(b));
    }
}

impl<'m, 'rx, F: PrimeField, R: Rank>
    ClaimProcessor<&'rx structured::Polynomial<F, R>, CircuitIndex>
    for ClaimBuilder<'m, 'rx, F, R>
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
        let circuit_id = id.circuit_index(self.num_application_steps);
        let rxs: Vec<_> = rxs.collect();
        assert!(!rxs.is_empty(), "must provide at least one rx polynomial");

        let rx = if rxs.len() == 1 {
            Cow::Borrowed(rxs[0])
        } else {
            let mut sum = rxs[0].clone();
            for rx in &rxs[1..] {
                sum.add_assign(rx);
            }
            Cow::Owned(sum)
        };

        self.circuit_impl(circuit_id, rx);
    }

    fn stage(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) -> Result<()> {
        let rxs: Vec<_> = rxs.collect();
        assert!(!rxs.is_empty(), "must provide at least one rx polynomial");

        let circuit_id = id.circuit_index(self.num_application_steps);
        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);

        let a = if rxs.len() == 1 {
            Cow::Borrowed(rxs[0])
        } else {
            Cow::Owned(structured::Polynomial::fold(rxs, self.z))
        };

        self.a.push(a);
        self.b.push(Cow::Owned(sy));
        Ok(())
    }
}
