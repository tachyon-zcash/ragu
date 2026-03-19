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
use core::iter::once;

use ff::PrimeField;
use ragu_circuits::{
    polynomials::{Rank, structured},
    registry::CircuitIndex,
};
use ragu_core::Result;
use ragu_core::drivers::Driver;
use ragu_primitives::Element;

use super::{InternalCircuitIndex, RxComponent, RxIndex};
use crate::internal::claims::{Builder, KyIter, KySource, Source, sum_polynomials};

/// Which $k(y)$ group a claim belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KyKind {
    Raw,
    Application,
    UnifiedBridge,
    Unified,
    Zero,
}

/// Canonical claim ordering, shared by [`build`] and [`KyValues::into_values`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClaimOrder {
    Raw,
    Application,
    Internal(InternalCircuitIndex),
}

impl ClaimOrder {
    pub(crate) fn ky_kind(&self) -> KyKind {
        match self {
            Self::Raw => KyKind::Raw,
            Self::Application => KyKind::Application,
            Self::Internal(id) => {
                use InternalCircuitIndex::*;
                match id {
                    Hashes1Circuit => KyKind::UnifiedBridge,
                    Hashes2Circuit
                    | PartialCollapseCircuit
                    | FullCollapseCircuit
                    | ComputeVCircuit => KyKind::Unified,
                    PreambleStage | ErrorMStage | ErrorNStage | QueryStage | EvalStage
                    | ErrorMFinalStaged | ErrorNFinalStaged | EvalFinalStaged => KyKind::Zero,
                }
            }
        }
    }
}

/// Returns the canonical claim ordering: raw, application, then all internal circuits.
pub(crate) fn claim_order() -> impl Iterator<Item = ClaimOrder> {
    once(ClaimOrder::Raw)
        .chain(once(ClaimOrder::Application))
        .chain(
            InternalCircuitIndex::ALL
                .iter()
                .copied()
                .map(ClaimOrder::Internal),
        )
}

/// Per-group $k(y)$ iterators, flattened in [`claim_order`] sequence.
pub(crate) struct KyValues<I: Iterator> {
    pub(crate) raw: I,
    pub(crate) application: I,
    pub(crate) unified_bridge: I,
    pub(crate) unified: I,
    pub(crate) zero: I::Item,
}

impl<I: Clone + Iterator> KyValues<I>
where
    I::Item: Clone,
{
    /// Flatten into $k(y)$ values in [`claim_order`] sequence.
    pub(crate) fn into_values(self) -> impl Iterator<Item = I::Item> {
        let KyValues {
            raw,
            application,
            unified_bridge,
            unified,
            zero,
        } = self;
        claim_order().flat_map(move |order| match order.ky_kind() {
            KyKind::Raw => KyIter::Value(raw.clone()),
            KyKind::Application => KyIter::Value(application.clone()),
            KyKind::UnifiedBridge => KyIter::Value(unified_bridge.clone()),
            KyKind::Unified => KyIter::Value(unified.clone()),
            KyKind::Zero => KyIter::Zero(once(zero.clone())),
        })
    }
}

/// Trait that processes claim values into accumulated outputs.
///
/// Defines how to process `rx` values from a [`Source`]. Implementations handle
/// polynomial and evaluation contexts differently:
///
/// - **Polynomial context** ([`Builder`]): `Rx` is a polynomial
///   reference. The processor accumulates polynomials for error term
///   construction.
/// - **Fuse path** ([`Builder`] with `TrackedPoly` `A`): `Rx` is an
///   `Atom` pairing a polynomial reference with a `FoldKey` key for
///   commitment decomposition tracking (see `fuse::claims`).
/// - **Evaluation context**: `Rx` carries a single evaluated field element at
///   $xz$. Both the `ax` and `bx` vectors derive from this shared evaluation:
///   `ax` uses $r\_i(xz)$ directly (since $A$ has no dilation), while `bx` adds
///   $s\_y + t(xz)$.
pub trait Processor<Rx, AppCircuitId> {
    /// Process a raw claim (a/b directly, $k(y) = c$).
    fn raw_claim(&mut self, a: Rx, b: Rx);

    /// Process an application circuit claim ($k(y) = \text{application\_ky}$).
    fn circuit(&mut self, app_id: AppCircuitId, rx: Rx);

    /// Process an internal circuit claim (sum of rxs, $k(y) = \text{internal\_ky}$).
    ///
    /// The processor looks up registry via [`InternalCircuitIndex`] from its stored context.
    fn internal_circuit(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>);

    /// Process a stage claim (fold of rxs, $k(y) = 0$).
    ///
    /// Returns `Result<()>` because evaluation context requires fallible fold operations.
    fn stage(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>) -> Result<()>;
}

impl<'m, 'rx, F: PrimeField, R: Rank> Processor<&'rx structured::Polynomial<F, R>, CircuitIndex>
    for Builder<'m, 'rx, Cow<'rx, structured::Polynomial<F, R>>, F, R>
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
        let rx = sum_polynomials(rxs);
        self.circuit_impl(circuit_id, rx);
    }

    fn stage(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) -> Result<()> {
        let circuit_id = id.circuit_index();
        let folded = self.fold_stage_polys(rxs);
        self.stage_impl(circuit_id, folded);
        Ok(())
    }
}

/// Build claims in unified interleaved order from a source.
///
/// The ordering is driven by [`claim_order`]: for each claim type, add claims
/// for all proofs before moving to the next claim type. This produces an
/// interleaved order: `[L_raw, R_raw, L_app, R_app, L_h1, R_h1, ...]` for
/// two-proof sources.
///
/// This ordering must match the $k(y)$ ordering produced by
/// [`KyValues::into_values`], which is also driven by [`claim_order`].
pub fn build<S, P>(source: &S, processor: &mut P) -> Result<()>
where
    S: Source<RxComponent = RxComponent>,
    P: Processor<S::Rx, S::AppCircuitId>,
{
    use RxComponent::*;
    use RxIndex::*;

    for order in claim_order() {
        match order {
            ClaimOrder::Raw => {
                for (a, b) in source.rx(AbA).zip(source.rx(AbB)) {
                    processor.raw_claim(a, b);
                }
            }
            ClaimOrder::Application => {
                for (app_id, rx) in source.app_circuits().zip(source.rx(Rx(Application))) {
                    processor.circuit(app_id, rx);
                }
            }
            ClaimOrder::Internal(id) => {
                use InternalCircuitIndex::*;
                match id {
                    // hashes_1: Hashes1 + Preamble + ErrorN
                    Hashes1Circuit => {
                        for ((h1, pre), en) in source
                            .rx(Rx(Hashes1))
                            .zip(source.rx(Rx(Preamble)))
                            .zip(source.rx(Rx(ErrorN)))
                        {
                            processor.internal_circuit(id, [h1, pre, en].into_iter());
                        }
                    }

                    // hashes_2: Hashes2 + ErrorN
                    Hashes2Circuit => {
                        for (h2, en) in source.rx(Rx(Hashes2)).zip(source.rx(Rx(ErrorN))) {
                            processor.internal_circuit(id, [h2, en].into_iter());
                        }
                    }

                    // partial_collapse: PartialCollapse + Preamble + ErrorM + ErrorN
                    PartialCollapseCircuit => {
                        for (((pc, pre), em), en) in source
                            .rx(Rx(PartialCollapse))
                            .zip(source.rx(Rx(Preamble)))
                            .zip(source.rx(Rx(ErrorM)))
                            .zip(source.rx(Rx(ErrorN)))
                        {
                            processor.internal_circuit(id, [pc, pre, em, en].into_iter());
                        }
                    }

                    // full_collapse: FullCollapse + Preamble + ErrorN
                    FullCollapseCircuit => {
                        for ((fc, pre), en) in source
                            .rx(Rx(FullCollapse))
                            .zip(source.rx(Rx(Preamble)))
                            .zip(source.rx(Rx(ErrorN)))
                        {
                            processor.internal_circuit(id, [fc, pre, en].into_iter());
                        }
                    }

                    // compute_v: ComputeV + Preamble + Query + Eval
                    ComputeVCircuit => {
                        for (((cv, pre), q), e) in source
                            .rx(Rx(ComputeV))
                            .zip(source.rx(Rx(Preamble)))
                            .zip(source.rx(Rx(Query)))
                            .zip(source.rx(Rx(Eval)))
                        {
                            processor.internal_circuit(id, [cv, pre, q, e].into_iter());
                        }
                    }

                    // Native stages (aggregated across all proofs)
                    PreambleStage => {
                        processor.stage(id, source.rx(Rx(Preamble)))?;
                    }
                    ErrorMStage => {
                        processor.stage(id, source.rx(Rx(ErrorM)))?;
                    }
                    ErrorNStage => {
                        processor.stage(id, source.rx(Rx(ErrorN)))?;
                    }
                    QueryStage => {
                        processor.stage(id, source.rx(Rx(Query)))?;
                    }
                    EvalStage => {
                        processor.stage(id, source.rx(Rx(Eval)))?;
                    }

                    // Final stage masks
                    ErrorMFinalStaged => {
                        processor.stage(id, source.rx(Rx(PartialCollapse)))?;
                    }
                    ErrorNFinalStaged => {
                        processor.stage(
                            id,
                            source
                                .rx(Rx(Hashes1))
                                .chain(source.rx(Rx(Hashes2)))
                                .chain(source.rx(Rx(FullCollapse))),
                        )?;
                    }
                    EvalFinalStaged => {
                        processor.stage(id, source.rx(Rx(ComputeV)))?;
                    }
                }
            }
        }
    }

    Ok(())
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
    type Item = Element<'dr, D>;

    fn ky_values(&self) -> impl Iterator<Item = Element<'dr, D>> {
        let pair =
            |l: &Element<'dr, D>, r: &Element<'dr, D>| once(l.clone()).chain(once(r.clone()));
        KyValues {
            raw: pair(&self.left_raw_c, &self.right_raw_c),
            application: pair(&self.left_app, &self.right_app),
            unified_bridge: pair(&self.left_bridge, &self.right_bridge),
            unified: pair(&self.left_unified, &self.right_unified),
            zero: self.zero.clone(),
        }
        .into_values()
    }

    fn zero(&self) -> Element<'dr, D> {
        self.zero.clone()
    }
}
