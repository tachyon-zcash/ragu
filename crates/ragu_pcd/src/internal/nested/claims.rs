//! Claim orchestration for nested field (scalar field) rx polynomials.
//!
//! This module provides a unified interface for assembling `a` and `b`
//! polynomial vectors for nested field revdot claim verification.
//!
//! The nested claim structure is simpler than native:
//! - Circuit checks ([`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)): $k(y) = 1$
//! - Masking checks ([`EndoscalarStage`](InternalCircuitIndex::EndoscalarStage),
//!   [`PointsStage`](InternalCircuitIndex::PointsStage),
//!   `PointsFinalStaged`, and all `Bridge*` variants): $k(y) = 0$

use alloc::borrow::Cow;

use ragu_arithmetic::ff::PrimeField;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;

use super::{ChildBridgeKind, InternalCircuitIndex, RxIndex};
use crate::internal::claims::{Builder, Source, sum_polynomials};

/// Trait for processing nested claim values into accumulated outputs.
///
/// This trait defines how to process rx values from a [`Source`].
pub trait Processor<Rx> {
    /// Process an internal circuit claim whose trace is the sum of the given
    /// rxs ($k(y) = 1$ for [`EndoscalingStep`]).
    ///
    /// [`EndoscalingStep`]: InternalCircuitIndex::EndoscalingStep
    fn internal_circuit_claim(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>);

    /// Process a claim whose trace is the Horner fold (with $z$) of the given
    /// rxs, with one rx per fold slot ($k(y) = 0$).
    ///
    /// The default implementation wraps each rx as a single-element group and
    /// delegates to [`grouped_bonding_claim`](Self::grouped_bonding_claim).
    fn bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = Rx>,
    ) -> Result<()> {
        self.grouped_bonding_claim(id, rxs.map(core::iter::once))
    }

    /// Process a claim whose trace is the Horner fold (with $z$) of per-group
    /// sums, where each fold slot holds the sum of one inner iterator
    /// ($k(y) = 0$).
    fn grouped_bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Rx>>,
    ) -> Result<()>;
}

impl<'m, 'rx, F: PrimeField, R: Rank> Processor<&'rx sparse::Polynomial<F, R>>
    for Builder<'m, 'rx, Cow<'rx, sparse::Polynomial<F, R>>, F, R>
{
    fn internal_circuit_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
    ) {
        let circuit_id = id.circuit_index();
        let rx = sum_polynomials(rxs);
        self.circuit_impl(circuit_id, rx);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx sparse::Polynomial<F, R>>>,
    ) -> Result<()> {
        let circuit_id = id.circuit_index();
        let folded = self.fold_bonding_groups(groups);
        self.bonding_impl(circuit_id, folded);
        Ok(())
    }
}

/// Build nested claims in unified interleaved order from a source.
///
/// The ordering is:
/// 1. Circuit checks ($k(y) = 1$): [`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)
///    for each step, interleaved across proofs
/// 2. Masking checks ($k(y) = 0$): [`EndoscalarStage`](InternalCircuitIndex::EndoscalarStage),
///    [`PointsStage`](InternalCircuitIndex::PointsStage), `PointsFinalStaged`,
///    and all `Bridge*` variants
///
/// This ordering must match the ky_elements ordering from [`ky_values`].
pub fn build<S, P>(source: &S, processor: &mut P) -> Result<()>
where
    S: Source<RxComponent = RxIndex>,
    P: Processor<S::Rx>,
{
    for &id in &InternalCircuitIndex::ALL {
        use InternalCircuitIndex::*;
        match id {
            EndoscalingStep(step) => {
                for ((step_rx, endo_rx), pts_rx) in source
                    .rx(RxIndex::EndoscalingStep(step))
                    .zip(source.rx(RxIndex::EndoscalarStage))
                    .zip(source.rx(RxIndex::PointsStage))
                {
                    processor.internal_circuit_claim(id, [step_rx, endo_rx, pts_rx].into_iter());
                }
            }
            EndoscalarStage => {
                processor.bonding_claim(id, source.rx(RxIndex::EndoscalarStage))?;
            }
            PointsStage => {
                processor.bonding_claim(id, source.rx(RxIndex::PointsStage))?;
            }
            PointsFinalStaged => {
                let num_steps = super::NUM_ENDOSCALING_STEPS;
                let final_rxs = (0..num_steps)
                    .flat_map(|step| source.rx(RxIndex::EndoscalingStep(step as u32)));
                processor.bonding_claim(id, final_rxs)?;
            }
            BridgePreamble => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgePreamble))?;
            }
            BridgeSPrime => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeSPrime))?;
            }
            BridgeInnerError => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeInnerError))?;
            }
            BridgeOuterError => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeOuterError))?;
            }
            BridgeAB => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeAB))?;
            }
            BridgeQuery => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeQuery))?;
            }
            BridgeF => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeF))?;
            }
            BridgeEval => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeEval))?;
            }
            Loading => {
                let groups = source
                    .rx(RxIndex::PointsStage)
                    .zip(source.rx(RxIndex::BridgePreamble))
                    .zip(source.rx(RxIndex::BridgeSPrime))
                    .zip(source.rx(RxIndex::BridgeInnerError))
                    .zip(source.rx(RxIndex::BridgeAB))
                    .zip(source.rx(RxIndex::BridgeQuery))
                    .zip(source.rx(RxIndex::BridgeF))
                    .map(|((((((ps, bp), bs), bi), ba), bq), bf)| {
                        [ps, bp, bs, bi, ba, bq, bf].into_iter()
                    });
                processor.grouped_bonding_claim(id, groups)?;
            }
            Copying(side) => {
                let groups = source
                    .rx(RxIndex::ChildPointsStage(side))
                    .zip(source.rx(RxIndex::BridgePreamble))
                    .zip(source.rx(RxIndex::ChildBridge(ChildBridgeKind::SPrime, side)))
                    .zip(source.rx(RxIndex::ChildBridge(ChildBridgeKind::InnerError, side)))
                    .zip(source.rx(RxIndex::ChildBridge(ChildBridgeKind::OuterError, side)))
                    .zip(source.rx(RxIndex::ChildBridge(ChildBridgeKind::AB, side)))
                    .zip(source.rx(RxIndex::ChildBridge(ChildBridgeKind::Query, side)))
                    .zip(source.rx(RxIndex::ChildBridge(ChildBridgeKind::Eval, side)))
                    .map(|(((((((cp, bp), cs), ci), co), ca), cq), ce)| {
                        [cp, bp, cs, ci, co, ca, cq, ce].into_iter()
                    });
                processor.grouped_bonding_claim(id, groups)?;
            }
        }
    }

    Ok(())
}

/// Trait for providing $k(y)$ values for nested claim verification.
pub trait KySource {
    /// The $k(y)$ value type.
    type Ky: Clone;

    /// Returns 1 for circuit checks.
    fn one(&self) -> Self::Ky;

    /// Returns 0 for stage checks.
    fn zero(&self) -> Self::Ky;
}

/// Build an iterator over $k(y)$ values in nested claim order.
///
/// Returns:
/// - `num_steps` ones (for EndoscalingStep circuit checks, single-proof verification)
/// - Infinite zeros (for stage checks)
pub fn ky_values<S: KySource>(source: &S) -> impl Iterator<Item = S::Ky> {
    let num_steps = super::NUM_ENDOSCALING_STEPS;

    // Circuit checks: k(y) = 1 (for single-proof, num_circuit_claims = num_steps)
    core::iter::repeat_n(source.one(), num_steps)
        // Masking checks: k(y) = 0 (infinite, matches how native does it)
        .chain(core::iter::repeat(source.zero()))
}
