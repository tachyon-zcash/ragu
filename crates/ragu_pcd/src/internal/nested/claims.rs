//! Claim orchestration for nested field (scalar field) rx polynomials.
//!
//! This module provides a unified interface for assembling `a` and `b`
//! polynomial vectors for nested field revdot claim verification.
//!
//! The nested claim structure is simpler than native:
//! - Circuit checks ([`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)): $k(y) = 1$
//! - Stage checks ([`EndoscalarStage`](InternalCircuitIndex::EndoscalarStage),
//!   [`PointsStage`](InternalCircuitIndex::PointsStage),
//!   `PointsFinalStaged`): $k(y) = 0$

use alloc::borrow::Cow;

use ff::PrimeField;
use ragu_circuits::polynomials::{Rank, structured};
use ragu_core::Result;

use super::InternalCircuitIndex;
use crate::internal::claims::{Builder, KyIter, Source, sum_polynomials};

/// Canonical claim ordering for nested claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClaimOrder {
    EndoscalingStep(u32),
    Stage(InternalCircuitIndex),
}

/// Returns the canonical nested claim ordering: steps then stages.
pub(crate) fn claim_order() -> impl Iterator<Item = ClaimOrder> {
    use super::NUM_ENDOSCALING_POINTS;
    use crate::internal::endoscalar::NumStepsLen;
    use ragu_primitives::vec::Len;

    let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();

    (0..num_steps)
        .map(|step| ClaimOrder::EndoscalingStep(step as u32))
        .chain([
            ClaimOrder::Stage(InternalCircuitIndex::EndoscalarStage),
            ClaimOrder::Stage(InternalCircuitIndex::PointsStage),
            ClaimOrder::Stage(InternalCircuitIndex::PointsFinalStaged),
        ])
}

/// Per-group $k(y)$ iterators for nested claims, flattened in [`claim_order`]
/// sequence.
pub(crate) struct KyValues<I: Iterator> {
    pub(crate) circuit: I,
    pub(crate) zero: I::Item,
}

impl<I: Clone + Iterator> KyValues<I>
where
    I::Item: Clone,
{
    /// Flatten into $k(y)$ values in [`claim_order`] sequence.
    pub(crate) fn into_values(self) -> impl Iterator<Item = I::Item> {
        let KyValues { circuit, zero } = self;
        claim_order().flat_map(move |order| match order {
            ClaimOrder::EndoscalingStep(_) => KyIter::Value(circuit.clone()),
            ClaimOrder::Stage(_) => KyIter::Zero(core::iter::once(zero.clone())),
        })
    }
}

/// Enum identifying which nested field rx polynomial to retrieve from a proof.
#[derive(Clone, Copy, Debug)]
pub enum RxComponent {
    /// EndoscalarStage rx polynomial.
    EndoscalarStage,
    /// PointsStage rx polynomial.
    PointsStage,
    /// EndoscalingStep circuit rx polynomial (indexed by step number).
    EndoscalingStep(u32),
}

/// Trait for processing nested claim values into accumulated outputs.
///
/// This trait defines how to process rx values from a [`Source`].
pub trait Processor<Rx> {
    /// Process an internal circuit claim (EndoscalingStep) - sums rxs then processes.
    fn internal_circuit(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>);

    /// Process a stage claim - aggregates rxs from all proofs.
    fn stage(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>) -> Result<()>;
}

impl<'m, 'rx, F: PrimeField, R: Rank> Processor<&'rx structured::Polynomial<F, R>>
    for Builder<'m, 'rx, Cow<'rx, structured::Polynomial<F, R>>, F, R>
{
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

/// Build nested claims in unified interleaved order from a source.
///
/// The ordering is driven by [`claim_order`]:
/// 1. Circuit checks ($k(y) = 1$): [`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)
///    for each step, interleaved across proofs
/// 2. Stage checks ($k(y) = 0$): [`EndoscalarStage`](InternalCircuitIndex::EndoscalarStage),
///    [`PointsStage`](InternalCircuitIndex::PointsStage), `PointsFinalStaged`
///
/// This ordering must match the $k(y)$ ordering produced by
/// [`KyValues::into_values`], which is also driven by [`claim_order`].
pub fn build<S, P>(source: &S, processor: &mut P) -> Result<()>
where
    S: Source<RxComponent = RxComponent>,
    P: Processor<S::Rx>,
{
    use super::NUM_ENDOSCALING_POINTS;
    use crate::internal::endoscalar::NumStepsLen;
    use ragu_primitives::vec::Len;

    let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();

    for order in claim_order() {
        match order {
            ClaimOrder::EndoscalingStep(step) => {
                for ((step_rx, endo_rx), pts_rx) in source
                    .rx(RxComponent::EndoscalingStep(step))
                    .zip(source.rx(RxComponent::EndoscalarStage))
                    .zip(source.rx(RxComponent::PointsStage))
                {
                    processor.internal_circuit(
                        InternalCircuitIndex::EndoscalingStep(step),
                        [step_rx, endo_rx, pts_rx].into_iter(),
                    );
                }
            }
            ClaimOrder::Stage(id) => {
                use InternalCircuitIndex::*;
                match id {
                    EndoscalarStage => {
                        processor.stage(id, source.rx(RxComponent::EndoscalarStage))?;
                    }
                    PointsStage => {
                        processor.stage(id, source.rx(RxComponent::PointsStage))?;
                    }
                    PointsFinalStaged => {
                        let final_rxs = (0..num_steps)
                            .flat_map(|step| source.rx(RxComponent::EndoscalingStep(step as u32)));
                        processor.stage(id, final_rxs)?;
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    Ok(())
}
