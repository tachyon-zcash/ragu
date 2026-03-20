//! Claim orchestration for nested field (scalar field) rx polynomials.
//!
//! This module provides a unified interface for assembling `a` and `b`
//! polynomial vectors for nested field revdot claim verification.
//!
//! The nested claim structure is simpler than native:
//! - Circuit checks ([`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)): $k(y) = 1$
//! - Stage checks ([`EndoscalarStage`](InternalCircuitIndex::EndoscalarStage),
//!   [`PointsStage`](InternalCircuitIndex::PointsStage),
//!   `PointsFinalStaged`, and all `Bridge*` variants): $k(y) = 0$

use alloc::borrow::Cow;

use ff::PrimeField;
use ragu_circuits::polynomials::{Rank, structured};
use ragu_core::Result;

use super::{InternalCircuitIndex, RxIndex};
use crate::internal::claims::{Builder, Source, sum_polynomials};

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
/// The ordering is:
/// 1. Circuit checks ($k(y) = 1$): [`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)
///    for each step, interleaved across proofs
/// 2. Stage checks ($k(y) = 0$): [`EndoscalarStage`](InternalCircuitIndex::EndoscalarStage),
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
                    processor.internal_circuit(id, [step_rx, endo_rx, pts_rx].into_iter());
                }
            }
            EndoscalarStage => {
                processor.stage(id, source.rx(RxIndex::EndoscalarStage))?;
            }
            PointsStage => {
                processor.stage(id, source.rx(RxIndex::PointsStage))?;
            }
            PointsFinalStaged => {
                let num_steps = super::NUM_ENDOSCALING_STEPS;
                let final_rxs = (0..num_steps)
                    .flat_map(|step| source.rx(RxIndex::EndoscalingStep(step as u32)));
                processor.stage(id, final_rxs)?;
            }
            BridgePreamble => {
                processor.stage(id, source.rx(RxIndex::BridgePreamble))?;
            }
            BridgeSPrime => {
                processor.stage(id, source.rx(RxIndex::BridgeSPrime))?;
            }
            BridgeInnerError => {
                processor.stage(id, source.rx(RxIndex::BridgeInnerError))?;
            }
            BridgeOuterError => {
                processor.stage(id, source.rx(RxIndex::BridgeOuterError))?;
            }
            BridgeAB => {
                processor.stage(id, source.rx(RxIndex::BridgeAB))?;
            }
            BridgeQuery => {
                processor.stage(id, source.rx(RxIndex::BridgeQuery))?;
            }
            BridgeF => {
                processor.stage(id, source.rx(RxIndex::BridgeF))?;
            }
            BridgeEval => {
                processor.stage(id, source.rx(RxIndex::BridgeEval))?;
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

/// Returns the number of concrete (non-zero) k(y) values produced by
/// [`ky_values`], i.e. the count before the infinite zero tail begins.
///
/// This must equal the number of non-stage claims produced by [`build`]
/// for the same source shape.
pub fn num_concrete_ky() -> usize {
    use super::NUM_ENDOSCALING_POINTS;
    use crate::internal::endoscalar::NumStepsLen;
    use ragu_primitives::vec::Len;

    NumStepsLen::<NUM_ENDOSCALING_POINTS>::len()
}

/// Build an iterator over $k(y)$ values in nested claim order.
///
/// Returns:
/// - `num_steps` ones (for EndoscalingStep circuit checks, single-proof verification)
/// - Infinite zeros (for stage checks)
///
/// See [`native::ky_values`] for notes on the infinite zero tail.
///
/// [`native::ky_values`]: crate::internal::native::claims::ky_values
pub fn ky_values<S: KySource>(source: &S) -> impl Iterator<Item = S::Ky> {
    let num_steps = super::NUM_ENDOSCALING_STEPS;

    // Circuit checks: k(y) = 1 (for single-proof, num_circuit_claims = num_steps)
    core::iter::repeat_n(source.one(), num_steps)
        // Stage checks: k(y) = 0 (infinite, also used for fold grouping padding)
        .chain(core::iter::repeat(source.zero()))
}
