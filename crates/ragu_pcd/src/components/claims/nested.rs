//! Claim orchestration for nested field (scalar field) rx polynomials.
//!
//! This module provides a unified interface for assembling `a` and `b`
//! polynomial vectors for nested field revdot claim verification.
//!
//! The nested claim structure is simpler than native:
//! - Circuit checks (EndoscalingStep): k(y) = 1
//! - Stage checks (EndoscalarStage, PointsStage, PointsFinalStaged): k(y) = 0

use ff::PrimeField;
use ragu_circuits::polynomials::{Rank, structured};
use ragu_core::Result;

use super::{Builder, Source};
use crate::circuits::nested::InternalCircuitIndex;

/// Enum identifying which nested field rx polynomial to retrieve from a proof.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RxComponent {
    /// EndoscalarStage rx polynomial.
    EndoscalarStage,
    /// PointsStage rx polynomial.
    PointsStage,
    /// EndoscalingStep circuit rx polynomial (indexed by step number).
    EndoscalingStep(usize),
}

/// Trait for processing nested claim values into accumulated outputs.
///
/// This trait defines how to process rx values from a [`Source`].
pub(crate) trait Processor<Rx> {
    /// Process an internal circuit claim (EndoscalingStep) - sums rxs then processes.
    fn internal_circuit(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>);

    /// Process a stage claim - aggregates rxs from all proofs.
    fn stage(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>) -> Result<()>;
}

impl<'m, 'rx, F: PrimeField, R: Rank> Processor<&'rx structured::Polynomial<F, R>>
    for Builder<'m, 'rx, F, R>
{
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

/// Build nested claims in unified interleaved order from a source.
///
/// The ordering is:
/// 1. Circuit checks (k(y) = 1): EndoscalingStep for each step, interleaved across proofs
/// 2. Stage checks (k(y) = 0): EndoscalarStage, PointsStage, PointsFinalStaged
///
/// This ordering must match the ky_elements ordering from [`ky_values`].
pub(crate) fn build<S, P>(source: &S, processor: &mut P) -> Result<()>
where
    S: Source<RxComponent = RxComponent>,
    P: Processor<S::Rx>,
{
    use crate::circuits::nested::NUM_ENDOSCALING_POINTS;
    use crate::components::endoscalar::NumStepsLen;
    use ragu_primitives::vec::Len;

    let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();

    use RxComponent::*;

    // 1. Circuit checks FIRST (k(y) = 1)
    // Process all EndoscalingStep circuits (interleaved across proofs)
    // Each circuit claim needs: step_rx + endoscalar_rx + points_rx
    for step in 0..num_steps {
        for ((step_rx, endo_rx), pts_rx) in source
            .rx(EndoscalingStep(step))
            .zip(source.rx(EndoscalarStage))
            .zip(source.rx(PointsStage))
        {
            processor.internal_circuit(
                InternalCircuitIndex::EndoscalingStep(step),
                [step_rx, endo_rx, pts_rx].into_iter(),
            );
        }
    }

    // 2. Stage checks SECOND (k(y) = 0)
    // EndoscalarStage (index 0)
    processor.stage(
        InternalCircuitIndex::EndoscalarStage,
        source.rx(EndoscalarStage),
    )?;

    // PointsStage (index 1)
    processor.stage(InternalCircuitIndex::PointsStage, source.rx(PointsStage))?;

    // PointsFinalStaged (index 2) - final stage check
    // Aggregates all EndoscalingStep rxs from all proofs
    {
        let final_rxs = (0..num_steps).flat_map(|step| source.rx(EndoscalingStep(step)));
        processor.stage(InternalCircuitIndex::PointsFinalStaged, final_rxs)?;
    }

    Ok(())
}

/// Trait for providing k(y) values for nested claim verification.
pub(crate) trait KySource {
    /// The k(y) value type.
    type Ky: Clone;

    /// Returns 1 for circuit checks.
    fn one(&self) -> Self::Ky;

    /// Returns 0 for stage checks.
    fn zero(&self) -> Self::Ky;
}

/// Build an iterator over k(y) values in nested claim order.
///
/// Returns:
/// - `num_steps` ones (for EndoscalingStep circuit checks, single-proof verification)
/// - Infinite zeros (for stage checks)
pub(crate) fn ky_values<S: KySource>(source: &S) -> impl Iterator<Item = S::Ky> {
    use crate::circuits::nested::NUM_ENDOSCALING_POINTS;
    use crate::components::endoscalar::NumStepsLen;
    use ragu_primitives::vec::Len;

    let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();

    // Circuit checks: k(y) = 1 (for single-proof, num_circuit_claims = num_steps)
    core::iter::repeat_n(source.one(), num_steps)
        // Stage checks: k(y) = 0 (infinite, matches how native does it)
        .chain(core::iter::repeat(source.zero()))
}
