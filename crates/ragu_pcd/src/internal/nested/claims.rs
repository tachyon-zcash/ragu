//! Claim orchestration for nested field (scalar field) rx polynomials.
//!
//! This module provides a unified interface for assembling `a` and `b`
//! polynomial vectors for nested field revdot claim verification.
//!
//! The nested claim structure is simpler than native:
//! - Circuit checks ([`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)): $k(y) = 1$
//! - Bonding checks ([`EndoscalarStage`](InternalCircuitIndex::EndoscalarStage),
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

    /// Process a bonding claim - aggregates rxs from all proofs.
    fn bonding(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>) -> Result<()>;
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

    fn bonding(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) -> Result<()> {
        let circuit_id = id.circuit_index();
        let folded = self.fold_bonding_polys(rxs);
        self.bonding_impl(circuit_id, folded);
        Ok(())
    }
}

/// Build nested claims in unified interleaved order from a source.
///
/// The ordering is:
/// 1. Circuit checks ($k(y) = 1$): [`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)
///    for each step, interleaved across proofs
/// 2. Bonding checks ($k(y) = 0$): [`EndoscalarStage`](InternalCircuitIndex::EndoscalarStage),
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
                processor.bonding(id, source.rx(RxIndex::EndoscalarStage))?;
            }
            PointsStage => {
                processor.bonding(id, source.rx(RxIndex::PointsStage))?;
            }
            PointsFinalStaged => {
                let num_steps = super::NUM_ENDOSCALING_STEPS;
                let final_rxs = (0..num_steps)
                    .flat_map(|step| source.rx(RxIndex::EndoscalingStep(step as u32)));
                processor.bonding(id, final_rxs)?;
            }
            BridgePreamble => {
                processor.bonding(id, source.rx(RxIndex::BridgePreamble))?;
            }
            BridgeSPrime => {
                processor.bonding(id, source.rx(RxIndex::BridgeSPrime))?;
            }
            BridgeInnerError => {
                processor.bonding(id, source.rx(RxIndex::BridgeInnerError))?;
            }
            BridgeOuterError => {
                processor.bonding(id, source.rx(RxIndex::BridgeOuterError))?;
            }
            BridgeAB => {
                processor.bonding(id, source.rx(RxIndex::BridgeAB))?;
            }
            BridgeQuery => {
                processor.bonding(id, source.rx(RxIndex::BridgeQuery))?;
            }
            BridgeF => {
                processor.bonding(id, source.rx(RxIndex::BridgeF))?;
            }
            BridgeEval => {
                processor.bonding(id, source.rx(RxIndex::BridgeEval))?;
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
        // Bonding checks: k(y) = 0 (infinite, matches how native does it)
        .chain(core::iter::repeat(source.zero()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::endoscalar::NumStepsLen;
    use crate::internal::nested::{InternalCircuitIndex, NUM_ENDOSCALING_POINTS};
    use alloc::vec::Vec;
    use ragu_primitives::vec::Len;

    /// Mock KySource that returns u32 values (1 and 0).
    struct MockKySource;

    impl KySource for MockKySource {
        type Ky = u32;
        fn one(&self) -> u32 {
            1
        }
        fn zero(&self) -> u32 {
            0
        }
    }

    /// Mock Source providing a single proof with unique rx tags.
    struct SingleProofSource;

    impl Source for SingleProofSource {
        type RxComponent = RxIndex;
        type Rx = (RxIndex, usize);
        type AppCircuitId = ();

        fn rx(&self, component: RxIndex) -> impl Iterator<Item = Self::Rx> {
            core::iter::once((component, 0))
        }

        fn app_circuits(&self) -> impl Iterator<Item = ()> {
            core::iter::empty()
        }
    }

    /// Recording processor that logs calls in order.
    #[derive(Default)]
    struct RecordingProcessor {
        /// (call_type, circuit_id_variant, rx_count)
        calls: Vec<(&'static str, &'static str, usize)>,
    }

    impl Processor<(RxIndex, usize)> for RecordingProcessor {
        fn internal_circuit(
            &mut self,
            id: InternalCircuitIndex,
            rxs: impl Iterator<Item = (RxIndex, usize)>,
        ) {
            let rx_count = rxs.count();
            let name = match id {
                InternalCircuitIndex::EndoscalingStep(_) => "EndoscalingStep",
                InternalCircuitIndex::EndoscalarStage => "EndoscalarStage",
                InternalCircuitIndex::PointsStage => "PointsStage",
                InternalCircuitIndex::PointsFinalStaged => "PointsFinalStaged",
                InternalCircuitIndex::BridgePreamble => "BridgePreamble",
                InternalCircuitIndex::BridgeSPrime => "BridgeSPrime",
                InternalCircuitIndex::BridgeInnerError => "BridgeInnerError",
                InternalCircuitIndex::BridgeOuterError => "BridgeOuterError",
                InternalCircuitIndex::BridgeAB => "BridgeAB",
                InternalCircuitIndex::BridgeQuery => "BridgeQuery",
                InternalCircuitIndex::BridgeF => "BridgeF",
                InternalCircuitIndex::BridgeEval => "BridgeEval",
            };
            self.calls.push(("circuit", name, rx_count));
        }

        fn stage(
            &mut self,
            id: InternalCircuitIndex,
            rxs: impl Iterator<Item = (RxIndex, usize)>,
        ) -> Result<()> {
            let rx_count = rxs.count();
            let name = match id {
                InternalCircuitIndex::EndoscalingStep(_) => "EndoscalingStep",
                InternalCircuitIndex::EndoscalarStage => "EndoscalarStage",
                InternalCircuitIndex::PointsStage => "PointsStage",
                InternalCircuitIndex::PointsFinalStaged => "PointsFinalStaged",
                InternalCircuitIndex::BridgePreamble => "BridgePreamble",
                InternalCircuitIndex::BridgeSPrime => "BridgeSPrime",
                InternalCircuitIndex::BridgeInnerError => "BridgeInnerError",
                InternalCircuitIndex::BridgeOuterError => "BridgeOuterError",
                InternalCircuitIndex::BridgeAB => "BridgeAB",
                InternalCircuitIndex::BridgeQuery => "BridgeQuery",
                InternalCircuitIndex::BridgeF => "BridgeF",
                InternalCircuitIndex::BridgeEval => "BridgeEval",
            };
            self.calls.push(("stage", name, rx_count));
            Ok(())
        }
    }

    /// Issue #347: ky_values produces num_steps ones then zeros.
    #[test]
    fn ky_values_ones_then_zeros() {
        let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();
        let values: Vec<u32> = ky_values(&MockKySource).take(num_steps + 10).collect();

        // First num_steps values should be 1
        for (i, &v) in values[..num_steps].iter().enumerate() {
            assert_eq!(v, 1, "ky_values[{i}] should be 1 (circuit check)");
        }
        // Remaining should be 0
        for (i, &v) in values[num_steps..].iter().enumerate() {
            assert_eq!(
                v,
                0,
                "ky_values[{}] should be 0 (stage check)",
                num_steps + i
            );
        }
    }

    /// Issue #347: build processes num_steps circuit calls then 3 stage calls.
    #[test]
    fn build_ordering() -> Result<()> {
        let source = SingleProofSource;
        let mut processor = RecordingProcessor::default();
        build(&source, &mut processor)?;

        let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();

        // First num_steps calls should be circuit calls (EndoscalingStep)
        for call in &processor.calls[..num_steps] {
            assert_eq!(call.0, "circuit");
            assert_eq!(call.1, "EndoscalingStep");
        }

        // Next 11 calls should be stage calls (3 original + 8 bridge)
        assert_eq!(processor.calls[num_steps], ("stage", "EndoscalarStage", 1));
        assert_eq!(processor.calls[num_steps + 1], ("stage", "PointsStage", 1));
        assert_eq!(
            processor.calls[num_steps + 2],
            ("stage", "PointsFinalStaged", num_steps),
            "third stage is PointsFinalStaged"
        );
        assert_eq!(
            processor.calls[num_steps + 3],
            ("stage", "BridgePreamble", 1)
        );
        assert_eq!(processor.calls[num_steps + 4], ("stage", "BridgeSPrime", 1));
        assert_eq!(
            processor.calls[num_steps + 5],
            ("stage", "BridgeInnerError", 1)
        );
        assert_eq!(
            processor.calls[num_steps + 6],
            ("stage", "BridgeOuterError", 1)
        );
        assert_eq!(processor.calls[num_steps + 7], ("stage", "BridgeAB", 1));
        assert_eq!(processor.calls[num_steps + 8], ("stage", "BridgeQuery", 1));
        assert_eq!(processor.calls[num_steps + 9], ("stage", "BridgeF", 1));
        assert_eq!(processor.calls[num_steps + 10], ("stage", "BridgeEval", 1));

        // Total calls: num_steps circuits + 11 stages
        assert_eq!(processor.calls.len(), num_steps + 11);
        Ok(())
    }

    /// Issue #347: each EndoscalingStep circuit call receives 3 rx values.
    #[test]
    fn build_circuit_rx_components() -> Result<()> {
        let source = SingleProofSource;
        let mut processor = RecordingProcessor::default();
        build(&source, &mut processor)?;

        let num_steps = NumStepsLen::<NUM_ENDOSCALING_POINTS>::len();

        // Each circuit call should have 3 rx values (step + endo + points)
        for (i, call) in processor.calls[..num_steps].iter().enumerate() {
            assert_eq!(
                call.2, 3,
                "EndoscalingStep circuit call {i} should have 3 rx values"
            );
        }
        Ok(())
    }
}
