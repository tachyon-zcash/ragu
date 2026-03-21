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

use super::{InternalCircuitIndex, RxComponent, RxIndex};
use crate::internal::claims::{Builder, Source, sum_polynomials};

/// Number of circuits using unified $k(y)$ in [`build`].
///
/// These circuits use [`unified::InternalOutputKind`]:
/// [`hashes_2`], [`inner_collapse`], [`outer_collapse`], [`compute_v`].
///
/// Note: [`hashes_1`] separately uses `unified_bridge_ky` because its public
/// inputs include child proof headers (see [`hashes_1::Output`]).
///
/// [`hashes_1`]: crate::internal::native::circuits::hashes_1
/// [`hashes_1::Output`]: crate::internal::native::circuits::hashes_1::Output
/// [`hashes_2`]: crate::internal::native::circuits::hashes_2
/// [`inner_collapse`]: crate::internal::native::circuits::inner_collapse
/// [`outer_collapse`]: crate::internal::native::circuits::outer_collapse
/// [`compute_v`]: crate::internal::native::circuits::compute_v
/// [`unified::InternalOutputKind`]: crate::internal::native::unified::InternalOutputKind
const NUM_UNIFIED_CIRCUITS: usize = 4;

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

    /// Process a bonding claim (fold of rxs, $k(y) = 0$).
    ///
    /// Returns `Result<()>` because evaluation context requires fallible fold operations.
    fn bonding(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>) -> Result<()>;
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

/// Build claims in unified interleaved order from a source.
///
/// The ordering is: for each claim type, add claims for all proofs before
/// moving to the next claim type. This produces an interleaved order:
/// `[L_raw, R_raw, L_app, R_app, L_h1, R_h1, ...]` for two-proof sources.
///
/// This ordering must match the $k(y)$ ordering in
/// [`inner_collapse`](crate::internal::native::circuits::inner_collapse)
/// and `compute_outer_error` in the fuse implementation.
pub fn build<S, P>(source: &S, processor: &mut P) -> Result<()>
where
    S: Source<RxComponent = RxComponent>,
    P: Processor<S::Rx, S::AppCircuitId>,
{
    use RxComponent::*;
    use RxIndex::*;

    // Raw claims (interleaved per proof)
    for (a, b) in source.rx(AbA).zip(source.rx(AbB)) {
        processor.raw_claim(a, b);
    }

    // App circuits (interleaved per proof)
    for (app_id, rx) in source.app_circuits().zip(source.rx(Rx(Application))) {
        processor.circuit(app_id, rx);
    }

    // Internal circuits and stages in canonical order.
    for &id in &InternalCircuitIndex::ALL {
        use InternalCircuitIndex::*;
        match id {
            // hashes_1: Hashes1 + Preamble + OuterError
            Hashes1Circuit => {
                for ((h1, pre), en) in source
                    .rx(Rx(Hashes1))
                    .zip(source.rx(Rx(Preamble)))
                    .zip(source.rx(Rx(OuterError)))
                {
                    processor.internal_circuit(id, [h1, pre, en].into_iter());
                }
            }

            // hashes_2: Hashes2 + OuterError
            Hashes2Circuit => {
                for (h2, en) in source.rx(Rx(Hashes2)).zip(source.rx(Rx(OuterError))) {
                    processor.internal_circuit(id, [h2, en].into_iter());
                }
            }

            // inner_collapse: InnerCollapse + Preamble + InnerError + OuterError
            InnerCollapseCircuit => {
                for (((pc, pre), em), en) in source
                    .rx(Rx(InnerCollapse))
                    .zip(source.rx(Rx(Preamble)))
                    .zip(source.rx(Rx(InnerError)))
                    .zip(source.rx(Rx(OuterError)))
                {
                    processor.internal_circuit(id, [pc, pre, em, en].into_iter());
                }
            }

            // outer_collapse: OuterCollapse + Preamble + OuterError
            OuterCollapseCircuit => {
                for ((fc, pre), en) in source
                    .rx(Rx(OuterCollapse))
                    .zip(source.rx(Rx(Preamble)))
                    .zip(source.rx(Rx(OuterError)))
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
                processor.bonding(id, source.rx(Rx(Preamble)))?;
            }
            InnerErrorStage => {
                processor.bonding(id, source.rx(Rx(InnerError)))?;
            }
            OuterErrorStage => {
                processor.bonding(id, source.rx(Rx(OuterError)))?;
            }
            QueryStage => {
                processor.bonding(id, source.rx(Rx(Query)))?;
            }
            EvalStage => {
                processor.bonding(id, source.rx(Rx(Eval)))?;
            }

            // Final stage masks
            InnerErrorFinalStaged => {
                processor.bonding(id, source.rx(Rx(InnerCollapse)))?;
            }
            OuterErrorFinalStaged => {
                processor.bonding(
                    id,
                    source
                        .rx(Rx(Hashes1))
                        .chain(source.rx(Rx(Hashes2)))
                        .chain(source.rx(Rx(OuterCollapse))),
                )?;
            }
            EvalFinalStaged => {
                processor.bonding(id, source.rx(Rx(ComputeV)))?;
            }
        }
    }

    Ok(())
}

/// Trait for providing $k(y)$ values for claim verification.
pub trait KySource {
    /// The $k(y)$ value type.
    type Ky: Clone;

    /// Iterator over raw_c values (the c from AB proof / preamble unified).
    fn raw_c(&self) -> impl Iterator<Item = Self::Ky>;

    /// Iterator over application circuit $k(y)$ values.
    fn application_ky(&self) -> impl Iterator<Item = Self::Ky>;

    /// Iterator over unified bridge $k(y)$ values.
    fn unified_bridge_ky(&self) -> impl Iterator<Item = Self::Ky>;

    /// Base iterator over unified $k(y)$ values.
    ///
    /// Will be repeated [`NUM_UNIFIED_CIRCUITS`] times.
    /// The `+ Clone` bound is required for `repeat_n` in [`ky_values`].
    fn unified_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone;

    /// The zero value for stage claims.
    fn zero(&self) -> Self::Ky;
}

/// Build an iterator over $k(y)$ values in claim order.
///
/// Chains the $k(y)$ sources in the order required by [`build`],
/// with `unified_ky` repeated [`NUM_UNIFIED_CIRCUITS`] times,
/// followed by infinite zeros for stage claims.
///
/// The `unified_ky` and `unified_bridge_ky` values are computed by
/// [`ProofInputs::unified_ky_values`](super::stages::preamble::ProofInputs::unified_ky_values)
/// via Horner evaluation of the circuit instance polynomial.
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

impl<'dr, D: Driver<'dr>> TwoProofKySource<'dr, D> {
    /// Create a [`TwoProofKySource`] from child k(y) outputs and raw c values.
    pub fn new(
        dr: &mut D,
        left_raw_c: Element<'dr, D>,
        right_raw_c: Element<'dr, D>,
        left_ky: &super::stages::outer_error::ChildKyOutputs<'dr, D>,
        right_ky: &super::stages::outer_error::ChildKyOutputs<'dr, D>,
    ) -> Self {
        Self {
            left_raw_c,
            right_raw_c,
            left_app: left_ky.application.clone(),
            right_app: right_ky.application.clone(),
            left_bridge: left_ky.unified_bridge.clone(),
            right_bridge: right_ky.unified_bridge.clone(),
            left_unified: left_ky.unified.clone(),
            right_unified: right_ky.unified.clone(),
            zero: Element::zero(dr),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::native::InternalCircuitIndex;
    use alloc::{vec, vec::Vec};

    /// Mock KySource using string labels to trace ordering.
    struct MockKySource;

    impl KySource for MockKySource {
        type Ky = &'static str;

        fn raw_c(&self) -> impl Iterator<Item = &'static str> {
            ["raw_c_L", "raw_c_R"].into_iter()
        }

        fn application_ky(&self) -> impl Iterator<Item = &'static str> {
            ["app_L", "app_R"].into_iter()
        }

        fn unified_bridge_ky(&self) -> impl Iterator<Item = &'static str> {
            ["bridge_L", "bridge_R"].into_iter()
        }

        fn unified_ky(&self) -> impl Iterator<Item = &'static str> + Clone {
            ["unified_L", "unified_R"].into_iter()
        }

        fn zero(&self) -> &'static str {
            "zero"
        }
    }

    /// Mock Source providing two proofs with tagged rx values.
    struct TwoProofSource;

    impl Source for TwoProofSource {
        type RxComponent = RxComponent;
        type Rx = (&'static str, usize);
        type AppCircuitId = usize;

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            let label = match component {
                RxComponent::AbA => "AbA",
                RxComponent::AbB => "AbB",
                RxComponent::Rx(RxIndex::Application) => "Application",
                RxComponent::Rx(RxIndex::Hashes1) => "Hashes1",
                RxComponent::Rx(RxIndex::Hashes2) => "Hashes2",
                RxComponent::Rx(RxIndex::InnerCollapse) => "InnerCollapse",
                RxComponent::Rx(RxIndex::OuterCollapse) => "OuterCollapse",
                RxComponent::Rx(RxIndex::ComputeV) => "ComputeV",
                RxComponent::Rx(RxIndex::Preamble) => "Preamble",
                RxComponent::Rx(RxIndex::InnerError) => "InnerError",
                RxComponent::Rx(RxIndex::OuterError) => "OuterError",
                RxComponent::Rx(RxIndex::Query) => "Query",
                RxComponent::Rx(RxIndex::Eval) => "Eval",
            };
            [(label, 0), (label, 1)].into_iter()
        }

        fn app_circuits(&self) -> impl Iterator<Item = usize> {
            [0, 1].into_iter()
        }
    }

    /// Recording processor that logs calls in order.
    #[derive(Default)]
    struct RecordingProcessor {
        calls: Vec<Call>,
    }

    /// A single recorded processor call for test assertions.
    struct Call {
        kind: &'static str,
        id: &'static str,
        rx_count: usize,
    }

    fn ici_name(id: InternalCircuitIndex) -> &'static str {
        match id {
            InternalCircuitIndex::PreambleStage => "PreambleStage",
            InternalCircuitIndex::InnerErrorStage => "InnerErrorStage",
            InternalCircuitIndex::OuterErrorStage => "OuterErrorStage",
            InternalCircuitIndex::QueryStage => "QueryStage",
            InternalCircuitIndex::EvalStage => "EvalStage",
            InternalCircuitIndex::InnerErrorFinalStaged => "InnerErrorFinalStaged",
            InternalCircuitIndex::OuterErrorFinalStaged => "OuterErrorFinalStaged",
            InternalCircuitIndex::EvalFinalStaged => "EvalFinalStaged",
            InternalCircuitIndex::Hashes1Circuit => "Hashes1Circuit",
            InternalCircuitIndex::Hashes2Circuit => "Hashes2Circuit",
            InternalCircuitIndex::InnerCollapseCircuit => "InnerCollapseCircuit",
            InternalCircuitIndex::OuterCollapseCircuit => "OuterCollapseCircuit",
            InternalCircuitIndex::ComputeVCircuit => "ComputeVCircuit",
        }
    }

    impl Processor<(&'static str, usize), usize> for RecordingProcessor {
        fn raw_claim(&mut self, _a: (&'static str, usize), _b: (&'static str, usize)) {
            self.calls.push(Call {
                kind: "raw",
                id: "raw",
                rx_count: 2,
            });
        }

        fn circuit(&mut self, _app_id: usize, _rx: (&'static str, usize)) {
            self.calls.push(Call {
                kind: "circuit",
                id: "app",
                rx_count: 1,
            });
        }

        fn internal_circuit(
            &mut self,
            id: InternalCircuitIndex,
            rxs: impl Iterator<Item = (&'static str, usize)>,
        ) {
            let rx_count = rxs.count();
            self.calls.push(Call {
                kind: "internal_circuit",
                id: ici_name(id),
                rx_count,
            });
        }

        fn stage(
            &mut self,
            id: InternalCircuitIndex,
            rxs: impl Iterator<Item = (&'static str, usize)>,
        ) -> Result<()> {
            let rx_count = rxs.count();
            self.calls.push(Call {
                kind: "stage",
                id: ici_name(id),
                rx_count,
            });
            Ok(())
        }
    }

    /// Issue #347: ky_values ordering matches build ordering.
    #[test]
    fn ky_values_ordering() {
        let values: Vec<&str> = ky_values(&MockKySource).take(22).collect();

        // 2 raw_c
        assert_eq!(&values[0..2], &["raw_c_L", "raw_c_R"]);
        // 2 app
        assert_eq!(&values[2..4], &["app_L", "app_R"]);
        // 2 bridge
        assert_eq!(&values[4..6], &["bridge_L", "bridge_R"]);
        // 8 unified (4 circuits * 2 proofs)
        for i in 0..NUM_UNIFIED_CIRCUITS {
            let base = 6 + i * 2;
            assert_eq!(values[base], "unified_L", "unified block {i} left");
            assert_eq!(values[base + 1], "unified_R", "unified block {i} right");
        }
        // Then zeros
        assert_eq!(values[14], "zero");
        assert_eq!(values[15], "zero");
    }

    /// Issue #347: build processes calls in the correct order.
    #[test]
    fn build_ordering() -> Result<()> {
        let source = TwoProofSource;
        let mut processor = RecordingProcessor::default();
        build(&source, &mut processor)?;

        let names: Vec<(&str, &str)> = processor.calls.iter().map(|c| (c.kind, c.id)).collect();

        // Expected order (2 proofs each):
        // 2 raw claims, 2 app circuits,
        // 2 hashes_1, 2 hashes_2, 2 inner_collapse, 2 outer_collapse, 2 compute_v,
        // 8 stages
        let expected: Vec<(&str, &str)> = vec![
            ("raw", "raw"),
            ("raw", "raw"),
            ("circuit", "app"),
            ("circuit", "app"),
            ("internal_circuit", "Hashes1Circuit"),
            ("internal_circuit", "Hashes1Circuit"),
            ("internal_circuit", "Hashes2Circuit"),
            ("internal_circuit", "Hashes2Circuit"),
            ("internal_circuit", "InnerCollapseCircuit"),
            ("internal_circuit", "InnerCollapseCircuit"),
            ("internal_circuit", "OuterCollapseCircuit"),
            ("internal_circuit", "OuterCollapseCircuit"),
            ("internal_circuit", "ComputeVCircuit"),
            ("internal_circuit", "ComputeVCircuit"),
            ("stage", "PreambleStage"),
            ("stage", "InnerErrorStage"),
            ("stage", "OuterErrorStage"),
            ("stage", "QueryStage"),
            ("stage", "EvalStage"),
            ("stage", "InnerErrorFinalStaged"),
            ("stage", "OuterErrorFinalStaged"),
            ("stage", "EvalFinalStaged"),
        ];

        assert_eq!(names, expected);
        Ok(())
    }

    /// Issue #347: internal circuit calls receive the correct rx count.
    #[test]
    fn internal_circuit_rx_counts() -> Result<()> {
        let source = TwoProofSource;
        let mut processor = RecordingProcessor::default();
        build(&source, &mut processor)?;

        // Filter to internal_circuit calls only
        let internal: Vec<(&str, usize)> = processor
            .calls
            .iter()
            .filter(|c| c.kind == "internal_circuit")
            .map(|c| (c.id, c.rx_count))
            .collect();

        // hashes_1: 3 rx each (Hashes1 + Preamble + ErrorN)
        assert_eq!(internal[0], ("Hashes1Circuit", 3));
        assert_eq!(internal[1], ("Hashes1Circuit", 3));
        // hashes_2: 2 rx each (Hashes2 + ErrorN)
        assert_eq!(internal[2], ("Hashes2Circuit", 2));
        assert_eq!(internal[3], ("Hashes2Circuit", 2));
        // inner_collapse: 4 rx each (IC + Preamble + InnerError + OuterError)
        assert_eq!(internal[4], ("InnerCollapseCircuit", 4));
        assert_eq!(internal[5], ("InnerCollapseCircuit", 4));
        // outer_collapse: 3 rx each (OC + Preamble + OuterError)
        assert_eq!(internal[6], ("OuterCollapseCircuit", 3));
        assert_eq!(internal[7], ("OuterCollapseCircuit", 3));
        // compute_v: 4 rx each (CV + Preamble + Query + Eval)
        assert_eq!(internal[8], ("ComputeVCircuit", 4));
        assert_eq!(internal[9], ("ComputeVCircuit", 4));
        Ok(())
    }
}
