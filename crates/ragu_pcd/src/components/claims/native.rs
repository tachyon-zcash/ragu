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
/// [`hashes_2`], [`partial_collapse`], [`full_collapse`], [`compute_v`].
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
/// [`unified::InternalOutputKind`]: crate::circuits::native::unified::InternalOutputKind
pub const NUM_UNIFIED_CIRCUITS: usize = 4;

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

    // Stages (aggregated: collect all proofs' rxs together)

    // ErrorMFinalStaged: only partial_collapse uses error_m as final stage
    processor.stage(
        InternalCircuitIndex::ErrorMFinalStaged,
        source.rx(PartialCollapse),
    )?;

    // ErrorNFinalStaged: hashes_1, hashes_2, full_collapse use error_n as final stage
    processor.stage(
        InternalCircuitIndex::ErrorNFinalStaged,
        source
            .rx(Hashes1)
            .chain(source.rx(Hashes2))
            .chain(source.rx(FullCollapse)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::native::InternalCircuitIndex;
    use alloc::vec::Vec;

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

    impl super::super::Source for TwoProofSource {
        type RxComponent = RxComponent;
        type Rx = (&'static str, usize);
        type AppCircuitId = usize;

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            let label = match component {
                RxComponent::AbA => "AbA",
                RxComponent::AbB => "AbB",
                RxComponent::Application => "Application",
                RxComponent::Hashes1 => "Hashes1",
                RxComponent::Hashes2 => "Hashes2",
                RxComponent::PartialCollapse => "PartialCollapse",
                RxComponent::FullCollapse => "FullCollapse",
                RxComponent::ComputeV => "ComputeV",
                RxComponent::Preamble => "Preamble",
                RxComponent::ErrorM => "ErrorM",
                RxComponent::ErrorN => "ErrorN",
                RxComponent::Query => "Query",
                RxComponent::Eval => "Eval",
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
            InternalCircuitIndex::ErrorMStage => "ErrorMStage",
            InternalCircuitIndex::ErrorNStage => "ErrorNStage",
            InternalCircuitIndex::QueryStage => "QueryStage",
            InternalCircuitIndex::EvalStage => "EvalStage",
            InternalCircuitIndex::ErrorMFinalStaged => "ErrorMFinalStaged",
            InternalCircuitIndex::ErrorNFinalStaged => "ErrorNFinalStaged",
            InternalCircuitIndex::EvalFinalStaged => "EvalFinalStaged",
            InternalCircuitIndex::Hashes1Circuit => "Hashes1Circuit",
            InternalCircuitIndex::Hashes2Circuit => "Hashes2Circuit",
            InternalCircuitIndex::PartialCollapseCircuit => "PartialCollapseCircuit",
            InternalCircuitIndex::FullCollapseCircuit => "FullCollapseCircuit",
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
        // 2 hashes_1, 2 hashes_2, 2 partial_collapse, 2 full_collapse, 2 compute_v,
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
            ("internal_circuit", "PartialCollapseCircuit"),
            ("internal_circuit", "PartialCollapseCircuit"),
            ("internal_circuit", "FullCollapseCircuit"),
            ("internal_circuit", "FullCollapseCircuit"),
            ("internal_circuit", "ComputeVCircuit"),
            ("internal_circuit", "ComputeVCircuit"),
            ("stage", "ErrorMFinalStaged"),
            ("stage", "ErrorNFinalStaged"),
            ("stage", "EvalFinalStaged"),
            ("stage", "PreambleStage"),
            ("stage", "ErrorMStage"),
            ("stage", "ErrorNStage"),
            ("stage", "QueryStage"),
            ("stage", "EvalStage"),
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
        // partial_collapse: 4 rx each (PC + Preamble + ErrorM + ErrorN)
        assert_eq!(internal[4], ("PartialCollapseCircuit", 4));
        assert_eq!(internal[5], ("PartialCollapseCircuit", 4));
        // full_collapse: 3 rx each (FC + Preamble + ErrorN)
        assert_eq!(internal[6], ("FullCollapseCircuit", 3));
        assert_eq!(internal[7], ("FullCollapseCircuit", 3));
        // compute_v: 4 rx each (CV + Preamble + Query + Eval)
        assert_eq!(internal[8], ("ComputeVCircuit", 4));
        assert_eq!(internal[9], ("ComputeVCircuit", 4));
        Ok(())
    }
}
