//! The patcher's soundness oracle aimed at the **production internal
//! recursion circuits**.
//!
//! Every other patcher target hunts under-constrained advice in *generated*
//! substrate programs. This one hunts it in the circuits that actually carry
//! ragu's recursion — the native `hashes_1`, `hashes_2`, `collapse` and
//! `compute_v`, and the nested endoscaling steps — by
//! capturing them from real fuses and then playing a malicious prover
//! against the constraints they emitted.
//!
//! # Setup, paid once
//!
//! The circuits' honest witnesses exist only mid-fuse, so
//! [`capture_internal_circuits`] runs real fuses and hands each
//! circuit, its [`CircuitSpec`] and its witness to a visitor that records the
//! constraint graph ([`ragu_testing::patcher::capture_with_stage_values`]). It
//! does so at four [`Point`]s of a tree, because the cheap ones are degenerate
//! in their own ways — the bootstrap base case consumes synthesized dummies
//! and leaves `collapse`'s `c` free, while two children of equal depth
//! make the two sides of a collapse mirror images — and no single point is
//! representative.
//!
//! The points differ in more than shape. Each builds from its own RNG seed and,
//! when applicable, its own leaf witnesses, so the four captures are not four
//! views of the same field elements. And the base case runs in an application
//! registering one step rather than two or three. That puts the registry at
//! $2^4$ circuits instead of $2^5$ — a different width for `compute_v` to
//! evaluate over, not just a different tree.
//!
//! That costs some tens of seconds and happens once, in libFuzzer's `init`;
//! every fuzz iteration afterwards works on the captured graphs through a
//! [`Prepared`] probe, which solved the part of each witness the inputs force
//! once and only re-solves what a cheat can still change.
//! Each captured honest witness is replayed through fresh synthesis during
//! initialization, using the same checks as the PR regression suite.
//!
//! # The oracle
//!
//! A circuit's spec declares what it is responsible for: the unified instance
//! slots it covers and the stage values it checks (see
//! [`ragu_pcd::fuzzing::patcher`]). Those are its **outputs**; every other instance
//! wire and every other reserved stage wire is an **input** — received
//! commitments, challenges another circuit derived, stage values another
//! circuit checks. Before any fuzzing, witness-free
//! [`analyze_source_shape`](ragu_testing_fuzz::source_shape::analyze_source_shape) must
//! match concrete synthesis exactly; connectivity analysis rejects isolated wires and
//! floating subgraphs; bounded component-local Jacobian checks reject movable
//! derived wires and require non-vacuous rank coverage; and
//! [`forced_by`](ragu_testing::patcher::forced_by) runs twice. Granting the
//! inputs and every other free wire except the outputs, it must derive every
//! output — one it cannot reach is an output the circuit never constrains, a
//! finding in itself, and the harness refuses to start; it also reports how
//! many outputs the inputs *alone* force. Components too large for dense rank
//! elimination are explicitly reported as skipped by the analysis API rather
//! than certified.
//!
//! Then: pin the inputs, let the prover rewrite any other free advice —
//! Poseidon hints, allocator slack, the outputs themselves — and repair the
//! rest of the witness through the captured constraints. If every constraint
//! still holds while an **output** moved, the circuit accepts two witnesses
//! that agree on everything it received and disagree on something it is
//! responsible for. For the hash circuits that is a Fiat–Shamir binding
//! break; for the collapse circuits, a folded claim the prover can choose;
//! for an endoscaling step, an accumulator the prover can steer. Either way
//! it is a soundness bug, and the accepting witness is the evidence.
//!
//! A repaired witness the constraints *reject* is inconclusive — the solver
//! is deliberately bounded — and is never a signal.
//!
//! # The accepting witness is replayed before it is believed
//!
//! Everything above is judged against the *recorded* graph. A capture that
//! drifted from what ragu really synthesizes would produce a verdict about a
//! circuit that does not exist, and the recording path — a stage overlay, a
//! recorder allocation order — is exactly the sort of thing that drifts as the
//! production code moves. So a signal is not reported on the strength of the
//! recording alone. The accepting witness is injected back into a **fresh
//! synthesis of the same circuit** through
//! [`playback`](ragu_testing::patcher::playback), which re-runs the real
//! gadget code and checks every gate, `C · D = 0`, linear definition and
//! `enforce_zero` against the injected values — and that the synthesis
//! consumed exactly the wires the witness names. Only a witness fresh
//! synthesis also accepts is called soundness evidence.
//!
//! A witness the replay *rejects* is a finding of a different kind — the
//! capture and the circuit disagree, so every verdict this target has produced
//! about that circuit is unsound in both directions — and is reported as such
//! rather than quietly dropped. Replaying rebuilds the capture point from its
//! seed and costs seconds, which is why it happens only once a probe has
//! already fired.
//!
//! What the replay does *not* cover: `capture_internal_circuits_at` reproduces
//! `fuse`'s witness generation by mirroring it — the same challenges squeezed
//! from the same transcript in the same order — and the replay re-runs that
//! same path, so a mirror that has drifted from `fuse` is reproduced faithfully
//! rather than caught. The structural half of that drift (a circuit added to
//! the recursion and forgotten here, or one whose wire counts moved) is pinned
//! by the census in `qa/fuzz/src/internal_patcher_regression.rs`. Value-level drift —
//! the mirror deriving a *different* honest witness than a real fuse would —
//! is not checked anywhere yet, and wants the two paths sharing one
//! implementation rather than another test.

#![no_main]

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ragu_circuits::Circuit;
// The fields must come from the cycle's own dependency graph: the fuzz
// crate's direct `pasta_curves` is a distinct instance and would not unify
// with `<Pasta as Cycle>::CircuitField`.
use ragu_core::pasta::Pasta;
use ragu_core::{Cycle, Result};
use ragu_pcd::fuzzing::patcher::{CircuitSpec, InternalCircuitVisitor};
use ragu_testing::patcher::{Prepared, playback};
use ragu_testing_fuzz::{
    internal_patcher::{Mutation, Point, capture_checked, check_binding, probe_mutations},
    patcher_analysis::{analyze_component_rank, analyze_connectivity},
    source_shape::analyze_source_shape,
};
use udon::field::Field;

type NativeField = <Pasta as Cycle>::CircuitField;
type NestedField = <Pasta as Cycle>::ScalarField;
type CircuitSelector = u16;

/// One captured internal circuit, ready to probe.
struct Captured<F> {
    /// The circuit's own name, as its [`CircuitSpec`] gives it — what a
    /// replay matches on.
    spec: String,
    /// Where it was captured, so a replay can rebuild exactly that tree.
    point: Point,
    /// The capture with the input-forced part of its witness solved once.
    prepared: Prepared<F>,
    /// Free advice outside the inputs — the wires a cheat may rewrite.
    cheatable: Vec<usize>,
}

impl<F> Captured<F> {
    /// A name for diagnostics.
    fn name(&self) -> String {
        format!("{}@{}", self.spec, self.point.name())
    }
}

/// Captures one circuit, checks its spec statically, and classifies its
/// wires.
fn collect<'w, F: Field, Cir: Circuit<F>>(
    point: Point,
    spec: &CircuitSpec,
    circuit: &Cir,
    stage_values: &[F],
    make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
) -> Result<Captured<F>> {
    let name = format!("{}@{}", spec.name, point.name());
    let source_shape = analyze_source_shape(circuit)?;
    let (cap, resolution) = capture_checked(&name, spec, circuit, stage_values, make_witness)?;

    let source = source_shape.compare(&cap);
    assert!(
        source.is_clean(),
        "{name}: witness-free source shape disagrees with concrete synthesis: {source:?}",
    );

    // The static half: granting the inputs and every other free wire except
    // the outputs, the solver must force every output — else the circuit
    // never constrains it and no cheat can tell us anything about it.
    // Whether the inputs *alone* force it is reported.
    let binding = check_binding(&name, &cap, &resolution);
    let free = binding.free;
    let strongly_forced = binding.strongly_forced;
    let connectivity = analyze_connectivity(
        &cap.recorder.events,
        cap.recorder.values.len(),
        &resolution.inputs,
        &resolution.outputs,
    );
    assert!(
        connectivity.isolated_wires().is_empty(),
        "{name}: synthesized wires are absent from every constraint subgraph: {:?}",
        connectivity.isolated_wires(),
    );
    assert!(
        connectivity.floating_components().is_empty(),
        "{name}: constraint subgraphs reach no input, output, or fixed constant: {:?}",
        connectivity.floating_components(),
    );
    assert!(
        connectivity.output_components_without_inputs().is_empty(),
        "{name}: output subgraphs have no declared input path: {:?}",
        connectivity.output_components_without_inputs(),
    );
    let rank = analyze_component_rank(
        &cap.recorder.events,
        &cap.recorder.values,
        &free,
        &connectivity,
        384,
    );
    assert!(
        rank.checked_derived_wires > 0,
        "{name}: bounded component rank check covered no derived wire: {rank:?}",
    );
    assert!(
        rank.movable.is_empty(),
        "{name}: bounded component rank check found movable derived wires: {rank:?}",
    );
    let cheatable: Vec<usize> = free
        .iter()
        .copied()
        .filter(|w| !resolution.inputs.contains(w))
        .collect();
    let prepared = Prepared::new(
        cap.recorder.events,
        cap.recorder.values,
        resolution.inputs,
        resolution.outputs,
    );
    let (residual, total) = prepared.residual_events();
    eprintln!(
        "{name}: {} wires, {} inputs pinned, {} outputs watched ({strongly_forced} forced by \
         the inputs alone), {} cheatable, {residual} of {total} events solved per probe; rank \
         checked {} derived wires in {} components and skipped {} wires in {} oversized \
         components",
        prepared.honest().len(),
        prepared.inputs().len(),
        prepared.outputs().len(),
        cheatable.len(),
        rank.checked_derived_wires,
        rank.checked_components,
        rank.skipped_derived_wires,
        rank.skipped_components,
    );

    Ok(Captured {
        spec: spec.name.clone(),
        point,
        prepared,
        cheatable,
    })
}

/// The captured circuits of every visited point, by field.
struct Collector<N, S> {
    point: Point,
    native: Vec<Captured<N>>,
    nested: Vec<Captured<S>>,
}

// The fields are written as the cycle's own associated types so the methods'
// bounds match the trait's verbatim; spelling them `Fp` / `Fq` makes rustc
// reject the impl as having stricter requirements.
impl<C: Cycle> InternalCircuitVisitor<C> for Collector<C::CircuitField, C::ScalarField> {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        let captured = collect(self.point, spec, circuit, stage_values, make_witness)?;
        self.native.push(captured);
        Ok(())
    }

    fn visit_nested<'w, Cir: Circuit<C::ScalarField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::ScalarField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        let captured = collect(self.point, spec, circuit, stage_values, make_witness)?;
        self.nested.push(captured);
        Ok(())
    }
}

/// The captured circuits, built from real fuses on first use.
static CIRCUITS: LazyLock<Collector<NativeField, NestedField>> = LazyLock::new(|| {
    let mut collector = Collector {
        point: Point::Bootstrap,
        native: Vec::new(),
        nested: Vec::new(),
    };
    for point in Point::ALL {
        collector.point = point;
        point.capture(&mut collector).unwrap_or_else(|e| {
            panic!(
                "capturing the internal circuits at the {} point must succeed: {e:?}",
                point.name(),
            )
        });
    }
    let total = collector.native.len() + collector.nested.len();
    assert!(
        total <= usize::from(CircuitSelector::MAX) + 1,
        "the circuit selector must reach all {total} captured circuits",
    );
    collector
});

/// Replays one accepting witness through a fresh synthesis of the circuit it
/// came from.
///
/// Only one of the two witness slots is ever filled: a capture is taken in one
/// field, and the witness a probe returns is already indexed by recorder wire
/// in that field.
struct Replay<'w, N, S> {
    /// The [`CircuitSpec::name`] of the circuit to play back.
    spec: &'w str,
    /// The witness, when the circuit is a native one.
    native: Option<&'w [N]>,
    /// The witness, when the circuit is a nested one.
    nested: Option<&'w [S]>,
    /// Whether fresh synthesis accepted it; `None` until the circuit is
    /// reached.
    verdict: Option<bool>,
}

// As with `Collector`, the fields are written as the cycle's own associated
// types: rustc does not normalize `<Pasta as Cycle>::CircuitField` to `Fp` in
// an impl signature, and spelling it `Fp` makes the impl look stricter than
// the trait.
impl<C: Cycle> InternalCircuitVisitor<C> for Replay<'_, C::CircuitField, C::ScalarField> {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        _stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if let (Some(values), true) = (self.native, spec.name == self.spec) {
            self.verdict = Some(playback(circuit, make_witness()?, values.to_vec())?);
        }
        Ok(())
    }

    fn visit_nested<'w, Cir: Circuit<C::ScalarField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        _stage_values: &[C::ScalarField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if let (Some(values), true) = (self.nested, spec.name == self.spec) {
            self.verdict = Some(playback(circuit, make_witness()?, values.to_vec())?);
        }
        Ok(())
    }
}

/// Rebuilds `point`'s tree and plays `native` or `nested` back through a fresh
/// synthesis of the circuit named `spec`.
///
/// `None` means the circuit was never reached, which can only happen if the
/// capture point stopped being reproducible from its seed.
fn replay(
    point: Point,
    spec: &str,
    native: Option<&[NativeField]>,
    nested: Option<&[NestedField]>,
) -> Option<bool> {
    let mut visitor: Replay<'_, NativeField, NestedField> = Replay {
        spec,
        native,
        nested,
        verdict: None,
    };
    point
        .capture(&mut visitor)
        .expect("replaying a capture point must succeed — it succeeded once already");
    visitor.verdict
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// Which captured circuit to probe (modulo the count, native first).
    circuit: CircuitSelector,
    /// Coordinated cheats: `(wire index mod cheatable count, mutation)`.
    cheats: Vec<(u16, Mutation)>,
}

// The captures are paid for in `init`, before libFuzzer starts timing units,
// so the first input is not reported as a slow unit and written to
// `artifacts/`.
fuzz_target!(
    init: {
        if std::env::var("DEBUG_INPUT").is_err() {
            LazyLock::force(&CIRCUITS);
        }
    },
    |input: Input| {
        if std::env::var("DEBUG_INPUT").is_ok() {
            eprintln!("{input:#?}");
            return;
        }
        let circuits: &Collector<NativeField, NestedField> = &CIRCUITS;
        let total = circuits.native.len() + circuits.nested.len();
        if total == 0 {
            return;
        }
        let index = usize::from(input.circuit) % total;
        if index < circuits.native.len() {
            let circuit = &circuits.native[index];
            probe(circuit, &input, |witness| {
                replay(circuit.point, &circuit.spec, Some(witness), None)
            });
        } else {
            let circuit = &circuits.nested[index - circuits.native.len()];
            probe(circuit, &input, |witness| {
                replay(circuit.point, &circuit.spec, None, Some(witness))
            });
        }
    }
);

/// One fuzz iteration: resolve the cheats onto the captured circuit and
/// probe.
fn probe<F: Field>(circuit: &Captured<F>, input: &Input, replay: impl Fn(&[F]) -> Option<bool>) {
    probe_mutations(
        &circuit.name(),
        &circuit.prepared,
        &circuit.cheatable,
        &input.cheats,
        replay,
    );
}
