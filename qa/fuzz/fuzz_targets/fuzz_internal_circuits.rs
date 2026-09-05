//! The patcher's soundness oracle aimed at the **production internal
//! recursion circuits**.
//!
//! Every other patcher target hunts under-constrained advice in *generated*
//! substrate programs. This one hunts it in the circuits that actually carry
//! ragu's recursion — the native `hashes_1`, `hashes_2`, `inner_collapse`,
//! `outer_collapse` and `compute_v`, and the nested endoscaling steps — by
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
//! and leaves `outer_collapse`'s `c` free, while two children of equal depth
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
//! by the census in `ragu_pcd`'s `patcher_internal` test. Value-level drift —
//! the mirror deriving a *different* honest witness than a real fuse would —
//! is not checked anywhere yet, and wants the two paths sharing one
//! implementation rather than another test.

#![no_main]

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ragu_arithmetic::{Cycle, ff::PrimeFieldBits};
use ragu_circuits::Circuit;
use ragu_core::Result;
// The fields must come from the cycle's own dependency graph: the fuzz
// crate's direct `pasta_curves` is a distinct instance and would not unify
// with `<Pasta as Cycle>::CircuitField`.
use ragu_pasta::Pasta;
use ragu_pcd::{
    Application,
    fuzzing::patcher::{
        CircuitSpec, InternalCircuitVisitor, capture_internal_circuits,
        capture_internal_circuits_bootstrap,
    },
};
use ragu_testing::patcher::{
    Prepared, ProbeOutcome, capture_with_stage_values, discover_free_advice, forced_by, playback,
};
use ragu_testing_fuzz::{
    patcher_analysis::{analyze_component_rank, analyze_connectivity},
    pcd::{self, HEADER_SIZE, R, SyncApp},
    source_shape::analyze_source_shape,
};
use rand::{SeedableRng, rngs::StdRng};

type NativeField = <Pasta as Cycle>::CircuitField;
type NestedField = <Pasta as Cycle>::ScalarField;
type App = Application<'static, Pasta, R, HEADER_SIZE>;

/// The applications the capture points run in, indexed by how many steps they
/// register.
///
/// The base case runs in the one-step application on purpose: with one
/// registered step the registry rounds to $16$ circuits and with two or three
/// to $32$, so that point is not only a different fuse but a different
/// registry width.
static APPS: LazyLock<[SyncApp; 3]> = LazyLock::new(|| {
    [
        pcd::nontrivial_app(1),
        pcd::nontrivial_app(2),
        pcd::nontrivial_app(3),
    ]
});

/// Where in a proof tree the internal circuits are captured.
///
/// A point is a pure function of itself: it builds its own children from its
/// own seed and its own witnesses, so [`Point::capture`] can be run again
/// later and see the same circuits with the same honest witnesses. The replay
/// depends on that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    /// The base case: the internal bootstrap step over two synthesized dummy
    /// children, in the one-step application.
    Bootstrap,
    /// A `Hash2` fuse of two seeded leaves.
    Leaves,
    /// A `Merge2` fuse of two `Hash2` nodes: the first point whose children
    /// carry accumulators of their own.
    Nodes,
    /// A `Merge2` fuse of a `Merge2` node with a `Hash2` node. The two sides
    /// are of unequal depth, so the collapse circuits fold two accumulators
    /// that are not each other's mirror image.
    Lopsided,
}

impl Point {
    const ALL: [Point; 4] = [
        Point::Bootstrap,
        Point::Leaves,
        Point::Nodes,
        Point::Lopsided,
    ];

    fn name(self) -> &'static str {
        match self {
            Point::Bootstrap => "bootstrap",
            Point::Leaves => "leaves",
            Point::Nodes => "nodes",
            Point::Lopsided => "lopsided",
        }
    }

    /// How many steps the application this point runs in registers.
    fn steps(self) -> usize {
        match self {
            Point::Bootstrap => 1,
            Point::Leaves => 2,
            Point::Nodes | Point::Lopsided => 3,
        }
    }

    /// The RNG seed every proof of this point is built from — distinct per
    /// point, so no two points share their blinding.
    fn rng_seed(self) -> u64 {
        match self {
            Point::Bootstrap => 0x5eed_0001,
            Point::Leaves => 0x1eaf_0002,
            Point::Nodes => 0x0de0_0003,
            Point::Lopsided => 0x109d_0004,
        }
    }

    /// The leaf witnesses this point seeds from — empty for the bootstrap.
    fn witnesses(self) -> &'static [u64] {
        match self {
            Point::Bootstrap => &[],
            Point::Leaves => &[3, 5],
            Point::Nodes => &[7, 11, 13, 17],
            Point::Lopsided => &[19, 23, 29, 31, 37, 41],
        }
    }

    fn app(self) -> &'static App {
        &APPS[self.steps() - 1].0
    }

    /// Builds this point's tree and hands every internal circuit of its final
    /// fuse to `visitor`.
    fn capture<V: InternalCircuitVisitor<Pasta>>(self, visitor: &mut V) -> Result<()> {
        let app = self.app();
        let mut rng = StdRng::seed_from_u64(self.rng_seed());
        let w = self.witnesses();
        match self {
            Point::Bootstrap => capture_internal_circuits_bootstrap(app, &mut rng, visitor),
            Point::Leaves => {
                let left = pcd::seed(app, &mut rng, w[0]);
                let right = pcd::seed(app, &mut rng, w[1]);
                capture_internal_circuits(app, &mut rng, pcd::hash2(), (), left, right, visitor)
            }
            Point::Nodes => {
                let left = pcd::node(app, &mut rng, w[0], w[1]);
                let right = pcd::node(app, &mut rng, w[2], w[3]);
                capture_internal_circuits(app, &mut rng, pcd::merge2(), (), left, right, visitor)
            }
            Point::Lopsided => {
                let ll = pcd::node(app, &mut rng, w[0], w[1]);
                let lr = pcd::node(app, &mut rng, w[2], w[3]);
                let deep = app.fuse(&mut rng, pcd::merge2(), (), ll, lr)?.0;
                let shallow = pcd::node(app, &mut rng, w[4], w[5]);
                capture_internal_circuits(app, &mut rng, pcd::merge2(), (), deep, shallow, visitor)
            }
        }
    }
}

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
fn collect<'w, F: PrimeFieldBits, Cir: Circuit<F>>(
    point: Point,
    spec: &CircuitSpec,
    circuit: &Cir,
    stage_values: &[F],
    make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
) -> Result<Captured<F>> {
    let name = format!("{}@{}", spec.name, point.name());
    let source_shape = analyze_source_shape(circuit)?;
    let cap = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
    let resolution = spec.resolve(&cap.instance, &cap.stage_wires)?;
    assert!(
        !resolution.outputs.is_empty(),
        "{name}: nothing to watch — the oracle would be vacuous here",
    );

    let source = source_shape.compare(&cap);
    assert!(
        source.is_clean(),
        "{name}: witness-free source shape disagrees with concrete synthesis: {source:?}",
    );

    // The static half: granting the inputs and every other free wire except
    // the outputs, the solver must force every output — else the circuit
    // never constrains it and no cheat can tell us anything about it.
    // Whether the inputs *alone* force it is reported.
    let free = discover_free_advice(&cap.recorder.events, &cap.recorder.values);
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
    let mut granted = resolution.inputs.clone();
    granted.extend(
        free.iter()
            .copied()
            .filter(|w| !resolution.outputs.contains(w)),
    );
    let weakly = forced_by(&cap.recorder.events, &cap.recorder.values, &granted);
    let unforced: Vec<usize> = resolution
        .outputs
        .iter()
        .copied()
        .filter(|w| weakly.binary_search(w).is_err())
        .collect();
    assert!(
        unforced.is_empty(),
        "{name}: declared outputs {unforced:?} are not forced even with every hint \
         granted — the circuit never constrains them; fix before fuzzing",
    );
    let strongly = forced_by(
        &cap.recorder.events,
        &cap.recorder.values,
        &resolution.inputs,
    );
    let strongly_forced = resolution
        .outputs
        .iter()
        .filter(|w| strongly.binary_search(w).is_ok())
        .count();

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

/// How a cheat rewrites its target wire, mirroring the corner cases
/// `fuzz_advice_patcher` found productive.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Mutation {
    /// `v + δ` for a small delta.
    AddSmall(u64),
    /// `v · m`.
    MulSmall(u64),
    /// `−v`.
    Negate,
    /// Zero — the corner case gadget hints most often mishandle.
    Zero,
    /// Copy another cheatable wire's honest value: the probe for a missing
    /// copy constraint.
    CopyFrom(u16),
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// Which captured circuit to probe (modulo the count, native first).
    circuit: u8,
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
        let index = input.circuit as usize % total;
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
fn probe<F: PrimeFieldBits>(
    circuit: &Captured<F>,
    input: &Input,
    replay: impl Fn(&[F]) -> Option<bool>,
) {
    if circuit.cheatable.is_empty() {
        return;
    }
    let honest = circuit.prepared.honest();

    // Resolve the cheats onto distinct wires, each nudged off its honest
    // value so every cheat does real work.
    let mut cheats: Vec<(usize, F)> = Vec::new();
    for (raw, mutation) in input.cheats.iter().take(8) {
        let wire = circuit.cheatable[*raw as usize % circuit.cheatable.len()];
        if cheats.iter().any(|(w, _)| *w == wire) {
            continue;
        }
        let mut value = match mutation {
            Mutation::AddSmall(d) => honest[wire] + F::from(*d),
            Mutation::MulSmall(m) => honest[wire] * F::from(*m),
            Mutation::Negate => -honest[wire],
            Mutation::Zero => F::ZERO,
            Mutation::CopyFrom(o) => {
                honest[circuit.cheatable[*o as usize % circuit.cheatable.len()]]
            }
        };
        if value == honest[wire] {
            value += F::ONE;
        }
        cheats.push((wire, value));
    }
    if cheats.is_empty() {
        // Default to one small cheat so every input does work.
        cheats.push((circuit.cheatable[0], honest[circuit.cheatable[0]] + F::ONE));
    }

    let ProbeOutcome::OutputsMoved { witness, moved } = circuit.prepared.probe(&cheats) else {
        return;
    };

    // The recorded graph says this is a soundness bug. Before saying so, put
    // the accepting witness back through a fresh synthesis of the same
    // circuit: a capture that drifted from the production code would
    // otherwise be reported as a break in the circuit.
    let name = circuit.name();
    match replay(&witness) {
        Some(true) => panic!(
            "INTERNAL CIRCUIT SOUNDNESS SIGNAL in `{name}` (replay-confirmed): cheating \
             advice {cheats:?} and repairing through the captured constraints left every \
             constraint satisfied, yet the wires {moved:?} this circuit is responsible for \
             moved while every input it receives — instance and stage alike — was held at \
             its honest value. A fresh synthesis of the circuit accepts the same witness, \
             so this is not a recording artifact: the circuit accepts two witnesses that \
             agree on everything it takes in and disagree on something it vouches for.",
        ),
        Some(false) => panic!(
            "CAPTURE DIVERGENCE in `{name}`: the recorded constraint graph accepted a \
             witness that a fresh synthesis of the same circuit rejects, after cheating \
             advice {cheats:?} moved the outputs {moved:?}. This is not evidence about the \
             circuit — it is evidence that the capture and the circuit disagree, which \
             makes every verdict this target has produced about `{name}` unsound in both \
             directions. Fix the capture path before reading anything else here.",
        ),
        None => panic!(
            "REPLAY UNREACHABLE for `{name}`: rebuilding the capture point never reached \
             the circuit, so the accepting witness (from cheating {cheats:?}, moving \
             {moved:?}) could not be checked against a fresh synthesis. A capture point is \
             supposed to be reproducible from its own seed; this one is not.",
        ),
    }
}
