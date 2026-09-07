//! Aiming the patcher engine at the production internal recursion circuits
//! (issue #793).
//!
//! [`capture_internal_circuits`] hands every internal circuit —
//! the five native ones and the nested endoscaling steps — its
//! [`CircuitSpec`] and its honest witness, which exist only mid-fuse, to a
//! visitor. Here the visitor captures each circuit through the recording
//! driver and checks:
//!
//! * `constraints_hold` — the [reserved-wire overlay](ragu_testing::patcher::overlay_reserved)
//!   recovered the honest stage-wire values that `configure_stage` zeros (and
//!   the virtual wires computed from them), so the honest witness satisfies
//!   the recorded graph. This exercises the whole engine on the production
//!   circuits at once: routines (Poseidon permutations), pooled allocation,
//!   and multi-stage reservation.
//! * `playback` — a second, independent synthesis re-accepts the same
//!   witness, so the recording matches a live re-execution rather than merely
//!   agreeing with itself.
//! * `forced_by`, in two tiers — granting the declared inputs plus every other
//!   free wire except the declared outputs, the bounded solver must derive
//!   every output; one it cannot reach is an output the circuit never
//!   constrains, which no cheat sweep would tell, so it fails here, before
//!   fuzzing. And the inputs *alone* must force every output: the solver's
//!   case analysis on booleans is what carries it through `compute_v`'s
//!   endoscalar decomposition.
//! * a wrong spec is refused — declaring a received commitment coordinate of
//!   `hashes_1` as an output fails that check, so it is not vacuous on graphs
//!   this size.
//! * [`Prepared`] agrees with the full probe — the incremental probe the fuzz
//!   target runs returns the full [`determinism_probe`]'s verdict (or a more
//!   conclusive one) on a spread of single-wire cheats, none of which is a
//!   signal; their timings are printed for the record.
//! * a full single-wire sweep — every cheatable wire of every circuit is
//!   nudged through the prepared probe: no violation, and enough probes
//!   accepted that the sweep is not vacuous.
//!
//! The circuits are captured at three points of a small tree: the bootstrap
//! base case (over two synthesized dummy children, where `outer_collapse`
//! leaves `c` free by design), a fuse of two leaves, and a fuse of two such
//! nodes. The
//! census — wire counts, declarations, cheatable wires, sweep tallies — is
//! pinned per circuit and point, so a change that adds or removes hints,
//! stage wires or instance wires is noticed here.
//!
//! Gated behind `unstable-fuzzing` and run with
//! `cargo test -p ragu_pcd --features unstable-fuzzing --test patcher_internal`.

use std::time::{Duration, Instant};

use ragu_arithmetic::{Cycle, ff::PrimeFieldBits};
use ragu_circuits::{Circuit, polynomials::ProductionRank};
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{
    ApplicationBuilder,
    fuzzing::patcher::{
        CircuitSpec, InternalCircuitVisitor, OutputRef, capture_internal_circuits,
        capture_internal_circuits_bootstrap,
    },
};
use ragu_testing::{
    patcher::{
        Prepared, ProbeOutcome, capture_with_stage_values, constraints_hold, determinism_probe,
        discover_free_advice, forced_by, playback,
    },
    pcd::nontrivial::{Hash2, Merge2, WitnessLeaf},
};
use rand::{SeedableRng, rngs::StdRng};

/// One circuit's census at one capture point.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Census {
    name: String,
    /// Reserved stage wires (two per reserved gate).
    stage_wires: usize,
    wires: usize,
    instance: usize,
    /// Watched outputs.
    outputs: usize,
    /// Covered slots demoted to inputs.
    demoted: usize,
    /// Outputs the declared inputs alone force.
    strongly_forced: usize,
    /// Free wires outside the inputs — what the fuzzer may cheat. Judged at
    /// the witness, so it may differ between capture points.
    cheatable: usize,
    /// Sweep tallies: cheatable wires whose nudge was accepted with every
    /// output in place, and wires whose every nudge the solver rejected.
    pinned: usize,
    rejected: usize,
}

/// Captures one circuit and runs every check, returning its census.
fn check<'w, F: PrimeFieldBits, Cir: Circuit<F>>(
    point: &str,
    spec: &CircuitSpec,
    circuit: &Cir,
    stage_values: &[F],
    make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
) -> Result<Census> {
    let name = spec.name.as_str();

    let cap = capture_with_stage_values(circuit, make_witness()?, stage_values)
        .unwrap_or_else(|e| panic!("{name}@{point}: capture must succeed, got {e:?}"));
    let rec = &cap.recorder;
    assert_eq!(
        cap.stage_wires.len(),
        stage_values.len(),
        "{name}@{point}: one stage wire per supplied stage value",
    );
    assert!(
        constraints_hold(&rec.events, &rec.values),
        "{name}@{point}: the capture must satisfy the recorded constraints",
    );
    assert!(
        playback(circuit, make_witness()?, rec.values.clone())?,
        "{name}@{point}: an independent playback must re-accept the captured witness",
    );

    let resolution = spec.resolve(&cap.instance, &cap.stage_wires)?;
    assert!(
        !resolution.outputs.is_empty(),
        "{name}@{point}: a circuit with nothing to watch would make the oracle vacuous",
    );

    // The static check, two tiers (see the module docs).
    let free = discover_free_advice(&rec.events, &rec.values);
    let mut granted = resolution.inputs.clone();
    granted.extend(
        free.iter()
            .copied()
            .filter(|w| !resolution.outputs.contains(w)),
    );
    let weakly = forced_by(&rec.events, &rec.values, &granted);
    let strongly = forced_by(&rec.events, &rec.values, &resolution.inputs);
    let mut strongly_forced = 0;
    for output in &spec.outputs {
        let wire = match *output {
            OutputRef::Instance(i) => cap.instance[i],
            OutputRef::Stage(i) => cap.stage_wires[i],
        };
        if resolution.demoted.contains(&wire) {
            continue;
        }
        assert!(
            weakly.binary_search(&wire).is_ok(),
            "{name}@{point}: declared output {output:?} (wire {wire}) is not forced even \
             with every hint granted — the circuit never constrains it",
        );
        if strongly.binary_search(&wire).is_ok() {
            strongly_forced += 1;
        }
    }

    // A wrong spec must be refused: hashes_1's first instance wire is a
    // coordinate of the received preamble commitment, which the circuit
    // absorbs but nothing in it derives — not even with every hint and
    // every challenge granted, since that would mean inverting Poseidon.
    if name == "hashes_1" {
        let wrong = CircuitSpec {
            name: "hashes_1 (wrong)".into(),
            outputs: vec![OutputRef::Instance(0)],
        }
        .resolve(&cap.instance, &cap.stage_wires)?;
        let mut granted = wrong.inputs.clone();
        granted.extend(free.iter().copied().filter(|w| !wrong.outputs.contains(w)));
        let forced = forced_by(&rec.events, &rec.values, &granted);
        assert!(
            forced.binary_search(&cap.instance[0]).is_err(),
            "{name}@{point}: a received commitment coordinate declared as an output must \
             fail the static check",
        );
    }

    // The prepared probe against the full one, on a spread of single-wire
    // cheats. None may be a signal, and the prepared verdict must be at
    // least as conclusive as the full one.
    let cheatable: Vec<usize> = free
        .iter()
        .copied()
        .filter(|w| !resolution.inputs.contains(w))
        .collect();
    let prepared = Prepared::new(
        rec.events.clone(),
        rec.values.clone(),
        resolution.inputs.clone(),
        resolution.outputs.clone(),
    );
    let stride = (cheatable.len() / 12).max(1);
    let sample: Vec<usize> = cheatable.iter().copied().step_by(stride).take(12).collect();
    let cheat = |w: usize| [(w, rec.values[w] + F::ONE)];
    let moved_wires = |outcome: &ProbeOutcome<F>| match outcome {
        ProbeOutcome::OutputsMoved { moved, .. } => {
            Some(moved.iter().map(|(w, _, _)| *w).collect::<Vec<_>>())
        }
        _ => None,
    };
    let (mut full_time, mut fast_time) = (Duration::ZERO, Duration::ZERO);
    for &w in &sample {
        let started = Instant::now();
        let full = determinism_probe(
            &rec.events,
            &rec.values,
            &resolution.inputs,
            &resolution.outputs,
            &cheat(w),
        );
        full_time += started.elapsed();
        let started = Instant::now();
        let fast = prepared.probe(&cheat(w));
        fast_time += started.elapsed();

        for (which, outcome) in [("full", &full), ("prepared", &fast)] {
            assert!(
                moved_wires(outcome).is_none(),
                "{name}@{point}: SOUNDNESS SIGNAL ({which} probe): cheating wire {w} moved \
                 outputs {:?}",
                moved_wires(outcome),
            );
        }
        match (&full, &fast) {
            (ProbeOutcome::OutputsPinned, ProbeOutcome::OutputsPinned)
            | (ProbeOutcome::Rejected, _) => {}
            other => panic!(
                "{name}@{point}: wire {w}: the prepared probe must be at least as \
                 conclusive as the full one, got {other:?}",
            ),
        }
    }

    // The full single-wire sweep, through the prepared probe.
    let started = Instant::now();
    let report = prepared.sweep();
    let sweep_time = started.elapsed();
    assert!(
        report.violations.is_empty(),
        "{name}@{point}: SOUNDNESS SIGNAL (sweep): {:?}",
        report
            .violations
            .iter()
            .map(|v| (
                v.advice,
                v.moved.iter().map(|(w, _, _)| *w).collect::<Vec<_>>()
            ))
            .collect::<Vec<_>>(),
    );
    assert!(
        report.pinned > 0,
        "{name}@{point}: a sweep with no accepted probe is vacuous ({} rejected)",
        report.rejected,
    );

    if !sample.is_empty() {
        let n = sample.len() as u32;
        let (residual, total) = prepared.residual_events();
        println!(
            "{name}@{point}: probe {:?} full vs {:?} prepared ({residual} of {total} events \
             residual); sweep of {} wires in {sweep_time:?}",
            full_time / n,
            fast_time / n,
            cheatable.len(),
        );
    }

    Ok(Census {
        name: spec.name.clone(),
        stage_wires: cap.stage_wires.len(),
        wires: rec.values.len(),
        instance: cap.instance.len(),
        outputs: resolution.outputs.len(),
        demoted: resolution.demoted.len(),
        strongly_forced,
        cheatable: cheatable.len(),
        pinned: report.pinned,
        rejected: report.rejected,
    })
}

/// Checks each internal circuit, native and nested, at one capture point.
#[derive(Default)]
struct CaptureChecker {
    point: &'static str,
    census: Vec<Census>,
}

impl<C: Cycle> InternalCircuitVisitor<C> for CaptureChecker {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        let census = check(self.point, spec, circuit, stage_values, make_witness)?;
        self.census.push(census);
        Ok(())
    }

    fn visit_nested<'w, Cir: Circuit<C::ScalarField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::ScalarField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        let census = check(self.point, spec, circuit, stage_values, make_witness)?;
        self.census.push(census);
        Ok(())
    }
}

/// The pinned census: a change to a circuit that adds or removes stage
/// wires, instance wires, outputs or hints, or that changes how many single
/// wire nudges the constraints neutralize, is noticed here. The sweep
/// tallies and `cheatable` are judged at the witness, so they are pinned per
/// capture point; the rest is structural.
fn expected(name: &str, point: &str) -> Census {
    let (stage_wires, wires, instance, outputs, demoted, strongly_forced, cheatable) = match name {
        "hashes_1" => (456, 5561, 38, 8, 0, 8, 238),
        "hashes_2" => (456, 8527, 30, 6, 2, 6, 231),
        "inner_collapse" => (1254, 6264, 30, 19, 0, 19, 653),
        "outer_collapse" if point == "bootstrap" => (456, 2898, 30, 6, 0, 6, 234),
        "outer_collapse" => (456, 2898, 30, 7, 0, 7, 238),
        "compute_v" => (166, 3422, 30, 1, 0, 1, 337),
        step if step.starts_with("endoscaling_step_") => (220, 10380, 0, 2, 0, 2, 109),
        other => panic!("no census pinned for {other}"),
    };
    let (pinned, rejected) = match (name, point) {
        ("hashes_1", _) => (188, 50),
        ("hashes_2", _) => (189, 42),
        ("inner_collapse", "bootstrap") => (525, 128),
        ("inner_collapse", _) => (529, 124),
        ("outer_collapse", "bootstrap") => (190, 44),
        ("outer_collapse", _) => (188, 50),
        ("compute_v", _) => (13, 324),
        (_, "bootstrap") => (53, 56),
        (_, "leaves") => (48, 61),
        (_, "nodes") => (45, 64),
        other => panic!("no sweep tallies pinned for {other:?}"),
    };
    Census {
        name: name.to_owned(),
        stage_wires,
        wires,
        instance,
        outputs,
        demoted,
        strongly_forced,
        cheatable,
        pinned,
        rejected,
    }
}

/// Real fuses at three points of a small tree, with the patcher capturing
/// every internal circuit as its honest witness is built.
#[test]
fn patcher_captures_internal_circuits() -> Result<()> {
    let pasta = Pasta::baked();
    let leaf_step = || WitnessLeaf {
        poseidon_params: Pasta::circuit_poseidon(pasta),
    };
    let hash2 = || Hash2 {
        poseidon_params: Pasta::circuit_poseidon(pasta),
    };
    let merge2 = || Merge2 {
        poseidon_params: Pasta::circuit_poseidon(pasta),
    };
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(leaf_step())?
        .register(hash2())?
        .register(merge2())?
        .finalize(pasta)?;
    let mut rng = StdRng::seed_from_u64(1234);

    // The base case: the internal bootstrap step over two dummy children.
    let mut bootstrap = CaptureChecker {
        point: "bootstrap",
        ..Default::default()
    };
    capture_internal_circuits_bootstrap(&app, &mut rng, &mut bootstrap)?;

    // Level one: two leaves.
    let leaf = |rng: &mut StdRng| {
        app.seed(rng, leaf_step(), Fp::from(42u64))
            .map(|(pcd, _)| pcd)
    };
    let mut leaves = CaptureChecker {
        point: "leaves",
        ..Default::default()
    };
    let (l, r) = (leaf(&mut rng)?, leaf(&mut rng)?);
    capture_internal_circuits(&app, &mut rng, hash2(), (), l, r, &mut leaves)?;

    // Level two: two nodes, each a real fuse of two leaves.
    let node = |rng: &mut StdRng| -> Result<_> {
        let (l, r) = (leaf(rng)?, leaf(rng)?);
        app.fuse(rng, hash2(), (), l, r).map(|(pcd, _)| pcd)
    };
    let mut nodes = CaptureChecker {
        point: "nodes",
        ..Default::default()
    };
    let (l, r) = (node(&mut rng)?, node(&mut rng)?);
    capture_internal_circuits(&app, &mut rng, merge2(), (), l, r, &mut nodes)?;

    let native = [
        "hashes_1",
        "hashes_2",
        "inner_collapse",
        "outer_collapse",
        "compute_v",
    ];
    for checker in [&bootstrap, &leaves, &nodes] {
        let names: Vec<&str> = checker.census.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            &names[..native.len()],
            &native,
            "{}: the five native circuits, in order",
            checker.point,
        );
        assert!(
            names[native.len()..]
                .iter()
                .enumerate()
                .all(|(i, n)| *n == format!("endoscaling_step_{i}")),
            "{}: then the endoscaling steps, in order: {names:?}",
            checker.point,
        );
        for census in &checker.census {
            println!("{}: {census:?}", checker.point);
        }
    }

    // Leaves and nodes agree on everything the witness' values do not
    // decide; the base case differs only in outer_collapse's c.
    let structural = |census: &Census| {
        (
            census.name.clone(),
            census.stage_wires,
            census.wires,
            census.instance,
            census.outputs,
            census.demoted,
            census.strongly_forced,
        )
    };
    let all_structural =
        |checker: &CaptureChecker| checker.census.iter().map(structural).collect::<Vec<_>>();
    assert_eq!(all_structural(&leaves), all_structural(&nodes));
    for (s, l) in bootstrap.census.iter().zip(&leaves.census) {
        if s.name == "outer_collapse" {
            assert_eq!(
                s.outputs + 1,
                l.outputs,
                "outer_collapse: c is not an output at the base case"
            );
            assert_eq!(s.strongly_forced + 1, l.strongly_forced);
        } else {
            assert_eq!(
                structural(s),
                structural(l),
                "{}: the same declaration at the base case",
                s.name
            );
        }
    }

    // Only hashes_2 has demoted slots (mu and nu, the resumed sponge state);
    // every output is forced by the inputs alone; and the pinned census.
    for checker in [&bootstrap, &leaves, &nodes] {
        for census in &checker.census {
            assert!(census.outputs > 0, "{}: watched outputs", census.name);
            assert_eq!(
                census.demoted,
                if census.name == "hashes_2" { 2 } else { 0 },
                "{}: demoted covered slots",
                census.name,
            );
            assert_eq!(
                census.strongly_forced, census.outputs,
                "{}@{}: outputs forced by the declared inputs alone",
                census.name, checker.point,
            );
            assert_eq!(
                *census,
                expected(&census.name, checker.point),
                "{}@{}: census drifted",
                census.name,
                checker.point,
            );
        }
    }
    Ok(())
}
