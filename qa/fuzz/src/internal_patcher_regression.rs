//! Patcher regression tests for the production internal recursion circuits.
//!
//! [`capture_internal_circuits`] hands every native and nested internal circuit its
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
//! Capture and playback use one sequential proof tree. The static checks and
//! complete sweeps run in parallel over its recorded circuits at each point.
//!
//! Run by the PR fuzz harness job with
//! `cargo test --release --lib internal_patcher::tests -- --include-ignored`.

use std::time::{Duration, Instant};

use proptest::prelude::*;
use ragu_circuits::{Circuit, polynomials::ProductionRank};
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{
    ApplicationBuilder,
    fuzzing::patcher::{
        CircuitSpec, InternalCircuitVisitor, OutputRef, Resolution, capture_internal_circuits,
        capture_internal_circuits_bootstrap,
    },
};
use ragu_testing::{
    patcher::{Capture, Prepared, ProbeOutcome, determinism_probe, forced_by, playback},
    pcd::nontrivial::{Hash2, Merge2, WitnessLeaf},
};
use rand::{SeedableRng, rngs::StdRng};
use rayon::prelude::*;
use udon::field::Field;

use crate::internal_patcher::{
    CaptureCase, Mutation, Point, capture_checked, check_binding, probe_mutations,
};

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

type Check = Box<dyn FnOnce() -> Result<Census> + Send>;

/// Capture and independently replay while the circuit's witness is available.
/// The remaining checks own their recording and can run on another thread.
fn capture_check<'w, F: Field, Cir: Circuit<F>>(
    point: &str,
    spec: &CircuitSpec,
    circuit: &Cir,
    stage_values: &[F],
    make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
) -> Result<Check> {
    let name = spec.name.as_str();

    let (cap, resolution) = capture_checked(
        &format!("{name}@{point}"),
        spec,
        circuit,
        stage_values,
        &make_witness,
    )?;
    let rec = &cap.recorder;

    // The binding circuits must reject a different curve point in every
    // bound slot. Negating y preserves curve membership, so this exercises
    // the commitment equalities independently of the curve checks.
    if matches!(name, "bind_beta" | "bind_endoscalar" | "nested_export") {
        let point_wires: Vec<_> = spec
            .outputs
            .iter()
            .filter_map(|output| match (name, *output) {
                ("bind_beta", OutputRef::Stage(i)) => Some(cap.stage_wires[i]),
                ("bind_endoscalar", OutputRef::Instance(i)) => Some(cap.instance[i]),
                ("nested_export", OutputRef::Instance(i)) if i >= 5 => Some(cap.instance[i]),
                _ => None,
            })
            .collect();
        let expected = match name {
            "bind_beta" => 52,
            "bind_endoscalar" => 8,
            "nested_export" => 28,
            _ => unreachable!(),
        };
        assert_eq!(point_wires.len(), expected);
        for (i, coordinates) in point_wires.chunks_exact(2).enumerate() {
            let mut changed = rec.values.clone();
            let y = coordinates[1];
            changed[y] = -changed[y];
            assert_ne!(
                changed[y], rec.values[y],
                "{name}@{point}: point {i} must change"
            );
            assert!(
                !playback(circuit, make_witness()?, changed)?,
                "{name}@{point}: mismatched commitment {i} must be rejected",
            );
        }
    }

    let point = point.to_owned();
    let spec = spec.clone();
    Ok(Box::new(move || check(&point, &spec, &cap, &resolution)))
}

/// Run the same static checks and full sweeps against a recorded circuit.
fn check<F: Field>(
    point: &str,
    spec: &CircuitSpec,
    cap: &Capture<F>,
    resolution: &Resolution,
) -> Result<Census> {
    let name = spec.name.as_str();
    let rec = &cap.recorder;

    let binding = check_binding(&format!("{name}@{point}"), cap, resolution);
    let free = binding.free;
    let strongly_forced = binding.strongly_forced;

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
    checks: Vec<Check>,
    census: Vec<Census>,
}

impl CaptureChecker {
    fn finish(&mut self) -> Result<()> {
        // Indexed collection preserves the capture order despite parallel
        // completion. Drain each point before building the next tree level,
        // bounding the recordings retained in memory.
        self.census = core::mem::take(&mut self.checks)
            .into_par_iter()
            .map(|check| check())
            .collect::<Result<_>>()?;
        Ok(())
    }
}

impl<C: Cycle> InternalCircuitVisitor<C> for CaptureChecker {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        self.checks.push(capture_check(
            self.point,
            spec,
            circuit,
            stage_values,
            make_witness,
        )?);
        Ok(())
    }

    fn visit_nested<'w, Cir: Circuit<C::ScalarField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::ScalarField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        self.checks.push(capture_check(
            self.point,
            spec,
            circuit,
            stage_values,
            make_witness,
        )?);
        Ok(())
    }
}

/// The pinned census: a change to a circuit that adds or removes stage
/// wires, instance wires, outputs or hints, or that changes how many single
/// wire nudges the constraints neutralize, is noticed here. The sweep
/// tallies and `cheatable` are judged at the witness, so they are pinned per
/// capture point; the rest is structural. The endoscaling tallies depend on
/// transcript-derived bit patterns, so they also depend on the fixed test tag.
/// These pins cover quotient folding and its four challenge binders.
fn expected(name: &str, point: &str) -> Census {
    let (stage_wires, wires, instance, outputs, demoted, strongly_forced, cheatable) = match name {
        "hashes_1" => (190, 5464, 46, 12, 0, 12, 108),
        "hashes_2" => (190, 8040, 38, 5, 1, 5, 98),
        "inner_collapse" => (274, 1502, 38, 14, 0, 14, 157),
        "outer_collapse" if point == "bootstrap" => (190, 899, 38, 2, 0, 2, 102),
        "outer_collapse" => (190, 899, 38, 3, 0, 3, 101),
        "compute_v" => (426, 7195, 38, 1, 0, 1, 467),
        "bind_challenges_0" => (426, 7467, 38, 2, 0, 2, 720),
        "bind_challenges_3" if point == "bootstrap" => (426, 7537, 38, 2, 0, 2, 722),
        "bind_challenges_3" => (426, 7537, 38, 2, 0, 2, 720),
        bind if bind.starts_with("bind_challenges_") => (426, 7488, 38, 2, 0, 2, 720),
        "bind_beta" => (190, 7014, 38, 52, 0, 52, 625),
        "bind_endoscalar" => (376, 2538, 38, 136, 0, 136, 442),
        // The native steps end their output in the internal suffix, a constant
        // zero element, which adds one wire and one instance wire.
        "native_endoscaling_step_24" => (376, 5725, 1, 2, 0, 2, 187),
        step if step.starts_with("native_endoscaling_step_") => (376, 10693, 1, 2, 0, 2, 187),
        "endoscaling_step_27" => (406, 5784, 0, 2, 0, 2, 202),
        step if step.starts_with("endoscaling_step_") => (406, 10752, 0, 2, 0, 2, 202),
        "nested_export" => (1004, 3781, 33, 31, 0, 31, 504),
        "nested_collapse" if point == "bootstrap" => (1004, 3293, 33, 10, 0, 10, 515),
        "nested_collapse" => (1004, 3293, 33, 11, 0, 11, 514),
        "nested_compute_v" => (1004, 6680, 33, 1, 0, 1, 504),
        other => panic!("no census pinned for {other}"),
    };
    let (pinned, rejected) = match (name, point) {
        ("hashes_1", _) => (13, 95),
        ("hashes_2", _) => (14, 84),
        ("inner_collapse", "bootstrap") => (20, 137),
        ("inner_collapse", _) => (17, 140),
        ("outer_collapse", "bootstrap") => (15, 87),
        ("outer_collapse", _) => (13, 88),
        ("compute_v", _) => (13, 454),
        ("bind_challenges_3", "bootstrap") => (15, 707),
        (bind, _) if bind.starts_with("bind_challenges_") => (13, 707),
        ("bind_beta", _) => (13, 612),
        ("bind_endoscalar", "bootstrap") => (54, 388),
        ("bind_endoscalar", "leaves") => (54, 388),
        ("bind_endoscalar", "nodes") => (50, 392),
        (step, "bootstrap") if step.starts_with("native_endoscaling_step_") => (53, 134),
        (step, "leaves") if step.starts_with("native_endoscaling_step_") => (53, 134),
        (step, "nodes") if step.starts_with("native_endoscaling_step_") => (49, 138),
        ("nested_export", "bootstrap") => (65, 439),
        ("nested_export", "leaves") => (65, 439),
        ("nested_export", "nodes") => (61, 443),
        ("nested_collapse", "bootstrap") => (66, 449),
        ("nested_collapse", "leaves") => (65, 449),
        ("nested_collapse", "nodes") => (61, 453),
        ("nested_compute_v", "bootstrap") => (64, 440),
        ("nested_compute_v", "leaves") => (64, 440),
        ("nested_compute_v", "nodes") => (60, 444),
        (_, "bootstrap") => (53, 149),
        (_, "leaves") => (53, 149),
        (_, "nodes") => (49, 153),
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
#[ignore = "internal patcher suite: run by the PR fuzz harness job"]
fn patcher_captures_internal_circuits() -> Result<()> {
    let pasta = ragu_pcd::pasta::baked();
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
    bootstrap.finish()?;

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
    leaves.finish()?;

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
    nodes.finish()?;

    let native = [
        "hashes_1",
        "hashes_2",
        "inner_collapse",
        "outer_collapse",
        "compute_v",
        "bind_challenges_0",
        "bind_challenges_1",
        "bind_challenges_2",
        "bind_challenges_3",
        "bind_beta",
        "bind_endoscalar",
    ];
    for checker in [&bootstrap, &leaves, &nodes] {
        let names: Vec<&str> = checker.census.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            &names[..native.len()],
            &native,
            "{}: the native circuits, in order",
            checker.point,
        );
        let native_steps: Vec<&str> = names[native.len()..]
            .iter()
            .copied()
            .take_while(|n| n.starts_with("native_endoscaling_step_"))
            .collect();
        assert!(
            !native_steps.is_empty()
                && native_steps
                    .iter()
                    .enumerate()
                    .all(|(i, n)| *n == format!("native_endoscaling_step_{i}")),
            "{}: then the native endoscaling steps, in order: {names:?}",
            checker.point,
        );
        let nested = ["nested_export", "nested_collapse", "nested_compute_v"];
        let steps = &names[native.len() + native_steps.len()..names.len() - nested.len()];
        assert!(
            steps
                .iter()
                .enumerate()
                .all(|(i, n)| *n == format!("endoscaling_step_{i}")),
            "{}: then the endoscaling steps, in order: {names:?}",
            checker.point,
        );
        assert_eq!(
            &names[names.len() - nested.len()..],
            &nested,
            "{}: then the nested instance circuits, in order",
            checker.point,
        );
        for census in &checker.census {
            println!("{}: {census:?}", checker.point);
        }
    }

    // Leaves and nodes agree on everything the witness' values do not
    // decide; the base case differs only in the c the two collapse circuits
    // leave free.
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
        if s.name == "outer_collapse" || s.name == "nested_collapse" {
            assert_eq!(
                s.outputs + 1,
                l.outputs,
                "{}: c is not an output at the base case",
                s.name
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

    // Only hashes_2 has a demoted slot (mu, from the resumed sponge state);
    // every output is forced by the inputs alone; and the pinned census.
    // The sweep tallies follow the captured witness values, so a circuit
    // change upstream moves several pins at once: report every drift
    // together rather than one per run.
    let mut drifted = Vec::new();
    for checker in [&bootstrap, &leaves, &nodes] {
        for census in &checker.census {
            assert!(census.outputs > 0, "{}: watched outputs", census.name);
            assert_eq!(
                census.demoted,
                if census.name == "hashes_2" { 1 } else { 0 },
                "{}: demoted covered slots",
                census.name,
            );
            assert_eq!(
                census.strongly_forced, census.outputs,
                "{}@{}: outputs forced by the declared inputs alone",
                census.name, checker.point,
            );
            let pinned = expected(&census.name, checker.point);
            if *census != pinned {
                drifted.push(format!(
                    "{}@{}: expected {pinned:?}, found {census:?}",
                    census.name, checker.point,
                ));
            }
        }
    }
    assert!(
        drifted.is_empty(),
        "census drifted:\n{}",
        drifted.join("\n")
    );
    Ok(())
}

/// Sample one native and one nested circuit per generated tree. Full sweeps
/// remain in the fixed regression; these cases spend their budget on varying
/// honest witnesses, blinding, registry width, and coordinated mutations.
struct GeneratedChecker<'a> {
    native: &'static str,
    nested: &'static str,
    mutations: &'a [(u16, Mutation)],
    checked: usize,
}

impl GeneratedChecker<'_> {
    fn check<'w, F: Field, Cir: Circuit<F>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[F],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        let (cap, resolution) =
            capture_checked(&spec.name, spec, circuit, stage_values, &make_witness)?;
        let binding = check_binding(&spec.name, &cap, &resolution);
        let cheatable: Vec<_> = binding
            .free
            .into_iter()
            .filter(|wire| !resolution.inputs.contains(wire))
            .collect();
        assert!(
            !cheatable.is_empty(),
            "{}: no mutation candidates",
            spec.name
        );
        let prepared = Prepared::new(
            cap.recorder.events,
            cap.recorder.values,
            resolution.inputs,
            resolution.outputs,
        );
        probe_mutations(
            &spec.name,
            &prepared,
            &cheatable,
            self.mutations,
            |witness| {
                Some(
                    playback(
                        circuit,
                        make_witness().expect("honest witness"),
                        witness.to_vec(),
                    )
                    .expect("replay must not error"),
                )
            },
        );
        self.checked += 1;
        Ok(())
    }
}

impl<C: Cycle> InternalCircuitVisitor<C> for GeneratedChecker<'_> {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if spec.name == self.native {
            self.check(spec, circuit, stage_values, make_witness)?;
        }
        Ok(())
    }

    fn visit_nested<'w, Cir: Circuit<C::ScalarField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::ScalarField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if spec.name == self.nested {
            self.check(spec, circuit, stage_values, make_witness)?;
        }
        Ok(())
    }
}

fn witness_strategy() -> impl Strategy<Value = Fp> {
    prop_oneof![
        1 => Just(Fp::ZERO), 1 => Just(Fp::ONE), 1 => Just(-Fp::ONE),
        3 => any::<u64>().prop_map(Fp::from),
    ]
}

fn mutation_strategy() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        any::<u64>().prop_map(Mutation::AddSmall),
        any::<u64>().prop_map(Mutation::MulSmall),
        Just(Mutation::Negate),
        Just(Mutation::Zero),
        any::<u16>().prop_map(Mutation::CopyFrom),
    ]
}

fn generated_config() -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = 2;
    }
    config.max_shrink_iters = 16;
    config
}

proptest! {
    #![proptest_config(generated_config())]

    #[test]
    #[ignore = "internal patcher suite: run by the PR fuzz harness job"]
    fn generated_captures_keep_outputs_bound(
        rng_seed in any::<u64>(),
        witnesses in prop::array::uniform6(witness_strategy()),
        extra_steps in any::<u8>(),
        native in prop::sample::select(vec![
            "hashes_1", "hashes_2", "inner_collapse", "outer_collapse", "compute_v",
            "bind_challenges_0", "bind_beta", "bind_endoscalar", "native_endoscaling_step_0",
        ]),
        nested in prop::sample::select(vec![
            "nested_export", "nested_collapse", "nested_compute_v", "endoscaling_step_0",
        ]),
        mutations in prop::collection::vec((any::<u16>(), mutation_strategy()), 0..=8),
    ) {
        for point in Point::ALL {
            let minimum = point.minimum_steps();
            let case = CaptureCase {
                point, steps: minimum + usize::from(extra_steps) % (4 - minimum),
                rng_seed, witnesses,
            };
            let mut checker = GeneratedChecker { native, nested, mutations: &mutations, checked: 0 };
            case.capture(&mut checker).unwrap_or_else(|error| panic!("{case:?}: {error:?}"));
            prop_assert_eq!(checker.checked, 2, "case {:?}", case);
        }
    }
}
