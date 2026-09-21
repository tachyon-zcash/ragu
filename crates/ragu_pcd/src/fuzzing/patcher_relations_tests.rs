//! Relations between separately supplied semantic endpoints need their own
//! mutations: output determinism at an honest capture does not exercise an
//! inconsistent pair.
//!
//! These checks cover review findings 3.1/R01 (every nested Export point),
//! 3.2/V01 (every nested endoscalar bit versus beta), R02 (every child binding
//! point), R03 (the native walk endpoint versus instance P_n), and V02
//! (every native walk bit versus canonical pre_beta). Only
//! internal advice may be repaired; every stage and instance wire is pinned,
//! including the deliberately changed endpoint. Recorded constraints and
//! live playback must agree on rejection.
//!
//! This is deliberately a local claim. The pins make the two endpoints
//! independent test inputs; they do not establish that either endpoint is
//! authenticated by the recursive protocol. Running the same mutation on
//! captures produced at several tree depths still tests the current circuit,
//! not transfer of a child's obligation through a parent. That stronger claim
//! additionally depends on the circuit trace entering the nested claims, the
//! child's instance copy entering the parent's fold, the non-base-case guard,
//! and the terminal commitment, transcript, walk, and accumulator checks.
//!
//! Calibration: omit one selected `instance.enforce_equal(dr, stage)` in
//! nested Export, or only `enforce_equal(dr, beta)` after ComputeV's lift.
//! The corresponding test must fail because both checks accept the repaired
//! mismatch, with point allocation and lift arithmetic still present.
//! For native calibration, the challenge-completion relation now has an
//! automated captured-graph cut: keep the changed point valid, delete each
//! event in its direct endpoint neighborhood in turn, and repair all internal
//! advice. Exactly the emitted y-coordinate equality admits the mismatch;
//! the complete recording and live circuit reject the same pinned endpoint.
//! The other 25 BindBeta point relations retain recorded/live rejection
//! sweeps. BindEndoscalar likewise retains the staged-to-extracted sweeps at
//! bit 0, 63, 64, and 127. Canonical extraction, point arithmetic, and every
//! other equality remain present in these controls.
//! For R03, omit only `walk.p().enforce_equal(dr, &p)` in BindEndoscalar;
//! the instance point changes while every stage, including the endpoint,
//! stays pinned. This local control repairs the instance's allocation advice.
//! A cache-repaired polynomial substitution with its old circuit trace can
//! still reject after removing the equality (see fuse/substitution_tests.rs).
//! Such acceptance proves sensitivity to the omitted local relation; it does
//! not by itself exhibit an end-to-end false proof or rule out a redundant
//! protocol-level path.

use ragu_arithmetic::{CurveAffine, ff::PrimeFieldBits};
use ragu_primitives::lift_endoscalar;
use ragu_testing::patcher::{Capture, Event};

use super::*;

type Leaf = HeaderStep<(), (), ApplicationHeader, 0>;
type Merge = HeaderStep<ApplicationHeader, ApplicationHeader, ApplicationHeader, 1>;

#[derive(Clone, Copy)]
enum Relation {
    ExportPoints,
    EndoscalarBits,
    ChildBindingPoints,
    NativeEndoscalarBits,
    NativeWalkEndpoint,
}

impl Relation {
    fn circuit_name(self) -> &'static str {
        match self {
            Self::ExportPoints => "nested_export",
            Self::EndoscalarBits => "nested_compute_v",
            Self::ChildBindingPoints => "bind_beta",
            Self::NativeEndoscalarBits | Self::NativeWalkEndpoint => "bind_endoscalar",
        }
    }

    fn count(self) -> usize {
        match self {
            Self::ExportPoints => 14,
            Self::EndoscalarBits => 128,
            Self::ChildBindingPoints => 26,
            Self::NativeEndoscalarBits => 128,
            Self::NativeWalkEndpoint => 1,
        }
    }
}

/// Preserve the mismatch and every other semantic endpoint while allowing
/// point-allocation copies and lift/arithmetic advice to follow the edit.
fn repair_internal_advice<F: Field>(
    cap: &Capture<F>,
    wire: usize,
    replacement: F,
    context: &str,
) -> Vec<F> {
    let rec = &cap.recorder;
    let pins: Vec<_> = cap
        .instance
        .iter()
        .chain(&cap.stage_wires)
        .copied()
        .collect();
    assert!(
        pins.contains(&wire),
        "{context}: the changed endpoint is pinned"
    );
    assert_ne!(
        replacement, rec.values[wire],
        "{context}: mutation is nonzero"
    );

    let mut changed = rec.values.clone();
    changed[wire] = replacement;
    repair(&rec.events, &mut changed, &pins);
    for pin in pins {
        assert_eq!(
            changed[pin],
            if pin == wire {
                replacement
            } else {
                rec.values[pin]
            },
            "{context}: repair changed pinned wire {pin}",
        );
    }
    changed
}

fn assert_rejected<'w, F: Field, Cir: Circuit<F>>(
    cap: &Capture<F>,
    circuit: &Cir,
    make_witness: &impl Fn() -> Result<Cir::Witness<'w>>,
    changed: Vec<F>,
    context: &str,
) -> Result<()> {
    let recorded = constraints_hold(&cap.recorder.events, &changed);
    let live = playback(circuit, make_witness()?, changed)?;
    assert_eq!(
        recorded, live,
        "{context}: recorded and live constraints disagree"
    );
    assert!(
        !recorded,
        "{context}: repaired mismatch accepted by recorded and live constraints"
    );
    Ok(())
}

/// The end-to-end V09 test identifies `child.challenges` as the sole
/// semantic mismatch. At the recorded circuit level, calibrate deletion of
/// the exact emitted coordinate equality: the repaired witness must violate
/// only that event, and removing it must accept every remaining constraint.
fn assert_unique_completion_cut<F: Field>(
    cap: &Capture<F>,
    endpoint: usize,
    changed: &[F],
    context: &str,
) {
    let candidates: Vec<_> = cap
        .recorder
        .events
        .iter()
        .enumerate()
        .filter(|(_, event)| match event {
            Event::Lin { out, terms } => {
                *out == endpoint || terms.iter().any(|(wire, _)| *wire == endpoint)
            }
            Event::Gate { a, b, c } => *a == endpoint || *b == endpoint || *c == endpoint,
            Event::Enforce { terms } => terms.iter().any(|(wire, _)| *wire == endpoint),
            Event::Extra { c, d } => *c == endpoint || *d == endpoint,
        })
        .map(|(i, _)| i)
        .collect();
    let pins: Vec<_> = cap
        .instance
        .iter()
        .chain(&cap.stage_wires)
        .copied()
        .collect();
    let accepting: Vec<_> = candidates
        .iter()
        .filter_map(|&cut| {
            let remaining: Vec<_> = cap
                .recorder
                .events
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != cut)
                .map(|(_, event)| event.clone())
                .collect();
            let mut repaired = cap.recorder.values.clone();
            for &pin in &pins {
                repaired[pin] = changed[pin];
            }
            repair(&remaining, &mut repaired, &pins);
            constraints_hold(&remaining, &repaired).then_some((cut, remaining, repaired))
        })
        .collect();
    assert_eq!(
        accepting.len(),
        1,
        "{context}: the completion mismatch must have one minimal raw-constraint cut"
    );
    let (cut, remaining, repaired) = &accepting[0];
    assert!(
        matches!(cap.recorder.events[*cut], Event::Enforce { .. }),
        "{context}: the cut must be the emitted coordinate equality"
    );
    assert!(
        constraints_hold(remaining, repaired),
        "{context}: deleting only the completion equality must accept the repaired witness"
    );
    assert!(
        !constraints_hold(&cap.recorder.events, repaired),
        "{context}: the intact completion equality must reject the cut witness"
    );
    for &pin in &pins {
        assert_eq!(
            repaired[pin], changed[pin],
            "{context}: cut repair changed semantic pin {pin}"
        );
    }
}

struct RelationChecker {
    relation: Relation,
    case: &'static str,
    base_case: bool,
    checked: usize,
}

impl RelationChecker {
    fn new(relation: Relation, case: &'static str, base_case: bool) -> Self {
        Self {
            relation,
            case,
            base_case,
            checked: 0,
        }
    }

    fn assert_complete(self) {
        assert_eq!(
            self.checked,
            self.relation.count(),
            "{}: {} must check every endpoint",
            self.case,
            self.relation.circuit_name(),
        );
    }
}

impl<C: Cycle> InternalCircuitVisitor<C> for RelationChecker {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if spec.name != self.relation.circuit_name() {
            return Ok(());
        }
        assert_eq!(self.checked, 0, "{}: circuit visited twice", self.case);
        let cap = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
        let rec = &cap.recorder;
        let context = format!("{}: {}", self.case, spec.name);
        assert!(
            constraints_hold(&rec.events, &rec.values),
            "{context}: honest capture"
        );
        assert!(
            playback(circuit, make_witness()?, rec.values.clone())?,
            "{context}: honest playback"
        );

        match self.relation {
            Relation::NativeWalkEndpoint => {
                let source = unified_slot_positions("nested_p_commitment");
                let endpoint = stage_wire_indices::<
                    C::CircuitField,
                    R,
                    native_points::WalkStage<C::NestedCurve>,
                >(|walk| wires_of(walk.p()))?;
                assert_eq!(source.len(), 2);
                assert_eq!(endpoint.len(), 2);
                for (&source, &endpoint) in source.iter().zip(&endpoint) {
                    let source = cap.instance[source];
                    let endpoint = cap.stage_wires[endpoint];
                    assert_ne!(source, endpoint, "separately supplied semantic endpoints");
                    assert_eq!(rec.values[source], rec.values[endpoint]);
                }
                let x = cap.instance[source[0]];
                let y = cap.instance[source[1]];
                let context = format!("{context}: instance P_n versus frozen walk endpoint");
                let changed = repair_internal_advice(&cap, y, -rec.values[y], &context);
                assert!(
                    bool::from(C::NestedCurve::from_xy(changed[x], changed[y]).is_some()),
                    "{context}: the changed instance point stays on the curve",
                );
                assert_ne!(changed[y], changed[cap.stage_wires[endpoint[1]]]);
                assert_rejected(&cap, circuit, &make_witness, changed, &context)?;
                self.checked += 1;
            }
            Relation::ChildBindingPoints => {
                // Name all semantic points independently of CircuitSpec's
                // output list and the production binding loop. The sweep in
                // tests/patcher_internal.rs leaves advice stale; here repair
                // must preserve every source and the mismatch.
                let names = [
                    "bridge_preamble",
                    "bridge_s_prime",
                    "bridge_inner_error",
                    "bridge_outer_error",
                    "bridge_ab",
                    "bridge_query",
                    "bridge_f",
                    "bridge_eval",
                    "challenges",
                    "a",
                    "b",
                    "registry_xy",
                    "p",
                ];
                let points = stage_wire_indices::<
                    C::CircuitField,
                    R,
                    native_points::BindingStage<C::NestedCurve>,
                >(|binding| {
                    let mut wires = Vec::new();
                    for child in [&binding.left, &binding.right] {
                        assert_eq!(child.bridges.len(), 8);
                        for point in [
                            &child.bridges[0],
                            &child.bridges[1],
                            &child.bridges[2],
                            &child.bridges[3],
                            &child.bridges[4],
                            &child.bridges[5],
                            &child.bridges[6],
                            &child.bridges[7],
                            &child.challenges,
                            &child.a,
                            &child.b,
                            &child.registry_xy,
                            &child.p,
                        ] {
                            wires.extend(wires_of(point)?);
                        }
                    }
                    Ok(wires)
                })?;
                assert_eq!(points.len(), 2 * 2 * names.len());
                for (i, coordinates) in points.chunks_exact(2).enumerate() {
                    let side = if i < names.len() { "left" } else { "right" };
                    let context = format!("{context}: {side}.{}", names[i % names.len()]);
                    let x = cap.stage_wires[coordinates[0]];
                    let y = cap.stage_wires[coordinates[1]];
                    let changed = repair_internal_advice(&cap, y, -rec.values[y], &context);
                    assert!(
                        bool::from(C::NestedCurve::from_xy(changed[x], changed[y]).is_some()),
                        "{context}: the changed point must stay on the curve",
                    );
                    if names[i % names.len()] == "challenges" {
                        assert_unique_completion_cut(&cap, y, &changed, &context);
                    }
                    assert_rejected(&cap, circuit, &make_witness, changed, &context)?;
                    self.checked += 1;
                }
            }
            Relation::NativeEndoscalarBits => {
                let bits = stage_wire_indices::<
                    C::CircuitField,
                    R,
                    native_points::WalkStage<C::NestedCurve>,
                >(|walk| wires_of(&walk.endoscalar))?;
                assert_eq!(bits.len(), 128, "{context}: all native endoscalar bits");
                let source = unified_slot_positions("pre_beta");
                assert_eq!(source.len(), 1);
                let source = cap.instance[source[0]];
                // Use the canonical integer's bits directly, independently
                // of extract_endoscalar and the circuit's extraction gadget.
                let canonical = rec.values[source].to_le_bits();
                for (i, &position) in bits.iter().enumerate() {
                    let context = format!("{context}: native endoscalar bit {i}");
                    let bit = cap.stage_wires[position];
                    assert_eq!(
                        rec.values[bit],
                        C::CircuitField::from(u64::from(canonical[i])),
                        "{context}: honest canonical extraction"
                    );
                    let changed = repair_internal_advice(
                        &cap,
                        bit,
                        C::CircuitField::ONE - rec.values[bit],
                        &context,
                    );
                    assert_eq!(
                        changed[source], rec.values[source],
                        "{context}: canonical source frozen"
                    );
                    for (j, &position) in bits.iter().enumerate() {
                        let value = changed[cap.stage_wires[position]];
                        assert!(
                            value == C::CircuitField::ZERO || value == C::CircuitField::ONE,
                            "{context}: bit {j} remains Boolean"
                        );
                        assert_eq!(
                            value == C::CircuitField::ONE,
                            canonical[j] ^ (i == j),
                            "{context}: exactly the intended bit differs"
                        );
                    }
                    assert_rejected(&cap, circuit, &make_witness, changed, &context)?;
                    self.checked += 1;
                }
            }
            _ => unreachable!("nested relation visited as a native circuit"),
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
        if spec.name != self.relation.circuit_name() {
            return Ok(());
        }
        assert_eq!(self.checked, 0, "{}: circuit visited twice", self.case);
        let cap = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
        let rec = &cap.recorder;
        let context = format!("{}: {}", self.case, spec.name);
        assert!(
            constraints_hold(&rec.events, &rec.values),
            "{context}: honest capture"
        );
        assert!(
            playback(circuit, make_witness()?, rec.values.clone())?,
            "{context}: honest playback",
        );

        type Challenges<C> = nested::stages::challenges::Stage<<C as Cycle>::HostCurve, R>;
        let sign = stage_wire_indices::<C::ScalarField, R, Challenges<C>>(|s| {
            wires_of(&s.base_case.lift)
        })?;
        assert_eq!(sign.len(), 1);
        assert_eq!(
            stage_values[sign[0]],
            if self.base_case {
                C::ScalarField::ONE
            } else {
                -C::ScalarField::ONE
            },
            "{context}: fixture exercises the intended base-case branch",
        );

        match self.relation {
            Relation::ExportPoints => {
                // The independent serialization contract is c, v, x, y, u,
                // then fourteen (x, y) pairs. Do not infer the watched points
                // from the scalar-only CircuitSpec output declaration.
                let names = [
                    "preamble",
                    "inner_error",
                    "outer_error",
                    "query",
                    "eval",
                    "a",
                    "b",
                    "registry_xy",
                    "P",
                    "points_binding",
                    "points_children",
                    "points_registry_wx",
                    "points_ab",
                    "points_f",
                ];
                assert_eq!(
                    cap.instance.len(),
                    5 + 2 * names.len(),
                    "{context}: instance layout"
                );
                for (i, name) in names.iter().enumerate() {
                    let context = format!("{context}: exported point {i} ({name})");
                    let x = cap.instance[5 + 2 * i];
                    let y = cap.instance[5 + 2 * i + 1];
                    let changed = repair_internal_advice(&cap, y, -rec.values[y], &context);
                    assert!(
                        bool::from(C::HostCurve::from_xy(changed[x], changed[y]).is_some()),
                        "{context}: the changed point must stay on the curve",
                    );
                    assert_rejected(&cap, circuit, &make_witness, changed, &context)?;
                    self.checked += 1;
                }
            }
            Relation::EndoscalarBits => {
                let bits =
                    stage_wire_indices::<C::ScalarField, R, EndoscalarStage>(|e| wires_of(&e))?;
                assert_eq!(bits.len(), 128, "{context}: all endoscalar bits");
                let beta = stage_wire_indices::<C::ScalarField, R, Challenges<C>>(|s| {
                    wires_of(&s.beta.lift)
                })?;
                assert_eq!(beta.len(), 1);
                let beta = cap.stage_wires[beta[0]];
                let endoscalar = |values: &[C::ScalarField]| {
                    bits.iter().enumerate().fold(0u128, |endo, (i, &position)| {
                        let bit = values[cap.stage_wires[position]];
                        assert!(
                            bit == C::ScalarField::ZERO || bit == C::ScalarField::ONE,
                            "{context}: Boolean bit {i}"
                        );
                        endo | (u128::from(bit == C::ScalarField::ONE) << i)
                    })
                };
                assert_eq!(
                    lift_endoscalar::<C::ScalarField>(endoscalar(&rec.values)),
                    rec.values[beta]
                );
                for (i, &position) in bits.iter().enumerate() {
                    let context = format!("{context}: endoscalar bit {i}");
                    let bit = cap.stage_wires[position];
                    let changed = repair_internal_advice(
                        &cap,
                        bit,
                        C::ScalarField::ONE - rec.values[bit],
                        &context,
                    );
                    assert_ne!(
                        lift_endoscalar::<C::ScalarField>(endoscalar(&changed)),
                        changed[beta],
                        "{context}: repaired Boolean bits must still disagree with beta",
                    );
                    assert_rejected(&cap, circuit, &make_witness, changed, &context)?;
                    self.checked += 1;
                }
            }
            _ => unreachable!("native relation visited as a nested circuit"),
        }
        Ok(())
    }
}

/// Exercise bootstrap, a seed, a fuse of distinct leaves, and a fuse with nontrivial
/// child accumulators. Header data and left/right histories differ; the
/// nested visitor also checks the captured base-case sign.
/// These depths diversify local witnesses and base-case branches; they do not
/// constitute a recursive propagation test.
fn check_tree(relation: Relation) -> Result<()> {
    let app = ApplicationBuilder::<Pasta, R, 4>::new()
        .register(Leaf::new())?
        .register(Merge::new())?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x0873_0102);

    let mut checker = RelationChecker::new(relation, "bootstrap", true);
    capture_internal_circuits_bootstrap(&app, &mut rng, &mut checker)?;
    checker.assert_complete();

    let mut checker = RelationChecker::new(relation, "seeded", false);
    capture_internal_circuits_seeded(&app, &mut rng, Leaf::new(), Fp::from(7), &mut checker)?;
    checker.assert_complete();

    let (left, _) = app.seed(&mut rng, Leaf::new(), Fp::from(19))?;
    let (right, _) = app.seed(&mut rng, Leaf::new(), Fp::from(43))?;
    let mut checker = RelationChecker::new(relation, "leaves", false);
    capture_internal_circuits(
        &app,
        &mut rng,
        Merge::new(),
        Fp::from(71),
        left.clone(),
        right.clone(),
        &mut checker,
    )?;
    checker.assert_complete();

    let (left_node, _) = app.fuse(&mut rng, Merge::new(), Fp::from(101), left, right)?;
    let (left, _) = app.seed(&mut rng, Leaf::new(), Fp::from(131))?;
    let (right, _) = app.seed(&mut rng, Leaf::new(), Fp::from(173))?;
    let (right_node, _) = app.fuse(&mut rng, Merge::new(), Fp::from(199), left, right)?;
    let mut checker = RelationChecker::new(relation, "nodes", false);
    capture_internal_circuits(
        &app,
        &mut rng,
        Merge::new(),
        Fp::from(233),
        left_node,
        right_node,
        &mut checker,
    )?;
    checker.assert_complete();
    Ok(())
}

#[test]
fn nested_export_locally_binds_every_point() -> Result<()> {
    check_tree(Relation::ExportPoints)
}

#[test]
fn nested_compute_v_locally_binds_every_endoscalar_bit() -> Result<()> {
    check_tree(Relation::EndoscalarBits)
}

#[test]
fn native_bind_beta_locally_binds_every_child_point_with_repaired_advice() -> Result<()> {
    check_tree(Relation::ChildBindingPoints)
}

#[test]
fn native_bind_endoscalar_locally_binds_every_canonical_bit() -> Result<()> {
    check_tree(Relation::NativeEndoscalarBits)
}

#[test]
fn native_bind_endoscalar_locally_binds_walk_endpoint_with_repaired_advice() -> Result<()> {
    check_tree(Relation::NativeWalkEndpoint)
}
