//! Review A09/A10: substitutions with an explicit repair frontier. The
//! original child challenges, traces and walk inputs stay fixed. Only the
//! named polynomial and its direct cache may change, except in the separately
//! named staged-copy and AB-bridge repair tiers. Parent fusions may build
//! all their own data. A10 also covers the instance-change direction of
//! R03/R04, keeping the complete corresponding walk frozen.
//!
//! These whole-proof substitutions retain the old circuit instance advice.
//! Calibration omitted only Export's held[8] equality, then only
//! BindEndoscalar's walk.p() equality. Each omission allowed the matching
//! local repaired-advice mismatch in patcher_relations_tests.rs, while these
//! whole-proof substitutions still failed only the corresponding revdot
//! predicate at the root, parent and grandparent. The local controls isolate
//! the endpoint equalities; these tests check the remaining rejection path.

use alloc::{format, vec::Vec};

use ragu_arithmetic::{
    CurveAffine, Cycle,
    ff::{Field, PrimeField},
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;
use ragu_pasta::{Fp, Fq, Pasta};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    C, HEADER_SIZE, R,
    test_steps::{Add, Leaf, Number},
};
use crate::{
    Application, ApplicationBuilder, Pcd, Proof,
    fuzzing::corrupt::{
        Binding, Corruption, NativeCommitment, NativeRx, NestedCommitment, NestedRx,
    },
    internal::{
        native, nested,
        stage_wires::{StageReader, stage_wire_indices, wires_of},
    },
    verify::VerificationChecks,
};

type App = Application<'static, C, R, HEADER_SIZE>;
type Node = Pcd<C, R, Number>;

struct Fixture {
    app: App,
    node: Node,
    sibling: Node,
}

fn fixture() -> Result<Fixture> {
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x000a_09a1_0873);
    let left = app.seed(&mut rng, Leaf, Fp::from(19))?.0;
    let right = app.seed(&mut rng, Leaf, Fp::from(43))?.0;
    let node = app.fuse(&mut rng, Add, (), left, right)?.0;
    let sibling = app.seed(&mut rng, Leaf, Fp::from(101))?.0;
    assert_ne!(node.data(), sibling.data());
    for honest in [&node, &sibling] {
        assert!(app.verify(honest, &mut rng)?);
    }
    assert_eq!(
        super::stage_values::<nested::stages::challenges::Stage<<C as Cycle>::HostCurve, R>>(
            node.proof().nested_challenges_rx()
        )[20],
        -Fq::ONE,
        "the corrupted node must exercise normal recursion"
    );
    Ok(Fixture { app, node, sibling })
}

fn checks(app: &App, node: &Node, context: &str) -> Result<VerificationChecks> {
    let (accepted, checks) =
        app.verify_with_checks(node, StdRng::seed_from_u64(0x000a_10de_c1de))?;
    let checks = checks.expect("valid metadata reaches every decider predicate");
    assert_eq!(accepted, checks.all(), "{context}: {checks:?}");
    Ok(checks)
}

#[derive(Clone, Copy, Debug)]
enum Batch {
    Native,
    Nested,
}

/// delta * X^degree * (X-u) changes the polynomial without changing its
/// claimed opening. Compare every coefficient and an independent dense
/// Horner evaluation, including a substitution at the degree bound.
fn preserve_evaluation<F: PrimeField>(poly: &mut sparse::Polynomial<F, R>, u: F, degree: usize) {
    let before: Vec<_> = poly.iter_coeffs().collect();
    let delta = F::from(7);
    assert!(degree + 1 < R::num_coeffs());
    assert_ne!(u, F::ZERO);
    let mut after = before.clone();
    after[degree] -= delta * u;
    after[degree + 1] += delta;
    *poly = sparse::Polynomial::from_coeffs(after.clone());
    let eval = |coefficients: &[F]| {
        coefficients
            .iter()
            .rev()
            .fold(F::ZERO, |acc, c| acc * u + c)
    };
    assert_eq!(eval(&before), eval(&after));
    assert_eq!(poly.eval(u), eval(&before));
    for (i, (old, new)) in before.iter().zip(poly.iter_coeffs()).enumerate() {
        assert_eq!(
            new - old,
            if i == degree {
                -delta * u
            } else if i == degree + 1 {
                delta
            } else {
                F::ZERO
            },
            "substitution coefficient {i}"
        );
    }
    assert_ne!(before, after);
}

fn substitute_batch(original: &Proof<C, R>, batch: Batch, degree: usize) -> Result<Proof<C, R>> {
    let mut changed = original.clone();
    match batch {
        Batch::Native => {
            preserve_evaluation(&mut changed.native_p_poly, original.u(), degree);
            let commitment = ReferenceBackend::sparse_commit_to_affine(
                changed.native_p_poly(),
                C::host_generators(Pasta::baked()),
            );
            assert_ne!(commitment, original.native_p_commitment());
            *changed.native_commitment_cache_mut(NativeCommitment::P) = commitment;
            assert_eq!(changed.v(), original.v());
            assert!(
                changed
                    .nested_points_rx
                    .iter_coeffs()
                    .eq(original.nested_points_rx.iter_coeffs())
            );
            let endpoint = stage_wire_indices::<Fq, R, nested::PointsStage<<C as Cycle>::HostCurve>>(
                |stage| wires_of(stage.interstitials.last().unwrap()),
            )?;
            assert_frozen_endpoint(
                &changed.nested_points_rx,
                &endpoint,
                original.native_p_commitment(),
                commitment,
            );
        }
        Batch::Nested => {
            preserve_evaluation(
                &mut changed.nested_p_poly,
                nested::challenge::<C>(original.u())?,
                degree,
            );
            let commitment = ReferenceBackend::sparse_commit_to_affine(
                changed.nested_p_poly(),
                C::nested_generators(Pasta::baked()),
            );
            assert_ne!(commitment, original.nested_p_commitment());
            *changed.nested_commitment_cache_mut(NestedCommitment::P) = commitment;
            assert_eq!(changed.nested_v()?, original.nested_v()?);
            assert!(
                changed
                    .native_points_walk_rx
                    .iter_coeffs()
                    .eq(original.native_points_walk_rx.iter_coeffs())
            );
            let endpoint = stage_wire_indices::<
                Fp,
                R,
                native::stages::points::WalkStage<<C as Cycle>::NestedCurve>,
            >(|stage| wires_of(stage.p()))?;
            assert_frozen_endpoint(
                &changed.native_points_walk_rx,
                &endpoint,
                original.nested_p_commitment(),
                commitment,
            );
        }
    }
    assert_eq!(
        changed.challenges().in_order(),
        original.challenges().in_order()
    );
    assert_eq!(changed.left_header(), original.left_header());
    assert_eq!(changed.right_header(), original.right_header());
    Ok(changed)
}

#[test]
fn evaluation_preserving_batch_substitutions_reject_with_valid_caches() -> Result<()> {
    let Fixture { app, node, .. } = fixture()?;
    for batch in [Batch::Native, Batch::Nested] {
        for degree in [0, R::n() - 1, R::num_coeffs() - 2] {
            let context = format!("{batch:?}, degree {degree}");
            let changed =
                substitute_batch(node.proof(), batch, degree)?.carry::<Number>(*node.data());
            let checks = checks(&app, &changed, &context)?;
            assert_eq!(
                checks,
                VerificationChecks {
                    native_revdot: matches!(batch, Batch::Native),
                    nested_revdot: matches!(batch, Batch::Nested),
                    native_registry: true,
                    nested_registry: true,
                    nested_challenges: true,
                    commitments: true,
                    nested_points: true,
                    transcript: true,
                    ab_bridge: true,
                    mesh: true,
                },
                "only the cross-field claims reject the changed batch commitment: {context}"
            );
        }
    }
    Ok(())
}

/// The false child relation remains fixed while each new parent computes
/// fresh commitments and traces. Require successful fusion and a decider
/// rejection: a prover error cannot count as recursive propagation coverage.
#[test]
fn evaluation_preserving_batch_substitutions_reject_after_parent_and_grandparent_fusions()
-> Result<()> {
    let fixture = fixture()?;
    for batch in [Batch::Native, Batch::Nested] {
        let changed = substitute_batch(fixture.node.proof(), batch, 0)?;
        reject_descendants(&fixture, changed, &format!("{batch:?} v-preserving"), 2)?;
    }
    Ok(())
}

fn reject_descendants(
    fixture: &Fixture,
    changed: Proof<C, R>,
    context: &str,
    generations: usize,
) -> Result<()> {
    let Fixture { app, node, sibling } = fixture;
    assert!(generations > 0);
    for starts_on_left in [true, false] {
        let mut current = changed.clone().carry::<Number>(*node.data());
        let mut honest = node.clone();
        let mut rng = StdRng::seed_from_u64(0x0a10_f05e);
        for generation in 1..=generations {
            let on_left = starts_on_left ^ (generation == 2);
            let expected_data = *current.data() + sibling.data();
            let fuse = |child, rng: &mut StdRng| {
                let (left, right) = if on_left {
                    (child, sibling.clone())
                } else {
                    (sibling.clone(), child)
                };
                app.fuse(rng, Add, (), left, right).map(|(pcd, _)| pcd)
            };
            current = fuse(current, &mut rng)?;
            honest = fuse(honest, &mut rng)?;
            assert_eq!(*current.data(), expected_data);
            assert_eq!(current.data(), honest.data());
            assert!(
                app.verify(&honest, &mut rng)?,
                "honest control at generation {generation}"
            );
            let context =
                format!("{context}, starts_on_left={starts_on_left}, generation={generation}");
            let checks = checks(app, &current, &context)?;
            assert!(
                checks.commitments
                    && checks.transcript
                    && checks.nested_challenges
                    && checks.native_registry
                    && checks.nested_registry
                    && checks.nested_points
                    && checks.ab_bridge
                    && checks.mesh,
                "fresh parent bookkeeping: {context}: {checks:?}"
            );
            assert!(
                !checks.native_revdot || !checks.nested_revdot,
                "lost child residual: {context}: {checks:?}"
            );
            assert!(!checks.all(), "{context}: {checks:?}");
        }
    }
    Ok(())
}

/// Write selected stage coordinates while keeping every other coefficient,
/// including stage blinding, frozen. Reservation indices start after the
/// system gate and alternate between reversed a and d blocks.
fn replace_stage_values<F: PrimeField>(
    poly: &mut sparse::Polynomial<F, R>,
    wires: &[usize],
    values: &[F],
) {
    assert_eq!(wires.len(), values.len());
    let original: Vec<_> = poly.iter_coeffs().collect();
    let mut changed = original.clone();
    for (&wire, &value) in wires.iter().zip(values) {
        let gate = 1 + wire / 2;
        let degree = if wire.is_multiple_of(2) {
            2 * R::n() - 1 - gate
        } else {
            4 * R::n() - 1 - gate
        };
        changed[degree] = value;
    }
    assert_ne!(changed, original, "stage copy repair must change something");
    *poly = sparse::Polynomial::from_coeffs(changed.clone());
    assert!(poly.iter_coeffs().eq(changed));
    let reader = StageReader::new(poly);
    for (&wire, &value) in wires.iter().zip(values) {
        assert_eq!(reader.read(wire), value);
    }
}

fn coordinates<P: CurveAffine>(point: P) -> [P::Base; 2] {
    let c = point
        .coordinates()
        .into_option()
        .expect("nonidentity commitment");
    [*c.x(), *c.y()]
}

fn assert_frozen_endpoint<P: CurveAffine>(
    poly: &sparse::Polynomial<P::Base, R>,
    wires: &[usize],
    original: P,
    changed: P,
) {
    let reader = StageReader::new(poly);
    let staged: Vec<_> = wires.iter().map(|&wire| reader.read(wire)).collect();
    assert_eq!(staged, coordinates(original));
    assert_ne!(
        staged,
        coordinates(changed),
        "the endpoint mismatch must survive cache repair"
    );
}

fn assert_scaled<F: Field>(
    before: &sparse::Polynomial<F, R>,
    after: &sparse::Polynomial<F, R>,
    scale: F,
    u: F,
) {
    assert!(!before.iter_coeffs().eq(after.iter_coeffs()));
    assert!(
        before
            .iter_coeffs()
            .map(|c| c * scale)
            .eq(after.iter_coeffs())
    );
    assert_ne!(
        before.eval(u),
        after.eval(u),
        "the substitution must break the held fold evaluation"
    );
}

/// Reconstruct only the AB bridge and its cache. This explicitly crosses
/// its transcript commitment: challenges stay frozen, so transcript rejection
/// is expected even though the exact AB reconstruction now passes.
fn repair_ab_bridge(proof: &mut Proof<C, R>) -> Result<()> {
    use ragu_circuits::staging::StageExt;

    let rx = nested::stages::ab::Stage::<<C as Cycle>::HostCurve, R>::rx(
        crate::proof::bridge_alpha_power(proof.bridge_alpha, nested::RxIndex::BridgeAB),
        &nested::stages::ab::Witness {
            a: proof.native_commitment(native::RxComponent::AbA),
            b: proof.native_commitment(native::RxComponent::AbB),
            native_points_ab: proof.native_rx_commitment(native::RxIndex::PointsAb),
        },
    )?;
    let commitment =
        ReferenceBackend::sparse_commit_to_affine(&rx, C::nested_generators(Pasta::baked()));
    *proof.nested_rx_mut(NestedRx::BridgeAB) = rx;
    *proof.nested_commitment_cache_mut(NestedCommitment::Rx(NestedRx::BridgeAB)) = commitment;
    Ok(())
}

#[test]
fn c_preserving_accumulator_substitutions_reject_after_staged_repairs_and_fusion() -> Result<()> {
    let fixture = fixture()?;
    let Fixture { app, node, .. } = &fixture;
    for batch in [Batch::Native, Batch::Nested] {
        let original = node.proof();
        let mut changed = original.clone();
        let corruption = match batch {
            Batch::Native => Corruption::RescaleNativeAccumulator(Fp::from(5)),
            Batch::Nested => Corruption::RescaleNestedAccumulator(Fq::from(5)),
        };
        assert_eq!(changed.corrupt(corruption), Binding::MustReject);
        // Tier one already exists in the corruption suite. Its check vector
        // is a baseline for distinguishing the guards removed by later tiers.
        let cache_only = checks(
            app,
            &changed.clone().carry::<Number>(*node.data()),
            "cache-only rescale",
        )?;
        assert!(
            cache_only.commitments && cache_only.transcript,
            "{batch:?}: {cache_only:?}"
        );
        assert!(
            !cache_only.mesh,
            "the fold evaluations changed: {batch:?}: {cache_only:?}"
        );
        match batch {
            Batch::Native => {
                assert!(!cache_only.ab_bridge, "{cache_only:?}");
                repair_ab_bridge(&mut changed)?;
            }
            Batch::Nested => {
                assert!(!cache_only.nested_points, "{cache_only:?}");
                let wires = stage_wire_indices::<
                    Fp,
                    R,
                    native::stages::points::AbStage<<C as Cycle>::NestedCurve>,
                >(|stage| {
                    let mut wires = wires_of(&stage.a)?;
                    wires.extend(wires_of(&stage.b)?);
                    Ok(wires)
                })?;
                let values: Vec<_> = [changed.nested_a_commitment(), changed.nested_b_commitment()]
                    .into_iter()
                    .flat_map(coordinates)
                    .collect();
                replace_stage_values(&mut changed.native_points_ab_rx, &wires, &values);
                let commitment = ReferenceBackend::sparse_commit_to_affine(
                    &changed.native_points_ab_rx,
                    C::host_generators(Pasta::baked()),
                );
                *changed.native_commitment_cache_mut(NativeCommitment::Rx(NativeRx::PointsAb)) =
                    commitment;
                let staged = checks(
                    app,
                    &changed.clone().carry::<Number>(*node.data()),
                    "repaired nested A/B stage",
                )?;
                assert!(
                    staged.commitments && staged.transcript && staged.nested_points,
                    "{staged:?}"
                );
                assert!(!staged.ab_bridge && !staged.mesh, "{staged:?}");
                repair_ab_bridge(&mut changed)?;
            }
        }
        let repaired = checks(
            app,
            &changed.clone().carry::<Number>(*node.data()),
            "repaired AB bridge",
        )?;
        assert!(
            repaired.commitments && repaired.nested_points && repaired.ab_bridge,
            "{batch:?}: {repaired:?}"
        );
        assert!(
            !repaired.transcript && !repaired.mesh,
            "{batch:?}: {repaired:?}"
        );
        assert!(!repaired.all());
        assert_eq!(changed.native_c(), original.native_c());
        assert_eq!(changed.nested_c(), original.nested_c());
        assert_eq!(
            changed.challenges().in_order(),
            original.challenges().in_order()
        );
        // The current fold evaluations stay frozen while A(u) and B(u)
        // change. This witnesses the surviving mesh rejection directly.
        assert!(
            changed[native::RxIndex::Eval]
                .iter_coeffs()
                .eq(original[native::RxIndex::Eval].iter_coeffs())
        );
        assert!(
            changed[nested::RxIndex::BridgeEval]
                .iter_coeffs()
                .eq(original[nested::RxIndex::BridgeEval].iter_coeffs())
        );
        // No tier may silently restore the prescribed accumulator.
        match batch {
            Batch::Native => {
                assert_scaled(
                    &original.native_a_poly,
                    &changed.native_a_poly,
                    Fp::from(5),
                    original.u(),
                );
                assert_scaled(
                    &original.native_b_poly,
                    &changed.native_b_poly,
                    Fp::from(5).invert().unwrap(),
                    original.u(),
                );
            }
            Batch::Nested => {
                let u = nested::challenge::<C>(original.u())?;
                assert_scaled(
                    &original.nested_a_poly,
                    &changed.nested_a_poly,
                    Fq::from(5),
                    u,
                );
                assert_scaled(
                    &original.nested_b_poly,
                    &changed.nested_b_poly,
                    Fq::from(5).invert().unwrap(),
                    u,
                );
            }
        }
        reject_descendants(
            &fixture,
            changed,
            &format!("{batch:?} c-preserving, repaired AB bridge"),
            1,
        )?;
    }
    Ok(())
}
