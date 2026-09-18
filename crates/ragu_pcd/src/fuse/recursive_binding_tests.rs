//! Review V05, R07/R08 and R09: deferred bindings and valid witness freedom.
//!
//! Each attack freezes the original child's transcript, application statement
//! and circuit traces. Only the named object and its direct commitment cache
//! may change; derived instance slots and all newly proved ancestors follow
//! that change. Thus these are accumulated-residual regressions, not isolated
//! tests of an individual equality with all child advice repaired. The local
//! equality calibration lives in patcher_relations_tests.rs.
//!
//! Every mutated child must successfully fuse twice (three times for splices).
//! Fresh root bookkeeping must pass while an accumulated claim still fails.
//! Alternating child roles exercises both sides for every mutation. Matching
//! honest chains are constructed once per fixture instead of reproving them
//! for every coefficient. Separate valid replacements cover repeated children.

use alloc::{format, vec::Vec};

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::sparse;
use ragu_core::Result;
use ragu_pasta::{Fp, Fq, Pasta};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    C, HEADER_SIZE, R, challenge_stage_coefficients,
    test_steps::{Add, AddSquare, Leaf, Number},
};
use crate::{
    Application, ApplicationBuilder, Pcd, Proof,
    fuzzing::corrupt::{NativeCommitment, NativeRx, NestedCommitment, NestedRx, RxComponent},
    internal::native,
    verify::VerificationChecks,
};

type App = Application<'static, C, R, HEADER_SIZE>;
type Node = Pcd<C, R, Number>;
const CHALLENGES: NestedCommitment = NestedCommitment::Rx(NestedRx::ChallengeStage);

struct Fixture {
    app: App,
    original: Node,
    replacement: Node,
    fresh_trace: Node,
    sibling: Node,
}

fn fixture() -> Result<Fixture> {
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .register(AddSquare)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x8730_0809);
    let left = app.seed(&mut rng, Leaf, Fp::from(19))?.0;
    let right = app.seed(&mut rng, Leaf, Fp::from(43))?.0;
    let sibling = app.seed(&mut rng, Leaf, Fp::from(101))?.0;
    // Keep both inherited proofs identical. Opposite private roots and fresh
    // blinding give different valid traces for the same public statement.
    let original = app
        .fuse(
            &mut StdRng::seed_from_u64(0x8730_c001),
            AddSquare,
            Fp::from(3),
            left.clone(),
            right.clone(),
        )?
        .0;
    let replacement = app
        .fuse(
            &mut StdRng::seed_from_u64(0x8730_c002),
            AddSquare,
            -Fp::from(3),
            left.clone(),
            right.clone(),
        )?
        .0;
    let fresh_trace = app
        .fuse(
            &mut StdRng::seed_from_u64(0x8730_c001),
            AddSquare,
            -Fp::from(3),
            left,
            right,
        )?
        .0;
    assert_eq!(*original.data(), Fp::from(19 + 43 + 9));
    assert_eq!(original.data(), replacement.data());
    assert_eq!(original.data(), fresh_trace.data());
    assert_eq!(
        original.proof().circuit_id(),
        replacement.proof().circuit_id()
    );
    assert_eq!(
        original.proof().left_header(),
        replacement.proof().left_header()
    );
    assert_eq!(
        original.proof().right_header(),
        replacement.proof().right_header()
    );
    assert!(
        original
            .proof()
            .test_mismatch(replacement.proof())
            .is_some()
    );
    assert!(
        !original
            .proof()
            .native_application_rx
            .iter_coeffs()
            .eq(replacement.proof().native_application_rx.iter_coeffs()),
        "opposite private roots must give different application traces"
    );
    for node in [&original, &replacement, &fresh_trace, &sibling] {
        assert!(checks(&app, node, "honest fixture")?.all());
    }
    Ok(Fixture {
        app,
        original,
        replacement,
        fresh_trace,
        sibling,
    })
}

fn checks(app: &App, node: &Node, context: &str) -> Result<VerificationChecks> {
    let rng = StdRng::seed_from_u64(0x8730_dec1);
    let (accepted, checks) = app.verify_with_checks(node, rng)?;
    let checks = checks.expect("valid metadata must reach the decider predicates");
    assert_eq!(accepted, checks.all(), "{context}: {checks:?}");
    Ok(checks)
}

fn fuse(app: &App, child: &Node, sibling: &Node, on_left: bool, seed: u64) -> Result<Node> {
    let (left, right) = if on_left {
        (child.clone(), sibling.clone())
    } else {
        (sibling.clone(), child.clone())
    };
    Ok(app
        .fuse(&mut StdRng::seed_from_u64(seed), Add, (), left, right)?
        .0)
}

/// These controls authenticate the same public statements and tree shapes as
/// the attacks. They are reusable because Add's output depends only on data.
struct Descendants {
    honest: [Vec<Node>; 2],
}

impl Descendants {
    fn new(app: &App, original: &Node, sibling: &Node, generations: usize) -> Result<Self> {
        let mut honest = [Vec::new(), Vec::new()];
        for (side, chain) in honest.iter_mut().enumerate() {
            let mut current = original.clone();
            for generation in 0..generations {
                current = fuse(
                    app,
                    &current,
                    sibling,
                    (side + generation).is_multiple_of(2),
                    0x8730_aa00 + generation as u64,
                )?;
                assert!(checks(app, &current, "honest descendant")?.all());
                chain.push(current.clone());
            }
        }
        Ok(Self { honest })
    }

    fn reject(
        &self,
        app: &App,
        mut changed: Node,
        sibling: &Node,
        side: usize,
        context: &str,
    ) -> Result<()> {
        for (generation, honest) in self.honest[side].iter().enumerate() {
            changed = fuse(
                app,
                &changed,
                sibling,
                (side + generation).is_multiple_of(2),
                0x8730_bb00 + generation as u64,
            )?;
            assert_eq!(changed.data(), honest.data());
            let context = format!(
                "{context}, generation={}, side={}",
                generation + 1,
                (side + generation) % 2
            );
            let checks = checks(app, &changed, &context)?;
            assert!(
                checks.native_registry
                    && checks.nested_registry
                    && checks.nested_challenges
                    && checks.commitments
                    && checks.nested_points
                    && checks.transcript
                    && checks.ab_bridge
                    && checks.mesh,
                "fresh root bookkeeping must pass: {context}: {checks:?}"
            );
            assert!(
                !checks.native_revdot || !checks.nested_revdot,
                "lost child residual: {context}: {checks:?}"
            );
        }
        Ok(())
    }
}

fn repair_challenge_cache(changed: &mut Proof<C, R>) {
    *changed.nested_commitment_cache_mut(CHALLENGES) = ReferenceBackend::sparse_commit_to_affine(
        changed.nested_challenges_rx(),
        C::nested_generators(Pasta::baked()),
    );
}

fn assert_only_challenge_stage_changed(original: &Proof<C, R>, changed: &Proof<C, R>) {
    assert_ne!(
        changed.nested_challenges_commitment(),
        original.nested_challenges_commitment()
    );
    let mut restored = changed.clone();
    restored.nested_challenges_rx = original.nested_challenges_rx.clone();
    *restored.nested_commitment_cache_mut(CHALLENGES) = original.nested_challenges_commitment();
    assert_eq!(
        restored.test_mismatch(original),
        None,
        "every other child object is frozen"
    );
}

fn challenge_coefficients_reject_recursively(from_seed: bool) -> Result<()> {
    let Fixture {
        app,
        mut original,
        sibling,
        ..
    } = fixture()?;
    if from_seed {
        original = app
            .seed(
                &mut StdRng::seed_from_u64(0x8730_ba5e),
                Leaf,
                *original.data(),
            )?
            .0;
    }
    let descendants = Descendants::new(&app, &original, &sibling, 2)?;
    let coefficients = challenge_stage_coefficients();
    assert_eq!(
        coefficients.len(),
        25,
        "all twelve lifts/sign, twelve companions and blinding"
    );
    for (i, (name, wire, degree)) in coefficients.into_iter().enumerate() {
        let mut changed = original.proof().clone();
        let before: Vec<_> = changed.nested_challenges_rx.iter_coeffs().collect();
        let mut after = before.clone();
        if wire == "d" || wire == "blinding" {
            assert_eq!(after[degree], Fq::ZERO);
        }
        after[degree] = if name == "sign" && wire == "a" {
            // Seeds consume bootstrap proofs with ordinary unit headers.
            // Both fixtures therefore take the recursive branch.
            assert_eq!(after[degree], -Fq::ONE);
            -after[degree]
        } else {
            after[degree] + Fq::ONE
        };
        changed.nested_challenges_rx = sparse::Polynomial::from_coeffs(after.clone());
        repair_challenge_cache(&mut changed);
        assert!(changed.nested_challenges_rx.iter_coeffs().eq(after));
        assert_only_challenge_stage_changed(original.proof(), &changed);
        let changed = changed.carry::<Number>(*original.data());
        let context = format!("V05 from_seed={from_seed}, {name}/{wire}");
        let root = checks(&app, &changed, &context)?;
        assert!(
            !root.nested_challenges && root.commitments && root.transcript,
            "{context}: {root:?}"
        );
        descendants.reject(&app, changed, &sibling, i % 2, &context)?;
    }
    Ok(())
}

#[test]
fn challenge_coefficients_reject_after_parent_and_grandparent_from_seed() -> Result<()> {
    challenge_coefficients_reject_recursively(true)
}

#[test]
fn challenge_coefficients_reject_after_parent_and_grandparent_from_internal_node() -> Result<()> {
    challenge_coefficients_reject_recursively(false)
}

#[test]
fn same_header_early_point_stage_splices_reject_through_three_fusions() -> Result<()> {
    let Fixture {
        app,
        original,
        replacement,
        sibling,
        ..
    } = fixture()?;
    let descendants = Descendants::new(&app, &original, &sibling, 3)?;
    // Independent semantic mapping: the five early native stage commitments
    // occupy Export[9..14], in their transcript commitment order.
    for (slot, index, mutable_index) in [
        (9, native::RxIndex::PointsBinding, NativeRx::PointsBinding),
        (
            10,
            native::RxIndex::PointsChildren,
            NativeRx::PointsChildren,
        ),
        (
            11,
            native::RxIndex::PointsRegistryWx,
            NativeRx::PointsRegistryWx,
        ),
        (12, native::RxIndex::PointsAb, NativeRx::PointsAb),
        (13, native::RxIndex::PointsF, NativeRx::PointsF),
    ] {
        let mut changed = original.proof().clone();
        let component = native::RxComponent::Rx(index);
        let mutable_component = RxComponent::Rx(mutable_index);
        let cache = NativeCommitment::Rx(mutable_index);
        *changed.native_component_mut(mutable_component) = replacement.proof()[component].clone();
        let commitment = ReferenceBackend::sparse_commit_to_affine(
            &changed[component],
            C::host_generators(Pasta::baked()),
        );
        assert_eq!(commitment, replacement.proof().native_rx_commitment(index));
        assert_ne!(commitment, original.proof().native_rx_commitment(index));
        *changed.native_commitment_cache_mut(cache) = commitment;
        assert_eq!(changed.nested_instance()?.exported[slot], commitment);

        let mut restored = changed.clone();
        *restored.native_component_mut(mutable_component) = original.proof()[component].clone();
        *restored.native_commitment_cache_mut(cache) = original.proof().native_rx_commitment(index);
        assert_eq!(
            restored.test_mismatch(original.proof()),
            None,
            "the authentic bridge copies and all child traces stay frozen"
        );

        let context = format!("R07/R08 {index:?}, Export[{slot}]");
        let changed = changed.carry::<Number>(*original.data());
        let root = checks(&app, &changed, &context)?;
        assert!(
            root.commitments && root.transcript && root.nested_challenges,
            "{context}: {root:?}"
        );
        assert!(
            !root.nested_revdot,
            "nested claims must reject the source/stage mismatch: {context}: {root:?}"
        );
        descendants.reject(&app, changed, &sibling, slot % 2, &context)?;
    }
    Ok(())
}

#[test]
fn same_header_challenge_binding_splices_reject_through_three_fusions() -> Result<()> {
    let Fixture {
        app,
        original,
        replacement,
        sibling,
        ..
    } = fixture()?;
    let descendants = Descendants::new(&app, &original, &sibling, 3)?;
    for splice_partial in [false, true] {
        let mut changed = original.proof().clone();
        if splice_partial {
            changed.nested_challenges_partial = replacement.proof().nested_challenges_partial();
            assert_ne!(
                changed.nested_challenges_partial(),
                original.proof().nested_challenges_partial()
            );
            let mut restored = changed.clone();
            restored.nested_challenges_partial = original.proof().nested_challenges_partial();
            assert_eq!(restored.test_mismatch(original.proof()), None);
        } else {
            changed.nested_challenges_rx = replacement.proof().nested_challenges_rx.clone();
            repair_challenge_cache(&mut changed);
            assert_eq!(
                changed.nested_challenges_commitment(),
                replacement.proof().nested_challenges_commitment()
            );
            assert_only_challenge_stage_changed(original.proof(), &changed);
        }
        let context = format!("R08 challenge binding, splice_partial={splice_partial}");
        let changed = changed.carry::<Number>(*original.data());
        let root = checks(&app, &changed, &context)?;
        assert!(root.commitments && root.transcript, "{context}: {root:?}");
        assert_eq!(
            root.nested_challenges, splice_partial,
            "{context}: {root:?}"
        );
        assert!(!root.all(), "{context}: {root:?}");
        descendants.reject(
            &app,
            changed,
            &sibling,
            usize::from(splice_partial),
            &context,
        )?;
    }
    Ok(())
}

#[test]
fn valid_private_witness_replacements_and_repeated_children_verify() -> Result<()> {
    let Fixture {
        app,
        original,
        fresh_trace: replacement,
        sibling,
        ..
    } = fixture()?;
    // The private root's sign changes only this fresh application trace and
    // its direct cache. Every inherited instance, stage, accumulator and
    // transcript object is identical, so this is a constructive validity
    // witness for a partial replacement, not just a new unrelated proof.
    assert_ne!(
        original
            .proof()
            .native_rx_commitment(native::RxIndex::Application),
        replacement
            .proof()
            .native_rx_commitment(native::RxIndex::Application)
    );
    let mut restored = replacement.proof().clone();
    restored.native_application_rx = original.proof().native_application_rx.clone();
    *restored.native_commitment_cache_mut(NativeCommitment::Rx(NativeRx::Application)) = original
        .proof()
        .native_rx_commitment(native::RxIndex::Application);
    assert_eq!(restored.test_mismatch(original.proof()), None);
    // R09: complete, valid replacements of the fresh parent's private trace
    // must be accepted. R08's partial transplants above must be rejected.
    // Include balanced, unbalanced and identical-child controls (O10).
    for repeated in [false, true] {
        let (left_sibling, right_sibling) = if repeated {
            (&original, &replacement)
        } else {
            (&sibling, &sibling)
        };
        for on_left in [false, true] {
            let mut a = fuse(&app, &original, left_sibling, on_left, 0x8730_0900)?;
            let mut b = fuse(&app, &replacement, right_sibling, on_left, 0x8730_0900)?;
            for generation in 0u64..3 {
                assert_eq!(a.data(), b.data());
                assert!(a.proof().test_mismatch(b.proof()).is_some());
                assert!(checks(&app, &a, "original witness control")?.all());
                assert!(checks(&app, &b, "replacement witness control")?.all());
                if generation < 2 {
                    a = fuse(
                        &app,
                        &a,
                        &sibling,
                        generation.is_multiple_of(2),
                        0x8730_0901 + generation,
                    )?;
                    b = fuse(
                        &app,
                        &b,
                        &sibling,
                        generation.is_multiple_of(2),
                        0x8730_0901 + generation,
                    )?;
                }
            }
        }
    }
    Ok(())
}
