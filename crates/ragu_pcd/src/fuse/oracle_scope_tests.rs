//! Review O01/O11: a corruption verdict belongs to a specific frozen/repair
//! scope. Private verifier randomness is sampled after the proof is fixed.
//! The known-seed controls below deliberately reverse that order; they are
//! local batching counterexamples, not Fiat-Shamir forgeries.
//!
//! Calibration: classifying high native coefficients as Unclassified fails
//! the stale-cache control below. Combining MustReject verdicts by OR fails
//! the bridge-alias cancellation control. Both source mutants were checked
//! separately and restored.

use alloc::vec::Vec;

use ragu_arithmetic::{Cycle, FixedGenerators, ff::Field};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use ragu_pasta::{Fp, Fq, Pasta};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    C, HEADER_SIZE, R,
    test_steps::{Add, Leaf, Number},
};
use crate::{
    Application, ApplicationBuilder, Pcd,
    fuzzing::corrupt::{
        Binding, BridgeCommitment, Challenge, Corruption, NativeCommitment, NativeRx,
        NestedAccumulator, NestedCommitment, NestedRx, RxComponent, Side,
    },
    internal::{native, nested},
    verify::VerificationChecks,
};

type App = Application<'static, C, R, HEADER_SIZE>;
type Node = Pcd<C, R, Number>;

fn fixture() -> Result<(App, Node)> {
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x0000_0010_0187_3abc);
    let left = app.seed(&mut rng, Leaf, Fp::from(17))?.0;
    let right = app.seed(&mut rng, Leaf, Fp::from(43))?.0;
    let node = app.fuse(&mut rng, Add, (), left, right)?.0;
    assert!(app.verify(&node, &mut rng)?);
    Ok((app, node))
}

fn checks(app: &App, node: &Node, seed: u64) -> Result<VerificationChecks> {
    let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(seed))?;
    let checks = checks.expect("well-formed metadata reaches all predicates");
    assert_eq!(accepted, checks.all());
    Ok(checks)
}

#[test]
fn no_op_corruptions_preserve_valid_proofs() -> Result<()> {
    let (app, node) = fixture()?;
    let proof = node.proof();
    let mut edits = Vec::new();
    for side in [Side::Left, Side::Right] {
        edits.push(Corruption::HeaderLen {
            side,
            len: HEADER_SIZE,
        });
        edits.push(Corruption::HeaderElement {
            side,
            index: 0,
            delta: Fp::ZERO,
        });
        edits.push(Corruption::HeaderElement {
            side,
            index: HEADER_SIZE,
            delta: Fp::ONE,
        });
    }
    for scale in [Fp::ZERO, Fp::ONE] {
        edits.push(Corruption::RescaleNativeAccumulator(scale));
    }
    for scale in [Fq::ZERO, Fq::ONE] {
        edits.push(Corruption::RescaleNestedAccumulator(scale));
    }
    edits.push(Corruption::CircuitId(usize::from(proof.circuit_id()) as u32));
    edits.push(Corruption::Challenge(Challenge::U, proof.u()));
    for (coeff, delta, nested_delta) in [
        (0, Fp::ZERO, Fq::ZERO),
        (R::num_coeffs(), Fp::ONE, Fq::ONE),
        (usize::MAX, Fp::ONE, Fq::ONE),
    ] {
        for component in [RxComponent::AbA, RxComponent::AbB]
            .into_iter()
            .chain(NativeRx::ALL.map(RxComponent::Rx))
        {
            edits.push(Corruption::NativeCoeff {
                component,
                coeff,
                delta,
            });
        }
        for index in NestedRx::ALL {
            edits.push(Corruption::NestedCoeff {
                index,
                coeff,
                delta: nested_delta,
            });
        }
        for which in NestedAccumulator::ALL {
            edits.push(Corruption::NestedAccumulatorCoeff {
                which,
                coeff,
                delta: nested_delta,
            });
        }
        edits.push(Corruption::RegistryXyCoeff { coeff, delta });
        edits.push(Corruption::PCoeff { coeff, delta });
        edits.push(Corruption::NestedRegistryXyCoeff {
            coeff,
            delta: nested_delta,
        });
        edits.push(Corruption::NestedPCoeff {
            coeff,
            delta: nested_delta,
        });
    }
    // Check every proof field after each operation so a sequence of falsely
    // classified edits cannot hide corruption by cancelling it later.
    let mut changed = proof.clone();
    for edit in edits {
        let context = alloc::format!("{edit:?}");
        assert_eq!(changed.corrupt(edit), Binding::NoOp, "{context}");
        assert_eq!(changed.test_mismatch(proof), None, "{context}");
    }
    assert!(app.verify(
        &changed.carry::<Number>(*node.data()),
        StdRng::seed_from_u64(17)
    )?);
    Ok(())
}

#[test]
fn aliased_commitment_edits_can_restore_a_valid_proof() -> Result<()> {
    let (app, node) = fixture()?;
    // All eight bridges also have names in the nested cache vocabulary.
    let aliases = [
        (BridgeCommitment::Preamble, NestedRx::BridgePreamble),
        (BridgeCommitment::SPrime, NestedRx::BridgeSPrime),
        (BridgeCommitment::InnerError, NestedRx::BridgeInnerError),
        (BridgeCommitment::OuterError, NestedRx::BridgeOuterError),
        (BridgeCommitment::AB, NestedRx::BridgeAB),
        (BridgeCommitment::Query, NestedRx::BridgeQuery),
        (BridgeCommitment::F, NestedRx::BridgeF),
        (BridgeCommitment::Eval, NestedRx::BridgeEval),
    ];
    for (bridge, nested) in aliases {
        let mut proof = node.proof().clone();
        let first = proof.corrupt(Corruption::NegateBridgeCommitment(bridge));
        assert_eq!(first, Binding::MustReject);
        assert!(!checks(&app, &proof.clone().carry::<Number>(*node.data()), 101)?.commitments);
        let second = proof.corrupt(Corruption::NegateNestedCommitment(NestedCommitment::Rx(
            nested,
        )));
        assert_eq!(second, Binding::MustReject);
        assert_eq!(first.combine(second), Binding::Unclassified);
        assert_eq!(proof.test_mismatch(node.proof()), None);
        assert!(checks(&app, &proof.carry::<Number>(*node.data()), 101)?.all());
    }
    Ok(())
}

#[test]
fn repairing_a_cache_changes_the_rejection_scope() -> Result<()> {
    let (app, node) = fixture()?;
    for coeff in [R::n(), R::num_coeffs() - 1] {
        let mut proof = node.proof().clone();
        let component = RxComponent::Rx(NativeRx::Hashes1);
        let before = proof.native_component_mut(component).clone();
        let verdict = proof.corrupt(Corruption::NativeCoeff {
            component,
            coeff,
            delta: Fp::ONE,
        });
        assert_eq!(verdict, Binding::MustReject);
        assert!(!checks(&app, &proof.clone().carry::<Number>(*node.data()), 102)?.commitments);
        let expected = ReferenceBackend::sparse_commit_to_affine(
            proof.native_component_mut(component),
            C::host_generators(Pasta::baked()),
        );
        *proof.native_commitment_cache_mut(NativeCommitment::Rx(NativeRx::Hashes1)) = expected;
        // Attack preservation: the repair changes only the direct cache.
        for (i, (old, new)) in before
            .iter_coeffs()
            .zip(proof.native_component_mut(component).iter_coeffs())
            .enumerate()
        {
            assert_eq!(new - old, if i == coeff { Fp::ONE } else { Fp::ZERO });
        }
        assert!(checks(&app, &proof.carry::<Number>(*node.data()), 102)?.commitments);

        let mut proof = node.proof().clone();
        let before = proof.nested_rx_mut(NestedRx::ComputeV).clone();
        let verdict = proof.corrupt(Corruption::NestedCoeff {
            index: NestedRx::ComputeV,
            coeff,
            delta: Fq::ONE,
        });
        assert_eq!(verdict, Binding::MustReject);
        assert!(!checks(&app, &proof.clone().carry::<Number>(*node.data()), 103)?.commitments);
        let expected = ReferenceBackend::sparse_commit_to_affine(
            proof.nested_rx_mut(NestedRx::ComputeV),
            C::nested_generators(Pasta::baked()),
        );
        *proof.nested_commitment_cache_mut(NestedCommitment::Rx(NestedRx::ComputeV)) = expected;
        for (i, (old, new)) in before
            .iter_coeffs()
            .zip(proof.nested_rx_mut(NestedRx::ComputeV).iter_coeffs())
            .enumerate()
        {
            assert_eq!(new - old, if i == coeff { Fq::ONE } else { Fq::ZERO });
        }
        assert!(checks(&app, &proof.carry::<Number>(*node.data()), 103)?.commitments);
        // The earlier MustReject is not an oracle for this repaired proof.
        // Other predicates may reject; cache consistency alone certifies no
        // ValidReencoding and we impose no whole-verifier outcome here.
    }
    Ok(())
}

#[test]
fn paired_cache_errors_cancel_at_a_known_seed_and_reject_under_fresh_seeds() -> Result<()> {
    let (app, node) = fixture()?;
    const KNOWN_SEED: u64 = 0x0011_0087_3bad;
    let mut rng = StdRng::seed_from_u64(KNOWN_SEED);
    // Exact verifier sampling schedule: native w/y/z, nested y/z/w,
    // then one cache-batch scalar per field. This control must fail if the
    // schedule changes without updating its causal model.
    for _ in 0..3 {
        let _ = Fp::random(&mut rng);
    }
    for _ in 0..3 {
        let _ = Fq::random(&mut rng);
    }
    let native_r = Fp::random(&mut rng);
    let nested_r = Fq::random(&mut rng);
    assert_ne!(native_r, Fp::ZERO);
    assert_ne!(nested_r, Fq::ZERO);

    for nested_batch in [false, true] {
        let mut proof = node.proof().clone();
        if nested_batch {
            let a = nested::RxIndex::Collapse;
            let b = nested::RxIndex::ComputeV;
            let i = nested::RxIndex::ALL.iter().position(|x| *x == a).unwrap();
            let j = nested::RxIndex::ALL.iter().position(|x| *x == b).unwrap();
            assert!(i < j);
            let delta = C::nested_generators(Pasta::baked()).g()[0] * Fq::from(7);
            let first = proof.nested_commitment_cache_mut(NestedCommitment::Rx(NestedRx::Collapse));
            *first = (*first + delta).into();
            assert!(
                !checks(
                    &app,
                    &proof.clone().carry::<Number>(*node.data()),
                    KNOWN_SEED
                )?
                .commitments
            );
            let second =
                proof.nested_commitment_cache_mut(NestedCommitment::Rx(NestedRx::ComputeV));
            *second = (*second - delta * nested_r.pow_vartime([(j - i) as u64])).into();
        } else {
            let a = native::RxIndex::Hashes1;
            let b = native::RxIndex::Hashes2;
            let i = native::RxIndex::ALL.iter().position(|x| *x == a).unwrap();
            let j = native::RxIndex::ALL.iter().position(|x| *x == b).unwrap();
            assert!(i < j);
            let delta = C::host_generators(Pasta::baked()).g()[0] * Fp::from(7);
            let first = proof.native_commitment_cache_mut(NativeCommitment::Rx(NativeRx::Hashes1));
            *first = (*first + delta).into();
            assert!(
                !checks(
                    &app,
                    &proof.clone().carry::<Number>(*node.data()),
                    KNOWN_SEED
                )?
                .commitments
            );
            let second = proof.native_commitment_cache_mut(NativeCommitment::Rx(NativeRx::Hashes2));
            *second = (*second - delta * native_r.pow_vartime([(j - i) as u64])).into();
        }
        let changed = proof.carry::<Number>(*node.data());
        assert!(
            checks(&app, &changed, KNOWN_SEED)?.all(),
            "known-randomness cancellation control"
        );
        // No mutation occurs after this point. Fresh coins expose the same
        // fixed pair; all nine other predicates continue to pass.
        for seed in [11, 23, 47, 97, 193, 389, 769, 1543] {
            let mut result = checks(&app, &changed, seed)?;
            assert!(!result.commitments, "nested={nested_batch}, seed={seed}");
            result.commitments = true;
            assert!(
                result.all(),
                "only the cache batch should reject: {result:?}"
            );
        }
    }
    Ok(())
}
