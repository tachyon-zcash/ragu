//! T07/T08: real Eval retries and an independent, explicit transcript schedule.
//!
//! A test-only response hook forces the rare range-rejection branch after a
//! real Eval commitment has been sampled and hashed. It never substitutes an
//! accepted challenge. Every retained payload and every unmodified hash output
//! is checked against a fresh replay of the frozen prefix.

use alloc::{boxed::Box, vec::Vec};

use ragu_arithmetic::{CurveAffine, ff::PrimeField};
use ragu_circuits::staging::Stage;
use ragu_core::Error;
use ragu_pasta::{EpAffine, EqAffine};
use ragu_primitives::{GadgetExt, Point, Simulator, poseidon::SpongeState};

use super::{test_steps::*, *};
use crate::{
    Pcd, RAGU_TAG,
    fuse::EvalAttempt,
    internal::{native, transcript::Transcript},
};

pub(crate) struct Replay<F> {
    pub(crate) challenges: [F; 11],
    pub(crate) state: Vec<F>,
}

pub(crate) fn bridge_points(proof: &Proof<C, R>) -> [EpAffine; 8] {
    [
        proof.bridge_preamble_commitment(),
        proof.bridge_s_prime_commitment(),
        proof.bridge_inner_error_commitment(),
        proof.bridge_outer_error_commitment(),
        proof.bridge_ab_commitment(),
        proof.bridge_query_commitment(),
        proof.bridge_f_commitment(),
        proof.bridge_eval_commitment(),
    ]
}

/// Explicit schedule, independent of fuse, Hashes1/2, and verify. `resume`
/// supplies untrusted state and an optional extra squeeze before mu. `leaked`
/// models keeping rejected attempts in the sponge before the accepted Eval.
pub(crate) fn replay(
    points: &[EpAffine; 8],
    resume: Option<(&[Fp], usize)>,
    leaked: &[EpAffine],
) -> Result<Replay<Fp>> {
    replay_for::<C>(Pasta::baked(), points, resume, leaked)
}

pub(crate) fn replay_for<C: Cycle>(
    params: &C::Params,
    points: &[C::NestedCurve; 8],
    resume: Option<(&[C::CircuitField], usize)>,
    leaked: &[C::NestedCurve],
) -> Result<Replay<C::CircuitField>> {
    let mut dr = Simulator::<C::CircuitField>::new();
    let params = C::circuit_poseidon(params);
    let mut transcript = Transcript::new(&mut dr, params, RAGU_TAG)?;
    macro_rules! absorb {
        ($point:expr) => {
            Point::constant(&mut dr, $point)?.write(&mut dr, &mut transcript)?
        };
    }
    macro_rules! squeeze {
        () => {
            *transcript.challenge(&mut dr)?.value().take()
        };
    }
    absorb!(points[0]);
    let w = squeeze!();
    absorb!(points[1]);
    let y = squeeze!();
    let z = squeeze!();
    absorb!(points[2]);
    let state = transcript
        .clone()
        .save_state(&mut dr)
        .unwrap()
        .into_elements()
        .into_iter()
        .map(|e| *e.value().take())
        .collect();
    let (mu, nu) = if let Some((state, skip)) = resume {
        let state = SpongeState::from_elements(FixedVec::try_from_fn(|i| {
            Ok(Element::constant(&mut dr, state[i]))
        })?);
        let mut resumed = Transcript::resume_from_state(state, params);
        for _ in 0..skip {
            resumed.challenge(&mut dr)?;
        }
        let mu = *resumed.challenge(&mut dr)?.value().take();
        let nu = *resumed.challenge(&mut dr)?.value().take();
        transcript = resumed.into_transcript();
        (mu, nu)
    } else {
        (squeeze!(), squeeze!())
    };
    absorb!(points[3]);
    let mu_prime = squeeze!();
    let nu_prime = squeeze!();
    absorb!(points[4]);
    let x = squeeze!();
    absorb!(points[5]);
    let alpha = squeeze!();
    absorb!(points[6]);
    let u = squeeze!();
    for point in leaked {
        absorb!(*point);
        let _ = squeeze!();
    }
    absorb!(points[7]);
    let beta = squeeze!();
    Ok(Replay {
        challenges: [w, y, z, mu, nu, mu_prime, nu_prime, x, alpha, u, beta],
        state,
    })
}

pub(crate) fn raw_stage<F: Field, S: Stage<F, R>>(poly: &sparse::Polynomial<F, R>) -> Vec<F> {
    let coefficients: Vec<_> = poly.iter_coeffs().collect();
    (0..S::values())
        .map(|i| {
            let gate = S::skip_gates() + i / 2;
            coefficients[(if i % 2 == 0 { 2 } else { 4 }) * R::n() - 1 - gate]
        })
        .collect()
}

pub(crate) fn coordinates<P: CurveAffine>(point: P) -> [P::Base; 2] {
    let xy = point.coordinates().unwrap();
    [*xy.x(), *xy.y()]
}

#[derive(Clone)]
struct Attempt {
    native: sparse::Polynomial<Fp, R>,
    bridge: sparse::Polynomial<Fq, R>,
    commitment: EpAffine,
    candidate: Fp,
}

impl From<EvalAttempt<'_, C, R>> for Attempt {
    fn from(value: EvalAttempt<'_, C, R>) -> Self {
        Self {
            native: value.native.clone(),
            bridge: value.bridge.clone(),
            commitment: value.commitment,
            candidate: value.candidate,
        }
    }
}

fn same_poly<F: Field>(a: &sparse::Polynomial<F, R>, b: &sparse::Polynomial<F, R>) -> bool {
    a.iter_coeffs().eq(b.iter_coeffs())
}

/// Separate predicates make the rejected-payload controls identify the
/// mismatch, even if a direct cache has been repaired.
fn accepted_tuple(proof: &Proof<C, R>, attempt: &Attempt) -> [bool; 4] {
    [
        same_poly(&proof.native_eval_rx, &attempt.native),
        same_poly(&proof.bridge_eval_rx, &attempt.bridge),
        proof.bridge_eval_commitment() == attempt.commitment,
        proof.pre_beta() == attempt.candidate,
    ]
}

fn check_attempts(proof: &Proof<C, R>, attempts: &[Attempt], rejected: usize) -> Result<()> {
    type Native = native::stages::eval::Stage<C, R, HEADER_SIZE>;
    type Bridge = nested::stages::eval::Stage<EqAffine, R>;
    assert_eq!(attempts.len(), rejected + 1);
    let accepted = attempts.last().unwrap();
    // Check the retained tuple before stage-layout assertions, detecting an
    // accepted challenge paired with a rejected payload.
    assert_eq!(accepted_tuple(proof, accepted), [true; 4]);
    let baseline = replay(&bridge_points(proof), None, &[])?;
    assert_eq!(baseline.challenges, proof.challenges().in_order());
    assert_eq!(
        baseline.challenges,
        replay(&bridge_points(proof), Some((&baseline.state, 0)), &[])?.challenges
    );
    for (index, attempt) in attempts.iter().enumerate() {
        let native_commitment = ReferenceBackend::sparse_commit_to_affine(
            &attempt.native,
            C::host_generators(Pasta::baked()),
        );
        if index == rejected {
            assert_eq!(
                native_commitment,
                proof.native_commitment(native::RxComponent::Rx(native::RxIndex::Eval))
            );
        }
        assert_eq!(
            ReferenceBackend::sparse_commit_to_affine(
                &attempt.bridge,
                C::nested_generators(Pasta::baked()),
            ),
            attempt.commitment
        );
        let bridge = raw_stage::<Fq, Bridge>(&attempt.bridge);
        assert_eq!(bridge[..2], coordinates(native_commitment));
        assert_eq!(
            bridge[2..],
            raw_stage::<Fq, Bridge>(&accepted.bridge)[2..],
            "all nested evaluation entries come from the fixed witness"
        );
        assert_eq!(
            raw_stage::<Fp, Native>(&attempt.native),
            raw_stage::<Fp, Native>(&accepted.native),
            "native evaluations and challenge partials stay fixed"
        );
        let mut points = bridge_points(proof);
        points[7] = attempt.commitment;
        let recomputed = replay(&points, None, &[])?;
        assert_eq!(recomputed.challenges[..10], baseline.challenges[..10]);
        assert_eq!(recomputed.challenges[10], attempt.candidate);
        if index < rejected {
            assert_ne!(attempt.commitment, accepted.commitment);
            assert_ne!(attempt.candidate, accepted.candidate);
            assert_eq!(accepted_tuple(proof, attempt), [false; 4]);
            // Each individual stale-field mutant is caught by its own
            // predicate; the other three fields remain the accepted tuple.
            for field in 0..4 {
                let mut mixed = accepted.clone();
                match field {
                    0 => mixed.native = attempt.native.clone(),
                    1 => mixed.bridge = attempt.bridge.clone(),
                    2 => mixed.commitment = attempt.commitment,
                    3 => mixed.candidate = attempt.candidate,
                    _ => unreachable!(),
                }
                assert_eq!(
                    accepted_tuple(proof, &mixed),
                    core::array::from_fn(|i| i != field)
                );
            }
            assert_eq!(
                attempt
                    .native
                    .iter_coeffs()
                    .zip(accepted.native.iter_coeffs())
                    .enumerate()
                    .filter_map(|(i, (x, y))| (x != y).then_some(i))
                    .collect::<Vec<_>>(),
                [2 * R::n() - 1],
                "native attempts differ only in system blinding"
            );
            assert_ne!(
                attempt.bridge.iter_coeffs().nth(2 * R::n() - 1),
                accepted.bridge.iter_coeffs().nth(2 * R::n() - 1),
                "bridge attempts also use fresh system blinding"
            );
        }
    }
    let leaked: Vec<_> = attempts[..rejected].iter().map(|a| a.commitment).collect();
    if rejected != 0 {
        assert_ne!(
            replay(&bridge_points(proof), None, &leaked)?.challenges[10],
            proof.pre_beta(),
            "cumulative rejected-attempt transcript must fail"
        );
    }
    Ok(())
}

#[test]
fn eval_retries_keep_only_the_accepted_tuple_and_rollback_transcript() -> Result<()> {
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x873_0701);
    let left = app.seed(&mut rng, Leaf, Fp::from(19))?.0;
    let right = app.seed(&mut rng, Leaf, Fp::from(43))?.0;
    let out_of_range = Fp::from(2).pow_vartime([Fp::CAPACITY as u64]);
    assert!(ragu_primitives::extract_endoscalar(out_of_range).is_err());
    for base_case in [true, false] {
        for rejected in [0, 1, 3] {
            let mut attempts = Vec::new();
            let hook = |attempt: EvalAttempt<'_, C, R>| {
                attempts.push(Attempt::from(attempt));
                assert!(attempts.len() <= rejected + 1, "unexpected natural retry");
                Ok((attempts.len() <= rejected).then_some(out_of_range))
            };
            let mut rng = StdRng::seed_from_u64(0x873_0702);
            let node = if base_case {
                app.fuse_inner(
                    &mut rng,
                    Leaf,
                    Fp::from(62),
                    app.bootstrap_pcd(),
                    app.bootstrap_pcd(),
                    |_, _| {},
                    hook,
                    &mut (),
                )?
                .0
            } else {
                app.fuse_inner(
                    &mut rng,
                    Add,
                    (),
                    left.clone(),
                    right.clone(),
                    |_, _| {},
                    hook,
                    &mut (),
                )?
                .0
            };
            check_attempts(node.proof(), &attempts, rejected)?;
            let (accepted, checks) =
                app.verify_with_checks(&node, StdRng::seed_from_u64(0x873_0703))?;
            assert!(accepted && checks.unwrap().all());
            // The accepted tuple also survives ordinary recursive use.
            let parent = app.fuse(&mut rng, Add, (), node, right.clone())?.0;
            assert!(app.verify(&parent, &mut rng)?);
        }
    }
    Ok(())
}

#[derive(Debug)]
struct AttemptFailure;

impl core::fmt::Display for AttemptFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("injected Eval attempt failure")
    }
}

impl core::error::Error for AttemptFailure {}

#[test]
fn eval_retry_propagates_non_range_errors_without_another_attempt() -> Result<()> {
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .finalize(Pasta::baked())?;
    for fail_at in [1, 2] {
        let mut calls = 0;
        let result: Result<(Pcd<C, R, Number>, ())> = app.fuse_inner(
            &mut StdRng::seed_from_u64(0x873_0704),
            Leaf,
            Fp::from(11),
            app.bootstrap_pcd(),
            app.bootstrap_pcd(),
            |_, _| {},
            |_| {
                calls += 1;
                if calls == fail_at {
                    Err(Error::InvalidWitness(Box::new(AttemptFailure)))
                } else {
                    assert!(calls < fail_at, "non-range error was retried");
                    Ok(Some(Fp::from(2).pow_vartime([Fp::CAPACITY as u64])))
                }
            },
            &mut (),
        );
        let Err(error) = result else {
            panic!("non-range error was swallowed")
        };
        assert!(error.invalid_witness_source::<AttemptFailure>().is_some());
        assert_eq!(calls, fail_at);
    }
    Ok(())
}

#[test]
fn saved_transcript_state_splices_and_squeeze_order_root() -> Result<()> {
    type Outer = native::stages::outer_error::Stage<C, R, HEADER_SIZE, native::RevdotParameters>;
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x873_0804);
    let left = app.seed(&mut rng, Leaf, Fp::from(19))?.0;
    let right = app.seed(&mut rng, Leaf, Fp::from(43))?.0;
    for base_case in [true, false] {
        let mut nodes = Vec::new();
        for seed in [0x873_0805, 0x873_0806] {
            let mut rng = StdRng::seed_from_u64(seed);
            nodes.push(if base_case {
                app.seed(&mut rng, Leaf, Fp::from(62))?.0
            } else {
                app.fuse(&mut rng, Add, (), left.clone(), right.clone())?.0
            });
        }
        let states: Vec<_> = nodes
            .iter()
            .map(|node| -> Result<_> {
                let expected = replay(&bridge_points(node.proof()), None, &[])?;
                let raw = raw_stage::<Fp, Outer>(&node.proof().native_outer_error_rx);
                assert_eq!(&raw[raw.len() - expected.state.len()..], &expected.state);
                assert_eq!(expected.challenges, node.proof().challenges().in_order());
                let (accepted, checks) =
                    app.verify_with_checks(node, StdRng::seed_from_u64(0x873_0807))?;
                assert!(accepted && checks.unwrap().all());
                Ok(expected.state)
            })
            .collect::<Result<_>>()?;
        let node = &nodes[1];
        let points = bridge_points(node.proof());
        let state = &states[1];
        for variant in 0..state.len() + 2 {
            let mut spliced = state.clone();
            let skip = if variant < state.len() {
                assert_ne!(states[0][variant], state[variant]);
                spliced[variant] = states[0][variant];
                0
            } else if variant == state.len() {
                1
            } else {
                4
            };
            let suffix = replay(&points, Some((&spliced, skip)), &[])?.challenges;
            assert_eq!(suffix[..3], node.proof().challenges().in_order()[..3]);
            assert_ne!(suffix[3..], node.proof().challenges().in_order()[3..]);
            // The root directly authenticates challenges against the bridge
            // transcript, without reading saved state. Give it the complete
            // alternate suffix (coordinate splices accept locally in Hashes2).
            // All polynomial/commitment data stays frozen; other predicates
            // may also reject, so assert the transcript verdict separately.
            let mut changed = node.proof().clone();
            [
                changed.w,
                changed.y,
                changed.z,
                changed.mu,
                changed.nu,
                changed.mu_prime,
                changed.nu_prime,
                changed.x,
                changed.alpha,
                changed.u,
                changed.pre_beta,
            ] = suffix;
            assert!(changed.challenges().lifts::<C>().is_ok());
            assert_eq!(bridge_points(&changed), points);
            let changed = changed.carry::<Number>(*node.data());
            let (accepted, checks) =
                app.verify_with_checks(&changed, StdRng::seed_from_u64(0x873_0808))?;
            let checks = checks.expect("in-range suffix reaches all predicates");
            assert!(!accepted);
            assert!(
                !checks.transcript,
                "root rejects false state/squeeze boundary {variant}"
            );
            assert!(checks.commitments && checks.ab_bridge && checks.nested_points);
        }
    }
    Ok(())
}
