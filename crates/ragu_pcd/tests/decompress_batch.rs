//! The batch's gadget against the native verifier, both curves of a real
//! compressed proof: on the openings the reductions leave, it computes
//! the native verifier's point and value and weights that combine $\[f\]$
//! and the commitments into its batched commitment, honest or tampered,
//! and fails to witness a point the native verifier rejects.

use alloc::vec::Vec;

use ragu_backend::{Backend, ReferenceBackend};
use ragu_core::{Result, maybe::Maybe};
use ragu_primitives::Simulator;
use udon::{curve::Affine, field::Field};

use super::{Challenges, Messages, verify};
use crate::{
    compress::{
        batch::{self, Batch, Batched},
        revdot::{OpeningClaim, Openings},
    },
    decompress::support::{Setup, alloc, alloc_all, replay_batch},
};

/// What the gadget produces on `claims` over `polys` committed
/// polynomials, by value: the point, the value and the weights.
fn simulate<F: Field>(
    claims: &[OpeningClaim<F>],
    polys: usize,
    evaluations: &[F],
    (alpha, u, beta): (F, F, F),
) -> Result<(F, F, Vec<F>)> {
    let mut out = None;
    Simulator::simulate((), |dr, _| {
        let claims: Vec<OpeningClaim<_>> = claims
            .iter()
            .map(|claim| {
                Ok(OpeningClaim {
                    poly: claim.poly,
                    point: alloc(dr, claim.point)?,
                    value: alloc(dr, claim.value)?,
                })
            })
            .collect::<Result<_>>()?;
        let challenges = Challenges {
            alpha: alloc(dr, alpha)?,
            u: alloc(dr, u)?,
            beta: alloc(dr, beta)?,
        };
        let messages = Messages {
            evaluations: alloc_all(dr, evaluations.iter().copied())?,
        };
        let batched = verify(dr, &claims, polys, &challenges, &messages)?;
        out = Some((
            *batched.point.value().take(),
            *batched.value.value().take(),
            batched
                .weights
                .iter()
                .map(|weight| *weight.value().take())
                .collect(),
        ));
        Ok(())
    })?;
    Ok(out.expect("the simulation ran"))
}

/// The gadget on `batch` over `openings` under `challenges` agrees with
/// the native verifier's `expected` claim: the same point and value, and
/// weights combining $\[f\]$ and the commitments into its commitment.
fn check<F: Field, C: Affine<Scalar = F>>(
    openings: &Openings<C>,
    batch: &Batch<C>,
    challenges: (F, F, F),
    expected: &Batched<C>,
) {
    let (point, value, weights) = simulate(
        &openings.claims,
        openings.commitments.len(),
        &batch.evaluations,
        challenges,
    )
    .expect("the batch satisfies the circuit");
    assert_eq!(point, expected.point);
    assert_eq!(value, expected.value);
    let points: Vec<C> = core::iter::once(batch.f)
        .chain(openings.commitments.iter().copied())
        .collect();
    let commitment: C = ReferenceBackend::msm(&weights, &points).into();
    assert_eq!(commitment, expected.commitment);
}

/// A tampered value at $u$ moves $v$ in both: the batch leaves it for the
/// IPA.
fn tampered<C: Affine>(batch: &Batch<C>) -> Batch<C> {
    let mut tampered = batch.clone();
    tampered.evaluations[2] += C::Scalar::ONE;
    tampered
}

/// With a claim's point moved onto $u$, neither side can form the
/// quotient.
fn onto_u<F: Field, C: Affine<Scalar = F>>(openings: &Openings<C>, u: F) -> Openings<C> {
    let mut moved = openings.clone();
    moved.claims[0].point = u;
    moved
}

#[test]
fn native_batch_matches_the_verifier() {
    let setup = Setup::new();
    let at_batch = || {
        let (mut t, sampled, nested_sampled) = setup.transcript();
        let openings = setup.native_openings(&mut t, &sampled, nested_sampled.y);
        (t, openings)
    };
    let challenges = |batch: &Batch<_>| replay_batch(batch, &mut at_batch().0.host());
    let expected = |openings: &Openings<_>, batch: &Batch<_>| {
        batch::verify::<_, ReferenceBackend, _>(
            &openings.commitments,
            &openings.claims,
            batch,
            &mut at_batch().0.host(),
        )
    };

    let openings = at_batch().1;
    for batch in [
        setup.proof.native.batch.clone(),
        tampered(&setup.proof.native.batch),
    ] {
        check(
            &openings,
            &batch,
            challenges(&batch),
            &expected(&openings, &batch).unwrap(),
        );
    }

    let batch = &setup.proof.native.batch;
    let challenges = challenges(batch);
    let moved = onto_u(&openings, challenges.1);
    assert!(expected(&moved, batch).is_err());
    assert!(
        simulate(
            &moved.claims,
            moved.commitments.len(),
            &batch.evaluations,
            challenges
        )
        .is_err()
    );
}

#[test]
fn nested_batch_matches_the_verifier() {
    let setup = Setup::new();
    let at_batch = || {
        let (mut t, native_sampled, sampled) = setup.transcript();
        setup.run_native(&mut t, &native_sampled, sampled.y);
        let openings = setup.nested_openings(&mut t, &sampled, native_sampled.y);
        (t, openings)
    };
    let challenges = |batch: &Batch<_>| replay_batch(batch, &mut at_batch().0.nested());
    let expected = |openings: &Openings<_>, batch: &Batch<_>| {
        batch::verify::<_, ReferenceBackend, _>(
            &openings.commitments,
            &openings.claims,
            batch,
            &mut at_batch().0.nested(),
        )
    };

    let openings = at_batch().1;
    for batch in [
        setup.proof.nested.batch.clone(),
        tampered(&setup.proof.nested.batch),
    ] {
        check(
            &openings,
            &batch,
            challenges(&batch),
            &expected(&openings, &batch).unwrap(),
        );
    }

    let batch = &setup.proof.nested.batch;
    let challenges = challenges(batch);
    let moved = onto_u(&openings, challenges.1);
    assert!(expected(&moved, batch).is_err());
    assert!(
        simulate(
            &moved.claims,
            moved.commitments.len(),
            &batch.evaluations,
            challenges
        )
        .is_err()
    );
}
