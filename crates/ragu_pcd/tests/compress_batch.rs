//! The batch over the revdot reduction's openings on the bootstrap proof,
//! both curves, through to the IPA: the verifier's batched claim is the
//! commitment and value of the prover's $p$, the IPA proves it, and a
//! tampered message breaks the proof.

use alloc::{borrow::Cow, vec, vec::Vec};

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::{ProductionRank, Rank, TestRank, sparse};
use ragu_core::{
    Cycle, Error, FixedGenerators, Result,
    pasta::{Fp, Fq, Pasta},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::{curve::Affine, field::Field, polynomial::evaluate_iter};

type EpAffine = <Pasta as Cycle>::NestedCurve;
type EqAffine = <Pasta as Cycle>::HostCurve;

use super::{Batch, Batched, batch, verifier::verify};
use crate::{
    Application, ApplicationBuilder, Proof,
    compress::revdot::{self, OpeningClaim, Openings, Reduction},
    internal::{
        ky::{self, NativeKy, NestedKy},
        nested,
    },
    ipa::{self, CycleTranscript, IpaCycle, IpaProof, IpaTranscript, MSM, Params},
};

type TestR = ProductionRank;
const HEADER_SIZE: usize = 4;
const TAG: &[u8] = b"ragu-test-batch";

fn create_test_app() -> Application<'static, Pasta, TestR, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .finalize(crate::pasta::baked())
        .expect("failed to create test application")
}

fn transcript() -> CycleTranscript<'static, Pasta> {
    CycleTranscript::new(crate::pasta::baked(), TAG).unwrap()
}

/// Fixes alpha to one so contradictory duplicate claims can cancel. Tracks
/// transcript operations to require rejection before any challenge or message.
struct BatchTranscript<F> {
    challenges: core::array::IntoIter<F, 3>,
    writes: usize,
}

impl<F: Field> BatchTranscript<F> {
    fn new() -> Self {
        Self {
            challenges: [F::ONE, F::from(7), F::from(11)].into_iter(),
            writes: 0,
        }
    }

    fn assert_unused(&self) {
        assert_eq!(self.challenges.len(), 3);
        assert_eq!(self.writes, 0);
    }
}

impl<C: Affine> IpaTranscript<C> for BatchTranscript<C::Scalar> {
    fn write_point(&mut self, _: C) -> Result<()> {
        self.writes += 1;
        Ok(())
    }

    fn write_scalar(&mut self, _: C::Scalar) -> Result<()> {
        self.writes += 1;
        Ok(())
    }

    fn squeeze_challenge(&mut self) -> Result<C::Scalar> {
        Ok(self.challenges.next().expect("three batch challenges"))
    }
}

fn duplicate_claims<C: Affine>(generators: &impl FixedGenerators<C>) {
    let polys = [
        sparse::Polynomial::<C::Scalar, TestRank>::from_coeffs(vec![
            C::Scalar::ONE,
            C::Scalar::ONE,
        ]),
        sparse::Polynomial::<C::Scalar, TestRank>::from_coeffs(vec![
            C::Scalar::from(3),
            C::Scalar::from(5),
        ]),
    ];
    let commitments = polys
        .each_ref()
        .map(|poly| poly.commit_to_affine(generators));
    let polys = polys.each_ref().map(Cow::Borrowed);
    let claim = |poly: usize, point| OpeningClaim {
        poly,
        point,
        value: polys[poly].eval(point),
    };
    let repeated = claim(0, C::Scalar::from(2));
    // Identical duplicates are allowed, as are different points on the same
    // polynomial and different polynomials at the same point.
    let claims = [
        repeated,
        claim(0, C::Scalar::from(3)),
        claim(1, repeated.point),
        repeated,
    ];
    let (messages, witness) = batch::<C, TestRank, ReferenceBackend, _>(
        &polys,
        &claims,
        generators,
        &mut BatchTranscript::new(),
    )
    .unwrap();
    let batched = verify::<_, ReferenceBackend, _>(
        &commitments,
        &claims,
        &messages,
        &mut BatchTranscript::new(),
    )
    .unwrap();
    assert_eq!(batched.point, witness.u);
    assert_eq!(batched.value, evaluate_iter(&witness.p, witness.u));
    assert_eq!(
        batched.commitment,
        sparse::Polynomial::<_, TestRank>::from_coeffs(witness.p).commit_to_affine(generators)
    );

    // These nonadjacent errors cancel at alpha = 1, so without the
    // consistency check the same batch still gives the correct IPA claim.
    let mut conflicting = claims;
    conflicting[0].value += C::Scalar::ONE;
    conflicting[3].value -= C::Scalar::ONE;
    let mut verifier = BatchTranscript::new();
    assert!(matches!(
        verify::<_, ReferenceBackend, _>(&commitments, &conflicting, &messages, &mut verifier),
        Err(Error::InvalidWitness(_))
    ));
    verifier.assert_unused();

    let mut prover = BatchTranscript::new();
    assert!(matches!(
        batch::<C, TestRank, ReferenceBackend, _>(&polys, &conflicting, generators, &mut prover),
        Err(Error::InvalidWitness(_))
    ));
    prover.assert_unused();
}

#[test]
fn native_duplicate_claims() {
    duplicate_claims::<EqAffine>(Pasta::host_generators(crate::pasta::baked()));
}

#[test]
fn nested_duplicate_claims() {
    duplicate_claims::<EpAffine>(Pasta::nested_generators(crate::pasta::baked()));
}

/// The prover's batch and IPA opening after an accepted reduction, with the
/// claim the verifier is expected to derive.
struct Proved<C: Affine> {
    batch: Batch<C>,
    p: Vec<C::Scalar>,
    claim: Batched<C>,
    opening: IpaProof<C>,
}

/// The batch over `openings`, then the IPA opening of the batched claim,
/// which the prover derives the same way the verifier will, on its own copy
/// of the transcript.
fn prove<C, R, T>(
    polys: &[Cow<'_, sparse::Polynomial<C::Scalar, R>>],
    openings: &Openings<C>,
    generators: &impl FixedGenerators<C>,
    u: C,
    transcript: &mut T,
    verifier_transcript: &mut T,
    rng: &mut StdRng,
) -> Proved<C>
where
    C: Affine,
    R: Rank,
    T: IpaTranscript<C>,
{
    let (messages, witness) =
        batch::<C, R, ReferenceBackend, _>(polys, &openings.claims, generators, transcript)
            .unwrap();
    let claim = verify::<_, ReferenceBackend, _>(
        &openings.commitments,
        &openings.claims,
        &messages,
        verifier_transcript,
    )
    .unwrap();
    assert_eq!(claim.point, witness.u);
    let params = Params::new(generators, u);
    let opening = ipa::create_proof(&params, &mut *rng, transcript, &witness.p, witness.u).unwrap();
    Proved {
        batch: messages,
        p: witness.p,
        claim,
        opening,
    }
}

/// Derives the batched claim from `messages` and checks `opening` against it
/// with the IPA.
fn check<C, T>(
    openings: &Openings<C>,
    messages: &Batch<C>,
    opening: &IpaProof<C>,
    generators: &impl FixedGenerators<C>,
    u: C,
    transcript: &mut T,
) -> bool
where
    C: Affine,
    T: IpaTranscript<C>,
{
    let claim = verify::<_, ReferenceBackend, _>(
        &openings.commitments,
        &openings.claims,
        messages,
        transcript,
    )
    .unwrap();
    let params = Params::new(generators, u);
    let mut msm = MSM::new(&params);
    msm.append_term(C::Scalar::ONE, claim.commitment);
    ipa::verify_proof(&params, msm, transcript, opening, claim.point, claim.value)
        .unwrap()
        .use_challenges()
        .eval()
}

/// A verifier transcript that has replayed the native reduction.
fn native_verifier(
    app: &Application<'static, Pasta, TestR, HEADER_SIZE>,
    proof: &Proof<Pasta, TestR>,
    y: Fp,
    z: Fp,
    targets: &NativeKy<Fp>,
    reduction: &Reduction<EqAffine>,
) -> (CycleTranscript<'static, Pasta>, Openings<EqAffine>) {
    let mut t = transcript();
    let openings = revdot::verify_native::<Pasta, TestR, ReferenceBackend, _>(
        proof.circuit_id(),
        |component| proof.native_commitment(component),
        &app.native_registry,
        y,
        z,
        targets,
        &[],
        reduction,
        &mut t.host(),
    )
    .unwrap()
    .expect("the reduction holds");
    (t, openings)
}

#[test]
fn native_batch_opens_through_the_ipa() {
    let app = create_test_app();
    let pcd = app.bootstrap_pcd();
    let mut rng = StdRng::seed_from_u64(1);
    let (y, z) = (
        Fp::random(|bytes| rng.fill_bytes(bytes)),
        Fp::random(|bytes| rng.fill_bytes(bytes)),
    );
    let proof = pcd.proof();
    let targets = NativeKy {
        c: Some(proof.native_c()),
        ..ky::native_ky::<Pasta, TestR, (), HEADER_SIZE>(&pcd, y).unwrap()
    };
    let generators = Pasta::host_generators(crate::pasta::baked());

    // The reduction, on the prover's and the verifier's transcripts.
    let mut prover = transcript();
    let (reduction, witness) = revdot::reduce_native::<Pasta, TestR, ReferenceBackend, _>(
        proof,
        &app.native_registry,
        generators,
        y,
        z,
        &[],
        &mut prover.host(),
    )
    .unwrap();
    let (mut verifier, openings) = native_verifier(&app, proof, y, z, &targets, &reduction);

    // The batch and the IPA.
    let polys = witness.polys();
    let proved = prove::<EqAffine, TestR, _>(
        &polys,
        &openings,
        generators,
        *Pasta::host_u(crate::pasta::baked()),
        &mut prover.host(),
        &mut verifier.host(),
        &mut rng,
    );

    // The verifier's claim is the prover's p.
    assert_eq!(
        proved.claim.commitment,
        sparse::Polynomial::<Fp, TestR>::from_coeffs(proved.p.clone()).commit_to_affine(generators)
    );
    assert_eq!(
        proved.claim.value,
        evaluate_iter(&proved.p, proved.claim.point)
    );

    // The IPA proves it, on a verifier transcript replayed from the
    // reduction.
    let (mut verifier, _) = native_verifier(&app, proof, y, z, &targets, &reduction);
    assert!(check(
        &openings,
        &proved.batch,
        &proved.opening,
        generators,
        *Pasta::host_u(crate::pasta::baked()),
        &mut verifier.host()
    ));

    // A wrong sent value moves v and the challenges; the opening no longer
    // holds.
    let mut tampered = proved.batch.clone();
    tampered.evaluations[3] += Fp::ONE;
    let (mut verifier, _) = native_verifier(&app, proof, y, z, &targets, &reduction);
    assert!(!check(
        &openings,
        &tampered,
        &proved.opening,
        generators,
        *Pasta::host_u(crate::pasta::baked()),
        &mut verifier.host()
    ));

    // A wrong quotient commitment moves the batched commitment.
    let mut tampered = proved.batch.clone();
    tampered.f = openings.commitments[0];
    let (mut verifier, _) = native_verifier(&app, proof, y, z, &targets, &reduction);
    assert!(!check(
        &openings,
        &tampered,
        &proved.opening,
        generators,
        *Pasta::host_u(crate::pasta::baked()),
        &mut verifier.host()
    ));

    // A wrong target passes the reduction, which never reads the targets,
    // and changes only the claim on p at zero; the IPA settles it.
    let wrong = NativeKy {
        c: targets.c,
        unified: targets.unified,
        unified_bridge: targets.unified_bridge,
        application: targets.application + Fp::ONE,
    };
    let (mut verifier, wrong_openings) = native_verifier(&app, proof, y, z, &wrong, &reduction);
    let (at_zero, honest) = (
        wrong_openings.claims.last().unwrap(),
        openings.claims.last().unwrap(),
    );
    assert_eq!(at_zero.point, Fp::ZERO);
    assert_ne!(at_zero.value, honest.value);
    assert!(!check(
        &wrong_openings,
        &proved.batch,
        &proved.opening,
        generators,
        *Pasta::host_u(crate::pasta::baked()),
        &mut verifier.host()
    ));
}

#[test]
fn nested_batch_opens_through_the_ipa() {
    let app = create_test_app();
    let pcd = app.bootstrap_pcd();
    let proof = pcd.proof();
    let mut rng = StdRng::seed_from_u64(2);
    let (y, z) = (
        Fq::random(|bytes| rng.fill_bytes(bytes)),
        Fq::random(|bytes| rng.fill_bytes(bytes)),
    );
    let targets = NestedKy {
        c: proof.nested_c(),
        unified: ky::nested_ky(proof, y).unwrap(),
    };
    let generators = Pasta::nested_generators(crate::pasta::baked());
    let commitment = |component| match component {
        nested::RxComponent::AbA => proof.nested_a_commitment(),
        nested::RxComponent::AbB => proof.nested_b_commitment(),
        nested::RxComponent::Rx(index) => proof.nested_rx_commitment(index),
    };

    let mut prover = transcript();
    let (reduction, witness) = revdot::reduce_nested::<Pasta, TestR, ReferenceBackend, _>(
        proof,
        &app.nested_registry,
        generators,
        y,
        z,
        &[],
        &mut prover.nested(),
    )
    .unwrap();
    let nested_verifier = || {
        let mut t = transcript();
        let openings = revdot::verify_nested::<Pasta, TestR, ReferenceBackend, _>(
            commitment,
            &app.nested_registry,
            y,
            z,
            &targets,
            &[],
            &reduction,
            &mut t.nested(),
        )
        .unwrap()
        .expect("the reduction holds");
        (t, openings)
    };
    let (mut verifier, openings) = nested_verifier();

    let polys = witness.polys();
    let proved = prove::<EpAffine, TestR, _>(
        &polys,
        &openings,
        generators,
        *Pasta::nested_u(crate::pasta::baked()),
        &mut prover.nested(),
        &mut verifier.nested(),
        &mut rng,
    );
    assert_eq!(
        proved.claim.value,
        evaluate_iter(&proved.p, proved.claim.point)
    );

    let (mut verifier, _) = nested_verifier();
    assert!(check(
        &openings,
        &proved.batch,
        &proved.opening,
        generators,
        *Pasta::nested_u(crate::pasta::baked()),
        &mut verifier.nested()
    ));

    let mut tampered = proved.batch.clone();
    tampered.evaluations[0] += Fq::ONE;
    let (mut verifier, _) = nested_verifier();
    assert!(!check(
        &openings,
        &tampered,
        &proved.opening,
        generators,
        *Pasta::nested_u(crate::pasta::baked()),
        &mut verifier.nested()
    ));
}
