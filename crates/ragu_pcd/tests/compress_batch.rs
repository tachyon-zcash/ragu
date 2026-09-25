//! The batch over the revdot reduction's openings on the bootstrap proof,
//! both curves, through to the IPA: the verifier's batched claim is the
//! commitment and value of the prover's $p$, the IPA proves it, and a
//! tampered message breaks the proof.

use alloc::{borrow::Cow, vec::Vec};

use ragu_arithmetic::{
    CurveAffine, Cycle, FixedGenerators, eval,
    ff::{Field, PrimeField},
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::{ProductionRank, Rank, sparse};
use ragu_pasta::{EpAffine, EqAffine, Fp, Fq, Pasta};

use super::{Batch, Batched, batch, verify};
use crate::{
    Application, ApplicationBuilder, Proof,
    compress::revdot::{self, Openings, Reduction, native_components, nested_components},
    internal::{
        ky::{self, NativeKy, NestedKy},
        nested,
    },
    ipa::{self, Blind, CycleTranscript, IpaProof, IpaTranscript, MSM, Params},
};

type TestR = ProductionRank;
const HEADER_SIZE: usize = 4;
const TAG: &[u8] = b"ragu-test-batch";

fn create_test_app() -> Application<'static, Pasta, TestR, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .finalize(Pasta::baked())
        .expect("failed to create test application")
}

fn transcript() -> CycleTranscript<'static, Pasta> {
    CycleTranscript::new(Pasta::baked(), TAG).unwrap()
}

/// The prover's batch and IPA opening after an accepted reduction, with the
/// claim the verifier is expected to derive.
struct Proved<C: CurveAffine> {
    batch: Batch<C>,
    p: Vec<C::Scalar>,
    claim: Batched<C>,
    opening: IpaProof<C>,
}

/// The prover's side past the reduction: the batch over `openings`, then
/// the IPA opening of the batched claim, which the prover derives the same
/// way the verifier will, on its own copy of the transcript.
fn prove<C, R, T>(
    polys: &[Cow<'_, sparse::Polynomial<C::Scalar, R>>],
    openings: &Openings<C>,
    generators: &impl FixedGenerators<C>,
    transcript: &mut T,
    verifier_transcript: &mut T,
    rng: &mut StdRng,
) -> Proved<C>
where
    C: CurveAffine,
    C::Scalar: PrimeField,
    R: Rank,
    T: IpaTranscript<C>,
{
    let (messages, witness) =
        batch::<C, R, _>(polys, &openings.claims, generators, transcript).unwrap();
    let claim = verify(
        &openings.commitments,
        &openings.claims,
        &messages,
        verifier_transcript,
    )
    .unwrap();
    assert_eq!(claim.point, witness.u);
    let params = Params::new(generators);
    let opening = ipa::create_proof(
        &params,
        &mut *rng,
        transcript,
        &witness.p,
        Blind(C::Scalar::ZERO),
        witness.u,
    )
    .unwrap();
    Proved {
        batch: messages,
        p: witness.p,
        claim,
        opening,
    }
}

/// The verifier's side past the reduction: derives the batched claim from
/// `messages` and checks `opening` against it with the IPA.
fn check<C, T>(
    openings: &Openings<C>,
    messages: &Batch<C>,
    opening: &IpaProof<C>,
    generators: &impl FixedGenerators<C>,
    transcript: &mut T,
) -> bool
where
    C: CurveAffine,
    T: IpaTranscript<C>,
{
    let claim = verify(
        &openings.commitments,
        &openings.claims,
        messages,
        transcript,
    )
    .unwrap();
    let params = Params::new(generators);
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
    let openings = revdot::verify_native::<Pasta, TestR, _>(
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
    let (y, z) = (Fp::random(&mut rng), Fp::random(&mut rng));
    let proof = pcd.proof();
    let targets = NativeKy {
        c: Some(proof.native_c()),
        ..ky::native_ky::<Pasta, TestR, (), HEADER_SIZE>(&pcd, y).unwrap()
    };
    let generators = Pasta::host_generators(Pasta::baked());

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
    let polys = witness.polys(native_components().map(|component| &proof[component]));
    let proved = prove::<EqAffine, TestR, _>(
        &polys,
        &openings,
        generators,
        &mut prover.host(),
        &mut verifier.host(),
        &mut rng,
    );

    // The verifier's claim is the prover's p.
    assert_eq!(
        proved.claim.commitment,
        sparse::Polynomial::<Fp, TestR>::from_coeffs(proved.p.clone()).commit_to_affine(generators)
    );
    assert_eq!(proved.claim.value, eval(&proved.p, proved.claim.point));

    // The IPA proves it, on a verifier transcript replayed from the
    // reduction.
    let (mut verifier, _) = native_verifier(&app, proof, y, z, &targets, &reduction);
    assert!(check(
        &openings,
        &proved.batch,
        &proved.opening,
        generators,
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
        &mut verifier.host()
    ));
}

#[test]
fn nested_batch_opens_through_the_ipa() {
    let app = create_test_app();
    let pcd = app.bootstrap_pcd();
    let proof = pcd.proof();
    let mut rng = StdRng::seed_from_u64(2);
    let (y, z) = (Fq::random(&mut rng), Fq::random(&mut rng));
    let targets = NestedKy {
        c: proof.nested_c(),
        unified: ky::nested_ky(proof, y).unwrap(),
    };
    let generators = Pasta::nested_generators(Pasta::baked());
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
        let openings = revdot::verify_nested::<Pasta, TestR, _>(
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

    let polys = witness.polys(nested_components().map(|component| &proof[component]));
    let proved = prove::<EpAffine, TestR, _>(
        &polys,
        &openings,
        generators,
        &mut prover.nested(),
        &mut verifier.nested(),
        &mut rng,
    );
    assert_eq!(proved.claim.value, eval(&proved.p, proved.claim.point));

    let (mut verifier, _) = nested_verifier();
    assert!(check(
        &openings,
        &proved.batch,
        &proved.opening,
        generators,
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
        &mut verifier.nested()
    ));
}
