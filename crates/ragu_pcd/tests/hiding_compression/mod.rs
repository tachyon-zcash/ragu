//! Test-only proofs of the Fuse bridge transcript, the revdot split, and
//! the terminal batch and mask, against committed inputs. The fixture runs
//! the native verifier to obtain the committed advice from a real PCD.

use alloc::{borrow::Cow, vec::Vec};
use core::array;
use std::time::Instant;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Cycle, FixedGenerators};
use rand::{CryptoRng, SeedableRng, rngs::StdRng};
use udon::{
    curve::{Affine, Projective},
    field::Field,
    polynomial::evaluate_iter,
};

use self::{
    batch_proof::{BatchProof, BatchPublic, BatchRelation, BatchWitness, Opening},
    transcript::{BatchTranscript, Transcript},
};
use super::{App, Fp, HEADER_SIZE, Pasta, Pcd, Seed, TestR, Value, app};
use crate::{
    RAGU_TAG, SelectableBackend,
    compress::{
        Sampled, batch,
        instance::{Instance, OPENED},
        revdot::{self, Openings, Reduction, fold::Derived},
    },
    internal::{ky, native, nested},
    ipa::{self, CycleTranscript, IpaCycle, IpaProof, MSM, Params},
    wire::{Dimensions, Encode},
};

mod batch_proof;
mod circuit_proof;
mod committed_instance;
mod fuse_prefix;
mod point_binding;
mod reduction_schedule;
mod split_proof;
mod transcript;

type Backend = ragu_acceleration::AcceleratedBackend;
type Verifier = <Backend as SelectableBackend>::Verifier;
type Host = <Pasta as Cycle>::HostCurve;
type Nested = <Pasta as Cycle>::NestedCurve;

const DERIVED: usize = Derived::ALL.len();
const POLYS: usize = DERIVED + 2 + OPENED;
const CLAIMS: usize = POLYS + 1;
const QUERY_POLYS: [usize; CLAIMS] = {
    let mut indices = [0; CLAIMS];
    let mut i = 0;
    while i < DERIVED + 2 {
        indices[i] = i;
        i += 1;
    }
    indices[i] = DERIVED; // p(0), the combined revdot target.
    while i + 1 < CLAIMS {
        i += 1;
        indices[i] = i - 1;
    }
    indices
};

fn random<F: Field>(rng: &mut impl CryptoRng) -> F {
    F::random(|bytes| rng.fill_bytes(bytes))
}

#[derive(Clone, Copy)]
struct Bases<C: Affine> {
    g0: C,
    g1: C,
    h: C,
    j: C,
}

impl<C: Affine> Bases<C> {
    fn new(generators: &impl FixedGenerators<C>, j: C) -> Self {
        Self {
            g0: generators.g()[0],
            g1: generators.g()[1],
            h: *generators.h(),
            j,
        }
    }

    fn commit(self, value: C::Scalar, blind: C::Scalar) -> C {
        (self.g0 * value + self.h * blind).to_affine()
    }

    fn hide_point(self, point: C, blind: C::Scalar) -> HiddenPoint<C> {
        // ElGamal (DDH). The first component fixes the blinder and makes
        // this binding to the point, even without its discrete logarithm.
        HiddenPoint {
            first: (self.j * blind).to_affine(),
            second: (point.to_projective() + self.h * blind).to_affine(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct HiddenPoint<C: Affine> {
    first: C,
    second: C,
}

impl<C: Affine> HiddenPoint<C> {
    fn absorb(self, transcript: &mut Transcript) {
        transcript.point(self.first);
        transcript.point(self.second);
    }

    fn horner(self, beta: C::Scalar, next: Self) -> Self {
        Self {
            first: (self.first * beta + next.first.to_projective()).to_affine(),
            second: (self.second * beta + next.second.to_projective()).to_affine(),
        }
    }
}

#[derive(Clone)]
struct BatchOpening<C: Affine> {
    public: BatchPublic<C>,
    d: C,
    u: C::Scalar,
    proof: BatchProof<C>,
    split: circuit_proof::CircuitProof<C>,
    ipa: IpaProof<C>,
}

fn context(app: &App, header: &[Fp; HEADER_SIZE]) -> Transcript {
    let mut transcript = Transcript::new(b"batch and terminal opening");
    // This experiment fixes Pasta with the baked setup and Standard profile.
    transcript.bytes(b"pasta-baked-standard");
    transcript.bytes(&TestR::RANK.to_le_bytes());
    transcript.scalar(app.native_registry.tag());
    transcript.scalar(app.nested_registry.tag());
    for &element in header {
        transcript.scalar(element);
    }
    transcript
}

fn bind_opening<C: Affine>(mut transcript: Transcript, d: C, u: C::Scalar) -> Transcript {
    transcript.bytes(b"terminal statement");
    transcript.point(d);
    transcript.scalar(u);
    transcript
}

fn ipa_transcript(mut transcript: Transcript) -> Transcript {
    transcript.bytes(b"ipa: claimed value fixed to zero");
    transcript
}

fn verify_zero<C: Affine>(
    params: &Params<C>,
    transcript: Transcript,
    proof: &IpaProof<C>,
    d: C,
    u: C::Scalar,
) -> bool {
    let mut msm = MSM::new(params);
    msm.append_term(C::Scalar::ONE, d);
    ipa::verify_proof(
        params,
        msm,
        &mut ipa_transcript(transcript),
        proof,
        u,
        C::Scalar::ZERO,
    )
    .is_ok_and(|guard| guard.use_challenges().eval::<Verifier>())
}

impl<C: Affine> BatchOpening<C> {
    /// Checks the revdot split and terminal batch against committed data.
    /// The proof does not establish that replay produced the commitments.
    fn verify_terminal_batch(
        &self,
        transcript: Transcript,
        bases: Bases<C>,
        params: &Params<C>,
    ) -> bool {
        let (alpha, u, beta, transcript) = self.public.replay(transcript);
        let transcript = bind_opening(transcript, self.d, self.u);
        self.u == u
            && bases.g1.to_projective() != bases.g0 * u
            && BatchRelation {
                bases,
                alpha,
                u,
                beta,
                public: &self.public,
                d: self.d,
            }
            .verify(&mut transcript.clone(), &self.proof)
            && split_proof::verify(bases, transcript.clone(), &self.public, &self.split)
            && verify_zero(params, transcript, &self.ipa, self.d, u)
    }
}

fn prefix<C: Affine>(
    instance: &Instance<Pasta>,
    reduction: &Reduction<C>,
    openings: &Openings<C>,
) -> C::Scalar {
    // The checked native replay derives the batch inputs from this prefix.
    // The eventual private proof must enforce that derivation and this opening.
    let dims = Dimensions::of::<TestR, HEADER_SIZE>();
    let mut serialized = Vec::new();
    instance.encode(&mut serialized, dims).unwrap();
    reduction.encode(&mut serialized, dims).unwrap();
    let mut transcript = Transcript::new(b"private verifier prefix");
    transcript.bytes(&serialized);
    for &commitment in &openings.commitments {
        transcript.point(commitment);
    }
    for claim in &openings.claims {
        transcript.bytes(&(claim.poly as u64).to_le_bytes());
        transcript.scalar(claim.point);
        transcript.scalar(claim.value);
    }
    transcript.challenge(b"prefix digest")
}

struct BatchSources<C: Affine> {
    ciphertexts: [HiddenPoint<C>; POLYS],
    input_blinds: [C::Scalar; POLYS],
    reduction_evaluations: [Opening<C::Scalar>; DERIVED + 2],
}

fn run_batch<C: Affine>(
    transcript: Transcript,
    instance: &Instance<Pasta>,
    reduction: &Reduction<C>,
    openings: &Openings<C>,
    polys: &[Cow<'_, sparse::Polynomial<C::Scalar, TestR>>],
    generators: &impl FixedGenerators<C>,
    j: C,
    fuse_u: Option<Opening<C::Scalar>>,
    sources: BatchSources<C>,
    split_values: [C::Scalar; split_proof::AUX],
    rng: &mut impl CryptoRng,
) -> (BatchOpening<C>, Bases<C>, Params<C>) {
    let bases = Bases::new(generators, j);
    let prefix = bases.commit(prefix(instance, reduction, openings), random(rng));
    let BatchSources {
        ciphertexts: inputs,
        input_blinds,
        reduction_evaluations,
    } = sources;
    for (i, &point) in openings.commitments.iter().enumerate() {
        assert_eq!(inputs[i], bases.hide_point(point, input_blinds[i]));
    }
    assert_eq!(openings.claims.len(), CLAIMS);
    let queries = array::from_fn(|i| {
        let claim = openings.claims[i];
        assert_eq!(claim.poly, QUERY_POLYS[i]);
        let point_opening = match (i >= CLAIMS - 3, fuse_u) {
            (true, Some(opening)) => {
                assert_eq!(claim.point, opening.value);
                opening
            }
            _ => Opening::fresh(claim.point, rng),
        };
        let value_opening = reduction_evaluations
            .get(i)
            .copied()
            .unwrap_or_else(|| Opening::fresh(claim.value, rng));
        assert_eq!(value_opening.value, claim.value);
        (point_opening, value_opening)
    });
    let query_commitments = queries.map(|(point, value)| {
        (
            bases.commit(point.value, point.blind),
            bases.commit(value.value, value.blind),
        )
    });
    let split_witness = array::from_fn(|i| {
        let value = split_values[i];
        if split_proof::PUBLIC_AUX.contains(&i) {
            Opening {
                value,
                blind: C::Scalar::ZERO,
            }
        } else {
            Opening::fresh(value, rng)
        }
    });
    let split = split_witness.map(|value| bases.commit(value.value, value.blind));
    let mut pre_alpha = transcript.clone();
    BatchPublic::absorb_prefix(&mut pre_alpha, prefix, &inputs, &split, &query_commitments);

    let batch_blinds: [C::Scalar; POLYS + 1] = array::from_fn(|_| random(rng));
    let batch_transcript = || BatchTranscript {
        inner: pre_alpha.clone(),
        bases,
        blinds: &batch_blinds,
        quotient: None,
        evaluations: Vec::new(),
        draws: 0,
    };
    let mut prover_transcript = batch_transcript();
    let (batch, mut witness) = batch::batch::<_, TestR, Backend>(
        polys,
        &openings.claims,
        generators,
        &mut prover_transcript,
    )
    .unwrap();

    // Use the real batch verifier to derive (C, u, v) from its openings.
    let batch::Batched {
        commitment,
        point: u,
        value,
    } = batch::derive_claim::<_, Verifier, _>(
        &openings.commitments,
        &openings.claims,
        &batch,
        &mut batch_transcript(),
    )
    .unwrap();
    let public = BatchPublic {
        prefix,
        inputs,
        split,
        queries: query_commitments,
        quotient: prover_transcript.quotient.unwrap(),
        evaluations: prover_transcript.evaluations.try_into().unwrap(),
    };
    let (alpha, replayed_u, beta, transcript) = public.replay(transcript);
    assert_eq!(witness.u, u);
    assert_eq!(replayed_u, u);
    let params = Params::with_k(generators, j, TestR::RANK);

    assert_ne!(bases.g1.to_projective(), bases.g0 * u);
    let mask: C::Scalar = random(rng);
    let d =
        (commitment.to_projective() + bases.g0 * -(value + u * mask) + bases.g1 * mask).to_affine();
    witness.p[0] -= value + u * mask;
    witness.p[1] += mask;
    let transcript = bind_opening(transcript, d, u);
    let relation = BatchRelation {
        bases,
        alpha,
        u,
        beta,
        public: &public,
        d,
    };
    let batch_witness = BatchWitness {
        input_blinds,
        quotient_blind: batch_blinds[0],
        queries,
        evaluations: array::from_fn(|i| Opening {
            value: batch.evaluations[i],
            blind: batch_blinds[1 + i],
        }),
        mask,
    };
    let split = split_proof::prove(bases, transcript.clone(), &split_witness, &queries, rng);
    let proof = relation
        .prove(&mut transcript.clone(), &batch_witness, rng)
        .unwrap();
    let ipa = ipa::create_proof::<Backend, _>(
        &params,
        &mut *rng,
        &mut ipa_transcript(transcript.clone()),
        &witness.p,
        u,
    )
    .unwrap();

    assert_eq!(params.commit::<Verifier>(&witness.p).to_affine(), d);
    assert_eq!(evaluate_iter(&witness.p, u), C::Scalar::ZERO);
    (
        BatchOpening {
            public,
            d,
            u,
            proof,
            split,
            ipa,
        },
        bases,
        params,
    )
}

mod replay;

fn change_point<C: Affine>(point: C, delta: C) -> C {
    (point.to_projective() + delta.to_projective()).to_affine()
}

fn reject_mutations<C: Affine>(
    proof: &BatchOpening<C>,
    bases: Bases<C>,
    params: &Params<C>,
    transcript: Transcript,
    changed_header: Transcript,
    wrong_domain: Transcript,
    other: &BatchOpening<C>,
) {
    let verify = |candidate: &BatchOpening<C>| {
        candidate.verify_terminal_batch(transcript.clone(), bases, params)
    };
    assert!(verify(proof));
    assert!(!proof.verify_terminal_batch(changed_header, bases, params));
    assert!(!proof.verify_terminal_batch(wrong_domain, bases, params));
    let (alpha, u, beta, _) = proof.public.replay(transcript.clone());
    let mut bad = proof.clone();
    bad.d = change_point(bad.d, bases.g0);
    assert!(!verify(&bad));
    bad = proof.clone();
    bad.u += C::Scalar::ONE;
    assert!(!verify(&bad));
    bad = proof.clone();
    bad.public.prefix = change_point(bad.public.prefix, bases.g0);
    assert_ne!(bad.public.replay(transcript.clone()).0, alpha);
    assert!(!verify(&bad));
    bad = proof.clone();
    bad.public.quotient.second = change_point(bad.public.quotient.second, bases.g0);
    let (before_quotient, after_quotient, _, _) = bad.public.replay(transcript.clone());
    assert_eq!(before_quotient, alpha);
    assert_ne!(after_quotient, u);
    assert!(!verify(&bad));
    bad = proof.clone();
    bad.public.evaluations[0] = change_point(bad.public.evaluations[0], bases.g0);
    let (same_alpha, same_u, changed_beta, _) = bad.public.replay(transcript.clone());
    assert_eq!((same_alpha, same_u), (alpha, u));
    assert_ne!(changed_beta, beta);
    assert!(!verify(&bad));
    bad = proof.clone();
    bad.proof = other.proof.clone();
    assert!(!verify(&bad));
    bad = proof.clone();
    bad.split = other.split.clone();
    assert!(!verify(&bad));
    bad = proof.clone();
    bad.ipa = other.ipa.clone();
    assert!(!verify(&bad));

    // A valid zero IPA chosen independently of the batch cannot pass its checks.
    let mut bad = proof.clone();
    let (_, u, _, transcript) = bad.public.replay(transcript.clone());
    let zero_poly = alloc::vec![C::Scalar::ZERO; TestR::num_coeffs()];
    bad.d = C::identity();
    let bound = bind_opening(transcript, bad.d, u);
    bad.ipa = ipa::create_proof::<Backend, _>(
        params,
        StdRng::seed_from_u64(23),
        &mut ipa_transcript(bound.clone()),
        &zero_poly,
        u,
    )
    .unwrap();
    assert!(verify_zero(params, bound, &bad.ipa, bad.d, u));
    assert!(!verify(&bad));
}

/// Native equivalent of the IPA equation with an advised G' and a separate
/// generator check. The PR #894 circuit binds the same polynomial via staging.
fn verify_folded_generator<C: Affine>(
    proof: &BatchOpening<C>,
    context: Transcript,
    params: &Params<C>,
) {
    let (_, u, _, transcript) = proof.public.replay(context);
    let mut transcript = ipa_transcript(bind_opening(transcript, proof.d, u));
    let mut msm = MSM::new(params);
    msm.append_term(C::Scalar::ONE, proof.d);
    let guard =
        ipa::verify_proof(params, msm, &mut transcript, &proof.ipa, u, C::Scalar::ZERO).unwrap();

    let g = guard.compute_g::<Verifier>();
    let (equation, accumulator) = guard.use_g(g);
    assert!(equation.eval::<Verifier>());
    let coeffs = (0..TestR::num_coeffs())
        .map(|i| {
            accumulator
                .u
                .iter()
                .rev()
                .enumerate()
                .filter(|(bit, _)| (i >> bit) & 1 == 1)
                .fold(C::Scalar::ONE, |product, (_, &round)| product * round)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        params.commit::<Verifier>(&coeffs).to_affine(),
        accumulator.g
    );
}

#[test]
fn fixed_zero_ipa_supports_identity_rounds_on_both_curves() {
    fn check<C: Affine>(generators: &impl FixedGenerators<C>, j: C, domain: &[u8]) {
        let params = Params::with_k(generators, j, 1);
        let u = C::Scalar::ZERO;
        for constant in [C::Scalar::ZERO, C::Scalar::ONE] {
            let polynomial = [constant, C::Scalar::ONE];
            let d = params.commit::<Backend>(&polynomial).to_affine();
            let transcript = bind_opening(Transcript::new(domain), d, u);
            let opening = ipa::create_proof::<Backend, _>(
                &params,
                StdRng::seed_from_u64(5),
                &mut ipa_transcript(transcript.clone()),
                &polynomial,
                u,
            )
            .unwrap();
            assert!(opening.rounds[0].1.is_identity());
            assert_eq!(
                verify_zero(&params, transcript, &opening, d, u),
                constant == C::Scalar::ZERO
            );
        }
    }

    let params = crate::pasta::baked();
    check(
        Pasta::host_generators(params),
        *Pasta::host_u(params),
        b"host identity round",
    );
    check(
        Pasta::nested_generators(params),
        *Pasta::nested_u(params),
        b"nested identity round",
    );
}

#[test]
fn masked_real_batches_and_private_terminal_proofs() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(20261118);
    let (pcd, ()) = app.seed(&mut rng, Seed, Fp::from(7)).unwrap();
    assert!(
        app.verify_uncompressed(&pcd, StdRng::seed_from_u64(93))
            .unwrap()
    );

    let start = Instant::now();
    let ordinary = app.compress(&pcd, &mut rng).unwrap();
    let ordinary_time = start.elapsed();
    let ordinary_bytes = ordinary.proof().to_bytes().unwrap().len();
    let start = Instant::now();
    assert!(app.verify_compressed(&ordinary).unwrap());
    let ordinary_verify_time = start.elapsed();

    let header = ky::output_header::<Pasta, Value, HEADER_SIZE>(*pcd.data())
        .unwrap()
        .try_into()
        .unwrap();
    let wrong_header = ky::output_header::<Pasta, Value, HEADER_SIZE>(Fp::from(8))
        .unwrap()
        .try_into()
        .unwrap();
    let start = Instant::now();
    let (fuse, joint, native, nested) = replay::batches(&app, &pcd, &header, &mut rng);
    let experiment_time = start.elapsed();
    let (_, _, native_again, nested_again) = replay::batches(&app, &pcd, &header, &mut rng);
    assert!(joint.instance.has_expected_shape());
    let (native_proof, native_bases, native_params) = native;
    let (nested_proof, nested_bases, nested_params) = nested;
    assert_ne!(native_proof.u, native_again.0.u);
    assert_ne!(native_proof.d, native_again.0.d);
    assert_ne!(nested_proof.u, nested_again.0.u);
    assert_ne!(nested_proof.d, nested_again.0.d);

    let side = |label, header| joint.batch_transcript(&app, header, &fuse, label);
    let start = Instant::now();
    assert!(joint.verify_native(
        &app,
        &header,
        &fuse,
        &native_proof,
        native_bases,
        &native_params
    ));
    assert!(joint.verify_nested(
        &app,
        &header,
        &fuse,
        &nested_proof,
        nested_bases,
        &nested_params
    ));
    assert!(fuse.verify(&app, &header, &joint.instance, native_bases));
    assert!(
        native_proof.public.queries[CLAIMS - 3..]
            .iter()
            .all(|(x, _)| *x == fuse.native_u)
    );
    let partial_verify_time = start.elapsed();
    assert!(!fuse.verify(&app, &wrong_header, &joint.instance, native_bases));
    let wrong_app = crate::ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .finalize(crate::pasta::baked())
        .unwrap();
    assert_ne!(app.native_registry.tag(), wrong_app.native_registry.tag());
    assert!(!fuse.verify(&wrong_app, &header, &joint.instance, native_bases));
    assert!(!joint.verify_native(
        &wrong_app,
        &header,
        &fuse,
        &native_proof,
        native_bases,
        &native_params
    ));
    assert!(!joint.verify_nested(
        &wrong_app,
        &header,
        &fuse,
        &nested_proof,
        nested_bases,
        &nested_params
    ));
    let mut wrong_fold = joint.clone();
    wrong_fold.host_messages.points[0].second =
        change_point(wrong_fold.host_messages.points[0].second, native_bases.g0);
    assert!(!wrong_fold.verify_native(
        &app,
        &header,
        &fuse,
        &native_proof,
        native_bases,
        &native_params
    ));
    let mut bad_input = nested_proof.clone();
    bad_input.public.inputs[0].second =
        change_point(bad_input.public.inputs[0].second, nested_bases.g0);
    assert!(!joint.verify_nested(
        &app,
        &header,
        &fuse,
        &bad_input,
        nested_bases,
        &nested_params
    ));
    let mut wrong_bridge = fuse.clone();
    wrong_bridge.bridges[0] = change_point(wrong_bridge.bridges[0], native_bases.g0);
    assert!(!wrong_bridge.verify(&app, &header, &joint.instance, native_bases));
    let mut wrong_fuse_u = fuse.clone();
    wrong_fuse_u.native_u = change_point(wrong_fuse_u.native_u, native_bases.g0);
    assert!(!wrong_fuse_u.verify(&app, &header, &joint.instance, native_bases));
    reject_mutations(
        &native_proof,
        native_bases,
        &native_params,
        side(b"native", &header),
        side(b"native", &wrong_header),
        side(b"nested", &header),
        &native_again.0,
    );
    reject_mutations(
        &nested_proof,
        nested_bases,
        &nested_params,
        side(b"nested", &header),
        side(b"nested", &wrong_header),
        side(b"native", &header),
        &nested_again.0,
    );

    verify_folded_generator(&native_proof, side(b"native", &header), &native_params);
    verify_folded_generator(&nested_proof, side(b"nested", &header), &nested_params);

    // Packed element inventory with the same rank on both curves. This
    // excludes a codec, public H, and the unimplemented parts of replay.
    let opening_elements = 2 + 2 * TestR::RANK as usize;
    let per_curve = 1
        + 2 * POLYS
        + 2 * CLAIMS
        + 2
        + POLYS
        + 2
        + batch_proof::proof_elements()
        + opening_elements;
    let bytes = 2 * 32 * (per_curve + split_proof::AUX)
        + 32 * (17
            + fuse.proof_elements()
            + native_proof.split.elements()
            + nested_proof.split.elements());
    let bytes = bytes + 32 * joint.elements();
    std::println!(
        "rank {}, {POLYS} polynomials, {CLAIMS} claims per curve\n         ordinary: {ordinary_time:?} prove, {ordinary_verify_time:?} verify, {ordinary_bytes} bytes\n         experiment: {experiment_time:?} including native replay, {partial_verify_time:?} Fuse, split and terminal verification, {bytes} bytes of elements",
        TestR::RANK,
    );
}
