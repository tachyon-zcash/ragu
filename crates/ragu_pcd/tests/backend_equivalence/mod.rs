#[cfg(feature = "unstable-fuzzing")]
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use proptest::{prelude::*, test_runner::TestCaseResult};
use ragu_acceleration::{AcceleratedBackend, AcceleratedProver};
#[cfg(feature = "unstable-fuzzing")]
use ragu_arithmetic::ff::PrimeField;
use ragu_arithmetic::{Cycle, ff::Field};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{ProductionRank, Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};
use ragu_pasta::{Fp, Fq, Pasta};
use ragu_primitives::allocator::Standard;
use ragu_testing::strategies::{bounded_edge_usize, edge_u64, nonzero_prime_field_element};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    Application, ApplicationBuilder, Pcd, Proof, SelectableBackend,
    header::Header,
    step::{Encoded, Index, Step},
};
#[cfg(feature = "unstable-fuzzing")]
use crate::{
    fuse::test_steps::{Add, AddAtTwo, Leaf, Number, OrderedAdd},
    fuzzing::corrupt::{NativeCommitment, NestedCommitment},
    internal::nested,
    verify::VerificationChecks,
};

static TRACKING_MSM_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Test backend that records whether PCD dispatch reaches `Backend::msm`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TrackingBackend;

impl TrackingBackend {
    fn reset_msm_calls() {
        TRACKING_MSM_CALLS.store(0, Ordering::Relaxed);
    }

    fn msm_calls() -> usize {
        TRACKING_MSM_CALLS.load(Ordering::Relaxed)
    }
}

impl Backend for TrackingBackend {
    fn msm<
        'a,
        C: ragu_arithmetic::CurveAffine,
        A: IntoIterator<Item = &'a C::Scalar>,
        Bases: IntoIterator<Item = &'a C>,
    >(
        coeffs: A,
        bases: Bases,
    ) -> C::Curve
    where
        Bases::IntoIter: Clone + Sync,
    {
        TRACKING_MSM_CALLS.fetch_add(1, Ordering::Relaxed);
        ReferenceBackend::msm(coeffs, bases)
    }
}

impl crate::backend::TestSealed for TrackingBackend {
    type Verifier = Self;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerifierDecision {
    Accept,
    Reject,
    Error,
}

const TEST_HEADER_SIZE: usize = 4;
const RNG_FINGERPRINT_WORDS: usize = 4;
const MAX_DUMMY_CIRCUITS: usize = 3;
const MAX_CORRUPTED_HEADER_LEN: usize = TEST_HEADER_SIZE * 2;

type TestApplication<'params, B> = Application<'params, Pasta, ProductionRank, TEST_HEADER_SIZE, B>;
type TestPcd<H = ()> = Pcd<Pasta, ProductionRank, H>;
type RngFingerprint = [u64; RNG_FINGERPRINT_WORDS];
type Outcome = (VerifierDecision, RngFingerprint);

/// Minimal application step used to drive the protocol in backend tests.
#[derive(Clone, Copy)]
struct UnitStep;

impl Step<Pasta> for UnitStep {
    const INDEX: Index = Index::new(0);

    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::unit(), D::unit()))
    }
}

/// Every selectable backend, over the same registered circuits: the reference,
/// the accelerated backend verifying with its own kernels, and the accelerated
/// prover verifying with the reference kernels.
struct Apps {
    reference: TestApplication<'static, ReferenceBackend>,
    accelerated: TestApplication<'static, AcceleratedBackend>,
    prover: TestApplication<'static, AcceleratedProver>,
}

impl Apps {
    fn build(dummy_circuits: usize) -> Self {
        let pasta = Pasta::baked();
        let reference = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .register(UnitStep)
            .unwrap()
            .register_dummy_circuits(dummy_circuits)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let accelerated = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .with_backend::<AcceleratedBackend>()
            .register(UnitStep)
            .unwrap()
            .register_dummy_circuits(dummy_circuits)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let prover = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .with_backend::<AcceleratedProver>()
            .register(UnitStep)
            .unwrap()
            .register_dummy_circuits(dummy_circuits)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        Self {
            reference,
            accelerated,
            prover,
        }
    }

    #[cfg(feature = "unstable-fuzzing")]
    fn build_semantic_source() -> Self {
        let pasta = Pasta::baked();
        let reference = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .register(Add)
            .unwrap()
            .register(AddAtTwo)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let accelerated = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .with_backend::<AcceleratedBackend>()
            .register(Leaf)
            .unwrap()
            .register(Add)
            .unwrap()
            .register(AddAtTwo)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let prover = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .with_backend::<AcceleratedProver>()
            .register(Leaf)
            .unwrap()
            .register(Add)
            .unwrap()
            .register(AddAtTwo)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        Self {
            reference,
            accelerated,
            prover,
        }
    }

    #[cfg(feature = "unstable-fuzzing")]
    fn build_semantic_receiver() -> Self {
        let pasta = Pasta::baked();
        let reference = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .register(Add)
            .unwrap()
            .register(OrderedAdd)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let accelerated = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .with_backend::<AcceleratedBackend>()
            .register(Leaf)
            .unwrap()
            .register(Add)
            .unwrap()
            .register(OrderedAdd)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let prover = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .with_backend::<AcceleratedProver>()
            .register(Leaf)
            .unwrap()
            .register(Add)
            .unwrap()
            .register(OrderedAdd)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        Self {
            reference,
            accelerated,
            prover,
        }
    }

    fn check_registries(&self) -> TestCaseResult {
        let native = self.reference.native_registry.tag();
        let nested = self.reference.nested_registry.tag();
        prop_assert_eq!(native, self.accelerated.native_registry.tag());
        prop_assert_eq!(nested, self.accelerated.nested_registry.tag());
        prop_assert_eq!(native, self.prover.native_registry.tag());
        prop_assert_eq!(nested, self.prover.nested_registry.tag());
        Ok(())
    }

    /// Verifies `pcd` with every backend, reseeding the verifier RNG from
    /// `seed` each time, so the outcomes are comparable.
    fn verify_all<H: Header<Fp>>(
        &self,
        pcd: &TestPcd<H>,
        seed: u64,
    ) -> [(&'static str, Outcome); 3] {
        [
            ("reference", verifier_outcome(&self.reference, pcd, seed)),
            (
                "accelerated",
                verifier_outcome(&self.accelerated, pcd, seed),
            ),
            (
                "accelerated prover",
                verifier_outcome(&self.prover, pcd, seed),
            ),
        ]
    }
}

/// One proof per backend, produced by identical driving of identically seeded
/// RNGs.
struct Proofs {
    reference: TestPcd,
    accelerated: TestPcd,
    prover: TestPcd,
}

impl Proofs {
    fn proofs(&self) -> [(&TestPcd, &'static str); 3] {
        [
            (&self.reference, "reference"),
            (&self.accelerated, "accelerated"),
            (&self.prover, "accelerated prover"),
        ]
    }
}

#[derive(Clone, Copy, Debug)]
struct CorruptionInputs {
    p_blind_delta: Fp,
    p_eval_delta: Fp,
    ab_c_delta: Fp,
    circuit_id: u32,
    challenge_u_delta: Fp,
    challenge_x_delta: Fp,
    challenge_y_delta: Fp,
    left_header_len: usize,
    right_header_len: usize,
}

#[derive(Clone, Copy, Debug)]
enum ProofMutation<F> {
    PBlind(F),
    PEval(F),
    AbC(F),
    CircuitId(u32),
    ChallengeU(F),
    ChallengeX(F),
    ChallengeY(F),
    LeftHeaderLen(usize),
    RightHeaderLen(usize),
}

fn apply_proof_mutation<C: Cycle, R: Rank>(
    proof: &mut Proof<C, R>,
    mutation: ProofMutation<C::CircuitField>,
) {
    match mutation {
        ProofMutation::PBlind(value) => proof
            .native_p_poly
            .add_assign(&sparse::Polynomial::from_coeffs(alloc::vec![value])),
        ProofMutation::PEval(value) => {
            proof
                .native_p_poly
                .add_assign(&sparse::Polynomial::from_coeffs(alloc::vec![
                    C::CircuitField::ZERO,
                    value,
                ]))
        }
        ProofMutation::AbC(value) => proof
            .native_a_poly
            .add_assign(&sparse::Polynomial::from_coeffs(alloc::vec![value])),
        ProofMutation::CircuitId(id) => proof.circuit_id = CircuitIndex::from_u32(id),
        ProofMutation::ChallengeU(value) => proof.u = value,
        ProofMutation::ChallengeX(value) => proof.x = value,
        ProofMutation::ChallengeY(value) => proof.y = value,
        ProofMutation::LeftHeaderLen(len) => {
            proof.left_header.resize(len, C::CircuitField::ZERO);
        }
        ProofMutation::RightHeaderLen(len) => {
            proof.right_header.resize(len, C::CircuitField::ZERO);
        }
    }
}

fn arb_dummy_circuit_count() -> impl Strategy<Value = usize> {
    bounded_edge_usize(MAX_DUMMY_CIRCUITS)
}

fn arb_invalid_header_len() -> impl Strategy<Value = usize> {
    bounded_edge_usize(MAX_CORRUPTED_HEADER_LEN).prop_filter(
        "header length differs from the application header size",
        |len| *len != TEST_HEADER_SIZE,
    )
}

fn arb_corruption_inputs() -> impl Strategy<Value = CorruptionInputs> {
    (
        nonzero_prime_field_element(),
        nonzero_prime_field_element(),
        nonzero_prime_field_element(),
        any::<u32>(),
        nonzero_prime_field_element(),
        nonzero_prime_field_element(),
        nonzero_prime_field_element(),
        arb_invalid_header_len(),
        arb_invalid_header_len(),
    )
        .prop_map(
            |(
                p_blind_delta,
                p_eval_delta,
                ab_c_delta,
                circuit_id,
                challenge_u_delta,
                challenge_x_delta,
                challenge_y_delta,
                left_header_len,
                right_header_len,
            )| CorruptionInputs {
                p_blind_delta,
                p_eval_delta,
                ab_c_delta,
                circuit_id,
                challenge_u_delta,
                challenge_x_delta,
                challenge_y_delta,
                left_header_len,
                right_header_len,
            },
        )
}

/// Two cases by default: each case builds three applications and runs the
/// protocol end to end. `PROPTEST_CASES` raises it (CI sets a floor).
fn config() -> ProptestConfig {
    let mut config = ProptestConfig::with_cases(2);
    if let Some(cases) = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
    {
        config.cases = cases;
    }
    config
}

fn rng_fingerprint(rng: &mut StdRng) -> RngFingerprint {
    core::array::from_fn(|_| rng.random())
}

fn verifier_outcome<B: SelectableBackend, H: Header<Fp>>(
    app: &TestApplication<'_, B>,
    pcd: &TestPcd<H>,
    seed: u64,
) -> Outcome {
    let mut rng = StdRng::seed_from_u64(seed);
    let decision = match app.verify(pcd, &mut rng) {
        Ok(true) => VerifierDecision::Accept,
        Ok(false) => VerifierDecision::Reject,
        Err(_) => VerifierDecision::Error,
    };
    (decision, rng_fingerprint(&mut rng))
}

fn corruptions(
    proof: &Proof<Pasta, ProductionRank>,
    inputs: CorruptionInputs,
) -> impl IntoIterator<Item = (&'static str, ProofMutation<Fp>)> {
    [
        ("p blind", ProofMutation::PBlind(inputs.p_blind_delta)),
        ("p evaluation", ProofMutation::PEval(inputs.p_eval_delta)),
        ("ab revdot", ProofMutation::AbC(inputs.ab_c_delta)),
        ("circuit id", ProofMutation::CircuitId(inputs.circuit_id)),
        (
            "challenge u",
            ProofMutation::ChallengeU(proof.u() + inputs.challenge_u_delta),
        ),
        (
            "challenge x",
            ProofMutation::ChallengeX(proof.x() + inputs.challenge_x_delta),
        ),
        (
            "challenge y",
            ProofMutation::ChallengeY(proof.y() + inputs.challenge_y_delta),
        ),
        (
            "left header",
            ProofMutation::LeftHeaderLen(inputs.left_header_len),
        ),
        (
            "right header",
            ProofMutation::RightHeaderLen(inputs.right_header_len),
        ),
    ]
}

/// Every backend must agree with the reference verifier on `pcd`: same
/// decision and same randomness consumption.
fn check_verifiers_agree<H: Header<Fp>>(
    apps: &Apps,
    pcd: &TestPcd<H>,
    verifier_seed: u64,
    context: &str,
) -> TestCaseResult {
    let outcomes = apps.verify_all(pcd, verifier_seed);
    let (_, reference_outcome) = outcomes[0];
    for (backend, outcome) in &outcomes[1..] {
        prop_assert_eq!(
            *outcome,
            reference_outcome,
            "verifier result or RNG consumption mismatch between reference and {} for {}",
            backend,
            context,
        );
    }
    Ok(())
}

/// Independently advance the verifier RNG through the complete schedule for
/// a well-formed proof. This deliberately does not call a verifier helper or
/// share its control flow: three native claim challenges, three nested claim
/// and registry challenges, then the native and nested commitment scalars.
fn full_verifier_schedule(seed: u64) -> RngFingerprint {
    let mut rng = StdRng::seed_from_u64(seed);
    let _: Fp = Fp::random(&mut rng);
    let _: Fp = Fp::random(&mut rng);
    let _: Fp = Fp::random(&mut rng);
    let _: Fq = Fq::random(&mut rng);
    let _: Fq = Fq::random(&mut rng);
    let _: Fq = Fq::random(&mut rng);
    let _: Fp = Fp::random(&mut rng);
    let _: Fq = Fq::random(&mut rng);
    rng_fingerprint(&mut rng)
}

/// Backend agreement is necessary but not sufficient: a well-formed attack
/// must also reach the independently specified full verifier RNG schedule.
#[cfg(feature = "unstable-fuzzing")]
fn check_well_formed_verifiers(
    apps: &Apps,
    pcd: &TestPcd<Number>,
    verifier_seed: u64,
    expected: VerifierDecision,
    context: &str,
) -> TestCaseResult {
    check_verifiers_agree(apps, pcd, verifier_seed, context)?;
    let schedule = full_verifier_schedule(verifier_seed);
    for (backend, (decision, fingerprint)) in apps.verify_all(pcd, verifier_seed) {
        prop_assert_eq!(
            decision,
            expected,
            "unexpected {} decision for {}",
            backend,
            context,
        );
        prop_assert_eq!(
            fingerprint,
            schedule,
            "{} did not follow the full verifier RNG schedule for {}",
            backend,
            context,
        );
    }
    Ok(())
}

#[cfg(feature = "unstable-fuzzing")]
#[derive(Clone, Copy, Debug)]
enum CoherentBatch {
    Native,
    Nested,
}

/// Change a polynomial by delta * (X-u), preserving its opening at `u`.
/// The dense Horner calculation is intentionally separate from the sparse
/// polynomial implementation used by the prover and verifier.
#[cfg(feature = "unstable-fuzzing")]
fn preserve_evaluation<F: PrimeField>(poly: &mut sparse::Polynomial<F, ProductionRank>, u: F) {
    let before: Vec<_> = poly.iter_coeffs().collect();
    let delta = F::from(7);
    let mut after = before.clone();
    after[0] -= delta * u;
    after[1] += delta;

    let dense_eval = |coefficients: &[F]| {
        coefficients
            .iter()
            .rev()
            .fold(F::ZERO, |acc, coefficient| acc * u + coefficient)
    };
    assert_eq!(dense_eval(&before), dense_eval(&after));
    *poly = sparse::Polynomial::from_coeffs(after.clone());
    assert_eq!(poly.eval(u), dense_eval(&before));
    assert_ne!(before, after);
}

/// Produce the same evaluation-preserving, cache-repaired proof substitution
/// that the focused substitution tests exercise. Commitments are recomputed
/// by both independent backend implementations before any verifier sees it.
#[cfg(feature = "unstable-fuzzing")]
fn coherent_substitution(
    original: &Proof<Pasta, ProductionRank>,
    batch: CoherentBatch,
) -> Proof<Pasta, ProductionRank> {
    let mut changed = original.clone();
    match batch {
        CoherentBatch::Native => {
            preserve_evaluation(&mut changed.native_p_poly, original.u());
            let reference = ReferenceBackend::sparse_commit_to_affine(
                changed.native_p_poly(),
                Pasta::host_generators(Pasta::baked()),
            );
            let accelerated = AcceleratedBackend::sparse_commit_to_affine(
                changed.native_p_poly(),
                Pasta::host_generators(Pasta::baked()),
            );
            assert_eq!(reference, accelerated);
            assert_ne!(reference, original.native_p_commitment());
            *changed.native_commitment_cache_mut(NativeCommitment::P) = reference;
            assert_eq!(changed.v(), original.v());
        }
        CoherentBatch::Nested => {
            let nested_u = nested::challenge::<Pasta>(original.u())
                .expect("a produced proof has a valid nested challenge");
            preserve_evaluation(&mut changed.nested_p_poly, nested_u);
            let reference = ReferenceBackend::sparse_commit_to_affine(
                changed.nested_p_poly(),
                Pasta::nested_generators(Pasta::baked()),
            );
            let accelerated = AcceleratedBackend::sparse_commit_to_affine(
                changed.nested_p_poly(),
                Pasta::nested_generators(Pasta::baked()),
            );
            assert_eq!(reference, accelerated);
            assert_ne!(reference, original.nested_p_commitment());
            *changed.nested_commitment_cache_mut(NestedCommitment::P) = reference;
            assert_eq!(changed.nested_v().unwrap(), original.nested_v().unwrap());
        }
    }
    assert_eq!(
        changed.challenges().in_order(),
        original.challenges().in_order(),
    );
    assert_eq!(changed.left_header(), original.left_header());
    assert_eq!(changed.right_header(), original.right_header());
    changed
}

#[cfg(feature = "unstable-fuzzing")]
fn reference_checks(
    apps: &Apps,
    pcd: &TestPcd<Number>,
    verifier_seed: u64,
    context: &str,
) -> VerificationChecks {
    let (accepted, checks) = apps
        .reference
        .verify_with_checks(pcd, StdRng::seed_from_u64(verifier_seed))
        .unwrap();
    let checks = checks.expect("well-formed proof metadata reaches every verifier predicate");
    assert_eq!(accepted, checks.all(), "{context}: {checks:?}");
    checks
}

fn check_valid_pcd_equivalence(
    apps: &Apps,
    proofs: &Proofs,
    verifier_seed: u64,
    proof_kind: &str,
) -> TestCaseResult {
    for (pcd, backend) in &proofs.proofs()[1..] {
        let mismatch = proofs.reference.proof().test_mismatch(pcd.proof());
        prop_assert!(
            mismatch.is_none(),
            "{} {} proof differs from the reference proof in {}",
            backend,
            proof_kind,
            mismatch.unwrap(),
        );
    }

    for (proof_name, pcd) in [
        ("reference", &proofs.reference),
        ("accelerated", &proofs.accelerated),
        ("accelerated prover", &proofs.prover),
    ] {
        let context = alloc::format!("{proof_name} {proof_kind} proof");
        check_verifiers_agree(apps, pcd, verifier_seed, &context)?;
        let outcome = verifier_outcome(&apps.reference, pcd, verifier_seed);
        prop_assert_eq!(
            outcome.0,
            VerifierDecision::Accept,
            "valid {} was rejected",
            context,
        );
        prop_assert_eq!(
            outcome.1,
            full_verifier_schedule(verifier_seed),
            "valid {} did not follow the independently specified RNG schedule",
            context,
        );
    }

    Ok(())
}

fn check_corrupted_pcd_equivalence(
    apps: &Apps,
    pcd: &TestPcd,
    verifier_seed: u64,
    proof_kind: &str,
    corruption_inputs: CorruptionInputs,
) -> TestCaseResult {
    for (corruption_name, corruption) in corruptions(pcd.proof(), corruption_inputs) {
        let mut corrupted = pcd.proof().clone();
        apply_proof_mutation(&mut corrupted, corruption);
        prop_assert!(
            pcd.proof().test_mismatch(&corrupted).is_some(),
            "proof comparison ignored {} corruption in {} proof",
            corruption_name,
            proof_kind,
        );
        let corrupted_pcd = corrupted.carry::<()>(());
        let context = alloc::format!("{corruption_name} corruption in {proof_kind} proof");
        check_verifiers_agree(apps, &corrupted_pcd, verifier_seed, &context)?;
        prop_assert_ne!(
            verifier_outcome(&apps.reference, &corrupted_pcd, verifier_seed).0,
            VerifierDecision::Accept,
            "verifier accepted {}",
            context,
        );
    }

    Ok(())
}

#[cfg(feature = "unstable-fuzzing")]
#[test]
fn coherent_attacks_match_all_backends_and_independent_oracles() -> TestCaseResult {
    const PROOF_SEED: u64 = 0x0000_0009_0873_0001;
    const VERIFIER_SEED: u64 = 0x0000_0009_0873_0002;
    const LEFT: Fp = Fp::from_raw([19, 0, 0, 0]);
    const RIGHT: Fp = Fp::from_raw([43, 0, 0, 0]);

    let source = Apps::build_semantic_source();
    let receiver = Apps::build_semantic_receiver();
    source.check_registries()?;
    receiver.check_registries()?;

    let mut rng = StdRng::seed_from_u64(PROOF_SEED);
    let left = source.reference.seed(&mut rng, Leaf, LEFT).unwrap().0;
    let right = source.reference.seed(&mut rng, Leaf, RIGHT).unwrap().0;
    let parent = source
        .reference
        .fuse(&mut rng, AddAtTwo, (), left, right)
        .unwrap()
        .0;
    prop_assert_eq!(*parent.data(), LEFT + RIGHT);
    prop_assert_ne!(*parent.data(), LEFT + RIGHT + RIGHT);
    check_well_formed_verifiers(
        &source,
        &parent,
        VERIFIER_SEED,
        VerifierDecision::Accept,
        "source control",
    )?;

    for batch in [CoherentBatch::Native, CoherentBatch::Nested] {
        let changed_proof = coherent_substitution(parent.proof(), batch);
        prop_assert!(parent.proof().test_mismatch(&changed_proof).is_some());
        let changed = changed_proof.carry::<Number>(*parent.data());
        let context = alloc::format!("{batch:?} evaluation-preserving substitution");
        let checks = reference_checks(&source, &changed, VERIFIER_SEED, &context);
        prop_assert_eq!(
            checks,
            VerificationChecks {
                native_revdot: matches!(batch, CoherentBatch::Native),
                nested_revdot: matches!(batch, CoherentBatch::Nested),
                native_registry: true,
                nested_registry: true,
                nested_challenges: true,
                commitments: true,
                nested_points: true,
                transcript: true,
                ab_bridge: true,
                mesh: true,
            },
            "only the cross-field claim may reject {}",
            context,
        );
        check_well_formed_verifiers(
            &source,
            &changed,
            VERIFIER_SEED,
            VerifierDecision::Reject,
            &context,
        )?;
    }

    // The proof bytes and public output remain those of the source relation.
    // The receiver assigns the same circuit index to left + 2*right, which is
    // independently false for that output.
    let spliced = parent.proof().clone().carry::<Number>(*parent.data());
    prop_assert_eq!(spliced.proof().test_mismatch(parent.proof()), None);
    prop_assert_ne!(*spliced.data(), LEFT + RIGHT + RIGHT);
    let checks = reference_checks(&receiver, &spliced, VERIFIER_SEED, "application splice");
    prop_assert!(
        !checks.native_registry,
        "receiver registry accepted: {:?}",
        checks,
    );
    prop_assert!(
        checks.commitments,
        "unchanged caches rejected: {:?}",
        checks,
    );
    prop_assert!(
        checks.transcript,
        "unchanged transcript rejected: {:?}",
        checks,
    );
    check_well_formed_verifiers(
        &receiver,
        &spliced,
        VERIFIER_SEED,
        VerifierDecision::Reject,
        "application splice",
    )?;

    // Prove that the receiving context and all three of its verifiers accept
    // a proof generated for the relation they actually registered.
    let mut receiver_rng = StdRng::seed_from_u64(PROOF_SEED + 1);
    let left = receiver
        .reference
        .seed(&mut receiver_rng, Leaf, LEFT)
        .unwrap()
        .0;
    let right = receiver
        .reference
        .seed(&mut receiver_rng, Leaf, RIGHT)
        .unwrap()
        .0;
    let receiver_parent = receiver
        .reference
        .fuse(&mut receiver_rng, OrderedAdd, (), left, right)
        .unwrap()
        .0;
    prop_assert_eq!(*receiver_parent.data(), LEFT + RIGHT + RIGHT);
    check_well_formed_verifiers(
        &receiver,
        &receiver_parent,
        VERIFIER_SEED,
        VerifierDecision::Accept,
        "receiver control",
    )?;
    Ok(())
}

#[test]
fn selected_backend_dispatch_reaches_msm() {
    let app = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
        .with_backend::<TrackingBackend>()
        .register(UnitStep)
        .unwrap()
        .register_dummy_circuits(0)
        .unwrap()
        .finalize(Pasta::baked())
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0);
    let (left, _) = app.seed(&mut rng, UnitStep, ()).unwrap();
    let (right, _) = app.seed(&mut rng, UnitStep, ()).unwrap();

    TrackingBackend::reset_msm_calls();
    let _ = app.fuse(&mut rng, UnitStep, (), left, right).unwrap();

    assert!(
        TrackingBackend::msm_calls() > 0,
        "PCD did not dispatch MSM through its selected backend",
    );
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn reference_and_accelerated_verifiers_reject_padded_circuit_ids(
        proof_seed in edge_u64(),
        verifier_seed in edge_u64(),
        dummy_circuits in arb_dummy_circuit_count(),
        padded_slot_selector in any::<usize>(),
    ) {
        let apps = Apps::build(dummy_circuits);
        apps.check_registries()?;

        let num_circuits = apps.reference.native_registry.num_circuits();
        prop_assume!(!num_circuits.is_power_of_two());
        let domain_size = num_circuits.next_power_of_two();
        let padded_index =
            num_circuits + padded_slot_selector % (domain_size - num_circuits);
        let padded = CircuitIndex::new(padded_index);
        prop_assert!(apps.reference.native_registry.circuit_in_domain(padded));
        prop_assert!(apps.accelerated.native_registry.circuit_in_domain(padded));
        prop_assert!(apps.prover.native_registry.circuit_in_domain(padded));

        let mut proof_rng = StdRng::seed_from_u64(proof_seed);
        let (valid_pcd, _) = apps
            .reference
            .seed(&mut proof_rng, UnitStep, ())
            .unwrap();
        check_verifiers_agree(&apps, &valid_pcd, verifier_seed, "valid leaf proof")?;
        prop_assert_eq!(
            verifier_outcome(&apps.reference, &valid_pcd, verifier_seed).0,
            VerifierDecision::Accept,
        );

        let mut corrupted = valid_pcd.proof().clone();
        apply_proof_mutation(&mut corrupted, ProofMutation::CircuitId(
            usize::from(padded).try_into().unwrap(),
        ));
        prop_assert!(valid_pcd.proof().test_mismatch(&corrupted).is_some());
        let corrupted_pcd = corrupted.carry::<()>(());

        check_verifiers_agree(&apps, &corrupted_pcd, verifier_seed, "padded circuit id")?;
        prop_assert_eq!(
            verifier_outcome(&apps.reference, &corrupted_pcd, verifier_seed).0,
            VerifierDecision::Reject,
        );
    }
}

// TODO: Add this end-to-end backend-equivalence property for a generated
// nontrivial Step; UnitStep exercises the protocol and application-circuit
// paths, but not nontrivial gadget logic.
proptest! {
    #![proptest_config(config())]

    #[test]
    fn reference_and_accelerated_proofs_and_verifiers_are_equivalent(
        proof_seed in edge_u64(),
        verifier_seed in edge_u64(),
        dummy_circuits in arb_dummy_circuit_count(),
        corruption_inputs in arb_corruption_inputs(),
    ) {
        let apps = Apps::build(dummy_circuits);
        apps.check_registries()?;

        let corrupted_circuit = CircuitIndex::from_u32(corruption_inputs.circuit_id);
        prop_assume!(!apps
            .reference
            .native_registry
            .circuit_in_domain(corrupted_circuit));
        prop_assert!(!apps
            .accelerated
            .native_registry
            .circuit_in_domain(corrupted_circuit));

        let mut reference_rng = StdRng::seed_from_u64(proof_seed);
        let mut accelerated_rng = StdRng::seed_from_u64(proof_seed);
        let mut prover_rng = StdRng::seed_from_u64(proof_seed);

        let check_rngs = |reference_rng: &mut StdRng,
                              accelerated_rng: &mut StdRng,
                              prover_rng: &mut StdRng|
         -> TestCaseResult {
            let reference_rng_state = rng_fingerprint(reference_rng);
            prop_assert_eq!(reference_rng_state, rng_fingerprint(accelerated_rng));
            prop_assert_eq!(reference_rng_state, rng_fingerprint(prover_rng));
            Ok(())
        };

        let (reference_leaf1, _) = apps
            .reference
            .seed(&mut reference_rng, UnitStep, ())
            .unwrap();
        let (accelerated_leaf1, _) = apps
            .accelerated
            .seed(&mut accelerated_rng, UnitStep, ())
            .unwrap();
        let (prover_leaf1, _) = apps
            .prover
            .seed(&mut prover_rng, UnitStep, ())
            .unwrap();
        check_rngs(&mut reference_rng, &mut accelerated_rng, &mut prover_rng)?;
        let leaf1 = Proofs {
            reference: reference_leaf1,
            accelerated: accelerated_leaf1,
            prover: prover_leaf1,
        };
        check_valid_pcd_equivalence(&apps, &leaf1, verifier_seed, "leaf")?;

        let (reference_leaf2, _) = apps
            .reference
            .seed(&mut reference_rng, UnitStep, ())
            .unwrap();
        let (accelerated_leaf2, _) = apps
            .accelerated
            .seed(&mut accelerated_rng, UnitStep, ())
            .unwrap();
        let (prover_leaf2, _) = apps
            .prover
            .seed(&mut prover_rng, UnitStep, ())
            .unwrap();
        check_rngs(&mut reference_rng, &mut accelerated_rng, &mut prover_rng)?;

        let (reference_node, _) = apps
            .reference
            .fuse(
                &mut reference_rng,
                UnitStep,
                (),
                leaf1.reference,
                reference_leaf2,
            )
            .unwrap();
        let (accelerated_node, _) = apps
            .accelerated
            .fuse(
                &mut accelerated_rng,
                UnitStep,
                (),
                leaf1.accelerated,
                accelerated_leaf2,
            )
            .unwrap();
        let (prover_node, _) = apps
            .prover
            .fuse(&mut prover_rng, UnitStep, (), leaf1.prover, prover_leaf2)
            .unwrap();
        check_rngs(&mut reference_rng, &mut accelerated_rng, &mut prover_rng)?;
        let node = Proofs {
            reference: reference_node,
            accelerated: accelerated_node,
            prover: prover_node,
        };
        check_valid_pcd_equivalence(&apps, &node, verifier_seed, "fused")?;
        check_corrupted_pcd_equivalence(
            &apps,
            &node.reference,
            verifier_seed,
            "fused",
            corruption_inputs,
        )?;
    }
}
