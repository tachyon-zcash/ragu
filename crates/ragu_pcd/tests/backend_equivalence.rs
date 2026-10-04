use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use proptest::{prelude::*, test_runner::TestCaseResult};
use ragu_acceleration::{AcceleratedBackend, AcceleratedProver};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{ProductionRank, Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::allocator::Standard;
use ragu_testing::strategies::{bounded_edge_usize, edge_u64, nonzero_prime_field_element};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use udon::{fft::Domain, field::Field};

use crate::{
    Application, ApplicationBuilder, CompressedPcd, CompressedProof, Pcd, Proof, SelectableBackend,
    step::{Encoded, Index, Step},
};

static TRACKING_MSM_CALLS: AtomicUsize = AtomicUsize::new(0);
static TRACKING_FFT_CALLS: AtomicUsize = AtomicUsize::new(0);
static TRACKING_IFFT_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Test backend that records MSM and transform dispatch, including worker threads.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TrackingBackend;

impl TrackingBackend {
    fn reset_calls() {
        TRACKING_MSM_CALLS.store(0, Ordering::Relaxed);
        TRACKING_FFT_CALLS.store(0, Ordering::Relaxed);
        TRACKING_IFFT_CALLS.store(0, Ordering::Relaxed);
    }

    fn calls() -> [usize; 3] {
        [
            TRACKING_MSM_CALLS.load(Ordering::Relaxed),
            TRACKING_FFT_CALLS.load(Ordering::Relaxed),
            TRACKING_IFFT_CALLS.load(Ordering::Relaxed),
        ]
    }
}

impl Backend for TrackingBackend {
    fn msm<
        'a,
        C: udon::curve::Affine,
        A: IntoIterator<Item = &'a C::Scalar>,
        Bases: IntoIterator<Item = &'a C>,
    >(
        coeffs: A,
        bases: Bases,
    ) -> C::Projective
    where
        Bases::IntoIter: Clone + Sync,
    {
        TRACKING_MSM_CALLS.fetch_add(1, Ordering::Relaxed);
        ReferenceBackend::msm(coeffs, bases)
    }

    fn fft<F: Field>(domain: Domain<F>, values: &mut Vec<F>) {
        TRACKING_FFT_CALLS.fetch_add(1, Ordering::Relaxed);
        ReferenceBackend::fft(domain, values);
    }

    fn ifft<F: Field>(domain: Domain<F>, values: &mut Vec<F>) {
        TRACKING_IFFT_CALLS.fetch_add(1, Ordering::Relaxed);
        ReferenceBackend::ifft(domain, values);
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
type TestPcd = Pcd<Pasta, ProductionRank, ()>;
type TestCompressedPcd = CompressedPcd<Pasta, ()>;
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
        let pasta = ragu_pcd::pasta::baked();
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
    fn verify_all(&self, pcd: &TestPcd, seed: u64) -> [(&'static str, Outcome); 3] {
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

    fn verify_compressed_all(&self, pcd: &TestCompressedPcd) -> [(&'static str, Result<bool>); 3] {
        [
            ("reference", self.reference.verify_compressed(pcd)),
            ("accelerated", self.accelerated.verify_compressed(pcd)),
            ("accelerated prover", self.prover.verify_compressed(pcd)),
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
        .filter(|&cases: &u32| cases > 0)
    {
        config.cases = cases;
    }
    config
}

fn rng_fingerprint(rng: &mut StdRng) -> RngFingerprint {
    core::array::from_fn(|_| rng.random())
}

fn verifier_outcome<B: SelectableBackend>(
    app: &TestApplication<'_, B>,
    pcd: &TestPcd,
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
fn check_verifiers_agree(
    apps: &Apps,
    pcd: &TestPcd,
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
        prop_assert_eq!(
            verifier_outcome(&apps.reference, pcd, verifier_seed).0,
            VerifierDecision::Accept,
            "valid {} was rejected",
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
        // A rejection, not an error: the verifier must decide on a
        // corrupted proof rather than fail on it.
        prop_assert_eq!(
            verifier_outcome(&apps.reference, &corrupted_pcd, verifier_seed).0,
            VerifierDecision::Reject,
            "verifier did not reject {}",
            context,
        );
    }

    Ok(())
}

/// With identical inputs and RNGs, every transmitted field must match.
fn check_compressed_proofs_match(
    expected: &CompressedProof<Pasta>,
    actual: &CompressedProof<Pasta>,
    backend: &str,
) -> TestCaseResult {
    macro_rules! compare_fields {
        ($($($field:ident).+),+ $(,)?) => {
            $(prop_assert_eq!(
                &expected.$($field).+,
                &actual.$($field).+,
                "{} compressed proof differs in {}",
                backend,
                stringify!($($field).+),
            );)+
        };
    }

    compare_fields!(
        instance.circuit_id,
        instance.left_header,
        instance.right_header,
        instance.native,
        instance.native_registry_xy,
        instance.native_p,
        instance.nested,
        instance.nested_registry_xy,
        instance.nested_p,
        instance.nested_challenges_partial,
        instance.bridge_alpha,
        instance.c,
        instance.v,
        instance.nested_c,
        instance.nested_v,
        instance.left.x,
        instance.left.y,
        instance.left.id,
        instance.right.x,
        instance.right.y,
        instance.right.id,
        instance.a_at_u,
        instance.b_at_u,
        instance.nested_left.x,
        instance.nested_left.y,
        instance.nested_right.x,
        instance.nested_right.y,
        instance.nested_a_at_u,
        instance.nested_b_at_u,
        native.reduction.fold.inner,
        native.reduction.fold.outer,
        native.reduction.fold.inner_epsilon,
        native.reduction.fold.outer_epsilon,
        native.reduction.p,
        native.reduction.q,
        native.reduction.openings,
        native.reduction.p_at_inverse_r,
        native.reduction.q_at_r,
        native.batch.f,
        native.batch.evaluations,
        native.opening,
        nested.reduction.fold.inner,
        nested.reduction.fold.outer,
        nested.reduction.fold.inner_epsilon,
        nested.reduction.fold.outer_epsilon,
        nested.reduction.p,
        nested.reduction.q,
        nested.reduction.openings,
        nested.reduction.p_at_inverse_r,
        nested.reduction.q_at_r,
        nested.batch.f,
        nested.batch.evaluations,
        nested.opening,
    );
    Ok(())
}

fn check_compressed_pcd_equivalence(
    apps: &Apps,
    proofs: &[(TestCompressedPcd, &str); 3],
) -> TestCaseResult {
    let reference = proofs[0].0.proof();
    for (pcd, backend) in &proofs[1..] {
        check_compressed_proofs_match(reference, pcd.proof(), backend)?;
    }

    // Each prover's output must be accepted by every verifier configuration.
    for (pcd, prover) in proofs {
        for (verifier, result) in apps.verify_compressed_all(pcd) {
            prop_assert!(
                matches!(result, Ok(true)),
                "{} verifier did not accept {} compressed proof: {:?}",
                verifier,
                prover,
                result,
            );
        }
    }

    type Mutation = fn(&mut CompressedProof<Pasta>);
    let corruptions: &[(&str, Mutation)] = &[
        ("native instance value", |p| p.instance.c += Fp::ONE),
        ("nested instance value", |p| p.instance.nested_c += Fq::ONE),
        ("native reduction opening", |p| {
            p.native.reduction.openings[0] += Fp::ONE
        }),
        ("nested reduction opening", |p| {
            p.nested.reduction.openings[0] += Fq::ONE
        }),
        ("native batch commitment", |p| {
            p.native.batch.f = -p.native.batch.f
        }),
        ("nested batch commitment", |p| {
            p.nested.batch.f = -p.nested.batch.f
        }),
        ("native batch evaluation", |p| {
            p.native.batch.evaluations[0] += Fp::ONE
        }),
        ("nested batch evaluation", |p| {
            p.nested.batch.evaluations[0] += Fq::ONE
        }),
        // These leave the reduction and batching messages intact, exercising
        // rejection by the IPA verifier on each curve.
        ("native IPA coefficient", |p| p.native.opening.c += Fp::ONE),
        ("nested IPA coefficient", |p| p.nested.opening.c += Fq::ONE),
    ];
    for &(case, edit) in corruptions {
        let mut corrupted = reference.clone();
        edit(&mut corrupted);
        let pcd = corrupted.carry::<()>(());
        for (verifier, result) in apps.verify_compressed_all(&pcd) {
            prop_assert!(
                matches!(result, Ok(false)),
                "{} verifier did not reject {} corruption: {:?}",
                verifier,
                case,
                result,
            );
        }
    }

    Ok(())
}

#[test]
fn selected_backend_dispatch_reaches_protocol_phases() {
    let app = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
        .with_backend::<TrackingBackend>()
        .register(UnitStep)
        .unwrap()
        .register_dummy_circuits(0)
        .unwrap()
        .finalize(ragu_pcd::pasta::baked())
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0);
    let (left, _) = app.seed(&mut rng, UnitStep, ()).unwrap();
    let (right, _) = app.seed(&mut rng, UnitStep, ()).unwrap();

    let assert_dispatch = |phase: &str, operations: &[(&str, usize)]| {
        for &(operation, calls) in operations {
            assert!(
                calls > 0,
                "{phase} did not dispatch {operation} through its selected backend"
            );
        }
    };

    // Reset after setup and between phases: earlier calls must not satisfy
    // an assertion about a later phase. Only this test uses TrackingBackend.
    TrackingBackend::reset_calls();
    let (fused, ()) = app.fuse(&mut rng, UnitStep, (), left, right).unwrap();
    // Fuse interpolates registry restrictions with IFFT; it needs no FFT.
    let [msm, _, ifft] = TrackingBackend::calls();
    assert_dispatch("Fuse", &[("MSM", msm), ("IFFT", ifft)]);

    TrackingBackend::reset_calls();
    assert!(app.verify(&fused, &mut rng).unwrap());
    let [msm, _, _] = TrackingBackend::calls();
    assert_dispatch("uncompressed verification", &[("MSM", msm)]);

    TrackingBackend::reset_calls();
    let compressed = app.compress(&fused, &mut rng).unwrap();
    let [msm, fft, ifft] = TrackingBackend::calls();
    assert_dispatch("compression", &[("MSM", msm), ("FFT", fft), ("IFFT", ifft)]);

    // Compressed verification needs MSMs but does not require transforms.
    TrackingBackend::reset_calls();
    assert!(app.verify_compressed(&compressed).unwrap());
    let [msm, _, _] = TrackingBackend::calls();
    assert_dispatch("compressed verification", &[("MSM", msm)]);
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

        let compressed = [
            (
                apps.reference.compress(&node.reference, &mut reference_rng).unwrap(),
                "reference",
            ),
            (
                apps.accelerated.compress(&node.accelerated, &mut accelerated_rng).unwrap(),
                "accelerated",
            ),
            (
                apps.prover.compress(&node.prover, &mut prover_rng).unwrap(),
                "accelerated prover",
            ),
        ];
        check_rngs(&mut reference_rng, &mut accelerated_rng, &mut prover_rng)?;
        check_compressed_pcd_equivalence(&apps, &compressed)?;
    }
}

mod proof_equivalence {
    //! Semantic proof comparison for backend-equivalence and recursion tests.

    use ragu_circuits::polynomials::{Rank, sparse::Polynomial};
    use ragu_core::Cycle;
    use udon::field::Field;

    use super::Proof;
    use crate::internal::{native, nested};

    fn polynomial_eq<F: Field, R: Rank>(left: &Polynomial<F, R>, right: &Polynomial<F, R>) -> bool {
        left.iter_coeffs().eq(right.iter_coeffs())
    }

    impl<C: Cycle, R: Rank> Proof<C, R> {
        /// Returns the first category in which two proofs differ semantically.
        ///
        /// The exhaustive pattern makes additions to [`Proof`] fail to compile
        /// until this comparison is reviewed. Polynomials are compared by their
        /// coefficient streams rather than their sparse storage layout.
        pub(crate) fn test_mismatch(&self, other: &Self) -> Option<&'static str> {
            let Self {
                bridge_alpha: _,
                circuit_id: _,
                left_header: _,
                right_header: _,
                native_application_rx: _,
                native_preamble_rx: _,
                native_inner_error_rx: _,
                native_outer_error_rx: _,
                native_a_poly: _,
                native_b_poly: _,
                native_query_rx: _,
                native_registry_xy_poly: _,
                native_eval_rx: _,
                native_p_poly: _,
                native_hashes_1_rx: _,
                native_hashes_2_rx: _,
                native_inner_collapse_rx: _,
                native_outer_collapse_rx: _,
                native_compute_v_rx: _,
                native_bind_challenges_rxs: _,
                native_bind_beta_rx: _,
                native_bind_endoscalar_rx: _,
                native_endoscaling_step_rxs: _,
                native_points_binding_rx: _,
                native_points_children_rx: _,
                native_points_registry_wx_rx: _,
                native_points_ab_rx: _,
                native_points_f_rx: _,
                native_points_walk_rx: _,
                bridge_preamble_rx: _,
                bridge_s_prime_rx: _,
                bridge_inner_error_rx: _,
                bridge_f_rx: _,
                bridge_outer_error_rx: _,
                bridge_ab_rx: _,
                bridge_query_rx: _,
                bridge_eval_rx: _,
                nested_endoscaling_step_rxs: _,
                nested_endoscalar_rx: _,
                nested_points_rx: _,
                nested_a_poly: _,
                nested_b_poly: _,
                nested_registry_xy_poly: _,
                nested_p_poly: _,
                nested_challenges_rx: _,
                nested_challenges_partial: _,
                nested_export_rx: _,
                nested_collapse_rx: _,
                nested_compute_v_rx: _,
                nested_endoscaling_step_commitments: _,
                nested_endoscalar_commitment: _,
                nested_points_commitment: _,
                nested_a_commitment: _,
                nested_b_commitment: _,
                nested_registry_xy_commitment: _,
                nested_p_commitment: _,
                nested_challenges_commitment: _,
                nested_export_commitment: _,
                nested_collapse_commitment: _,
                nested_compute_v_commitment: _,
                w: _,
                y: _,
                z: _,
                mu: _,
                nu: _,
                mu_prime: _,
                nu_prime: _,
                x: _,
                alpha: _,
                u: _,
                pre_beta: _,
                native_application_commitment: _,
                native_preamble_commitment: _,
                native_inner_error_commitment: _,
                native_outer_error_commitment: _,
                native_a_commitment: _,
                native_b_commitment: _,
                native_query_commitment: _,
                native_registry_xy_commitment: _,
                native_eval_commitment: _,
                native_p_commitment: _,
                native_hashes_1_commitment: _,
                native_hashes_2_commitment: _,
                native_inner_collapse_commitment: _,
                native_outer_collapse_commitment: _,
                native_compute_v_commitment: _,
                native_bind_challenges_commitments: _,
                native_bind_beta_commitment: _,
                native_bind_endoscalar_commitment: _,
                native_endoscaling_step_commitments: _,
                native_points_binding_commitment: _,
                native_points_children_commitment: _,
                native_points_registry_wx_commitment: _,
                native_points_ab_commitment: _,
                native_points_f_commitment: _,
                native_points_walk_commitment: _,
                bridge_preamble_commitment: _,
                bridge_s_prime_commitment: _,
                bridge_inner_error_commitment: _,
                bridge_f_commitment: _,
                bridge_outer_error_commitment: _,
                bridge_ab_commitment: _,
                bridge_query_commitment: _,
                bridge_eval_commitment: _,
            } = self;

            if self.bridge_alpha != other.bridge_alpha {
                return Some("bridge alpha");
            }
            if self.circuit_id != other.circuit_id {
                return Some("circuit id");
            }
            if self.left_header != other.left_header || self.right_header != other.right_header {
                return Some("headers");
            }

            if native::RxIndex::ALL
                .into_iter()
                .any(|index| !polynomial_eq(&self[index], &other[index]))
            {
                return Some("native rx polynomials");
            }
            if !polynomial_eq(&self.native_a_poly, &other.native_a_poly)
                || !polynomial_eq(&self.native_b_poly, &other.native_b_poly)
            {
                return Some("native ab polynomials");
            }
            if !polynomial_eq(
                &self.native_registry_xy_poly,
                &other.native_registry_xy_poly,
            ) || !polynomial_eq(&self.native_p_poly, &other.native_p_poly)
            {
                return Some("native protocol polynomials");
            }
            if nested::RxIndex::ALL
                .into_iter()
                .any(|index| !polynomial_eq(&self[index], &other[index]))
            {
                return Some("nested polynomials");
            }
            if !polynomial_eq(&self.nested_a_poly, &other.nested_a_poly)
                || !polynomial_eq(&self.nested_b_poly, &other.nested_b_poly)
            {
                return Some("nested ab polynomials");
            }
            if !polynomial_eq(
                &self.nested_registry_xy_poly,
                &other.nested_registry_xy_poly,
            ) || !polynomial_eq(&self.nested_p_poly, &other.nested_p_poly)
            {
                return Some("nested protocol polynomials");
            }

            if [
                self.w,
                self.y,
                self.z,
                self.mu,
                self.nu,
                self.mu_prime,
                self.nu_prime,
                self.x,
                self.alpha,
                self.u,
                self.pre_beta,
            ] != [
                other.w,
                other.y,
                other.z,
                other.mu,
                other.nu,
                other.mu_prime,
                other.nu_prime,
                other.x,
                other.alpha,
                other.u,
                other.pre_beta,
            ] {
                return Some("challenges");
            }

            if native::RxIndex::ALL
                .into_iter()
                .any(|index| self.native_rx_commitment(index) != other.native_rx_commitment(index))
            {
                return Some("native rx commitments");
            }
            if self.native_commitment(native::RxComponent::AbA)
                != other.native_commitment(native::RxComponent::AbA)
                || self.native_commitment(native::RxComponent::AbB)
                    != other.native_commitment(native::RxComponent::AbB)
            {
                return Some("native ab commitments");
            }
            if self.native_registry_xy_commitment() != other.native_registry_xy_commitment()
                || self.native_p_commitment() != other.native_p_commitment()
            {
                return Some("native protocol commitments");
            }

            if self.nested_endoscaling_step_commitments != other.nested_endoscaling_step_commitments
                || self.nested_endoscalar_commitment != other.nested_endoscalar_commitment
                || self.nested_points_commitment != other.nested_points_commitment
            {
                return Some("nested commitments");
            }
            if self.nested_a_commitment != other.nested_a_commitment
                || self.nested_b_commitment != other.nested_b_commitment
            {
                return Some("nested ab commitments");
            }
            if self.nested_registry_xy_commitment != other.nested_registry_xy_commitment
                || self.nested_p_commitment != other.nested_p_commitment
                || self.nested_challenges_commitment != other.nested_challenges_commitment
                || self.nested_challenges_partial != other.nested_challenges_partial
                || self.nested_export_commitment != other.nested_export_commitment
                || self.nested_collapse_commitment != other.nested_collapse_commitment
                || self.nested_compute_v_commitment != other.nested_compute_v_commitment
            {
                return Some("nested protocol commitments");
            }
            if [
                self.bridge_preamble_commitment(),
                self.bridge_s_prime_commitment(),
                self.bridge_inner_error_commitment(),
                self.bridge_outer_error_commitment(),
                self.bridge_ab_commitment(),
                self.bridge_query_commitment(),
                self.bridge_f_commitment(),
                self.bridge_eval_commitment(),
            ] != [
                other.bridge_preamble_commitment(),
                other.bridge_s_prime_commitment(),
                other.bridge_inner_error_commitment(),
                other.bridge_outer_error_commitment(),
                other.bridge_ab_commitment(),
                other.bridge_query_commitment(),
                other.bridge_f_commitment(),
                other.bridge_eval_commitment(),
            ] {
                return Some("bridge commitments");
            }

            None
        }
    }
}
