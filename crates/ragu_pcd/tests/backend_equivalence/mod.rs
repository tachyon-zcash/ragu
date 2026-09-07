use core::sync::atomic::{AtomicUsize, Ordering};

use proptest::{prelude::*, test_runner::TestCaseResult};
use ragu_acceleration::{AcceleratedBackend, AcceleratedProver};
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
use ragu_pasta::{Fp, Pasta};
use ragu_primitives::allocator::Standard;
use ragu_testing::strategies::{bounded_edge_usize, edge_u64, nonzero_prime_field_element};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    Application, ApplicationBuilder, Pcd, Proof, SelectableBackend,
    step::{Encoded, Index, Step},
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
type TestPcd = Pcd<Pasta, ProductionRank, ()>;
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

    fn check_registries(&self) -> TestCaseResult {
        let native = self.reference.native_registry.digest();
        let nested = self.reference.nested_registry.digest();
        prop_assert_eq!(native, self.accelerated.native_registry.digest());
        prop_assert_eq!(nested, self.accelerated.nested_registry.digest());
        prop_assert_eq!(native, self.prover.native_registry.digest());
        prop_assert_eq!(nested, self.prover.nested_registry.digest());
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
        prop_assert_ne!(
            verifier_outcome(&apps.reference, &corrupted_pcd, verifier_seed).0,
            VerifierDecision::Accept,
            "verifier accepted {}",
            context,
        );
    }

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
