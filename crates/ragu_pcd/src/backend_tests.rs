use proptest::{prelude::*, test_runner::TestCaseResult};
use ragu_acceleration::AcceleratedBackend;
use ragu_circuits::{polynomials::ProductionRank, registry::CircuitIndex};
use ragu_pasta::{Fp, Pasta};
use ragu_testing::strategies::{bounded_edge_usize, edge_u64, nonzero_prime_field_element};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    Application, ApplicationBuilder, Pcd, Proof, SelectableBackend, fuzz_utils::Corruption,
    step::internal::trivial::Trivial,
};

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

fn rng_fingerprint(rng: &mut StdRng) -> RngFingerprint {
    core::array::from_fn(|_| rng.random())
}

fn verifier_outcome<B: SelectableBackend>(
    app: &TestApplication<'_, B>,
    pcd: &TestPcd,
    seed: u64,
) -> (VerifierDecision, RngFingerprint) {
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
) -> impl IntoIterator<Item = (&'static str, Corruption<Fp>)> {
    [
        ("p blind", Corruption::PBlind(inputs.p_blind_delta)),
        ("p evaluation", Corruption::PEval(inputs.p_eval_delta)),
        ("ab revdot", Corruption::AbC(inputs.ab_c_delta)),
        ("circuit id", Corruption::CircuitId(inputs.circuit_id)),
        (
            "challenge u",
            Corruption::ChallengeU(proof.u() + inputs.challenge_u_delta),
        ),
        (
            "challenge x",
            Corruption::ChallengeX(proof.x() + inputs.challenge_x_delta),
        ),
        (
            "challenge y",
            Corruption::ChallengeY(proof.y() + inputs.challenge_y_delta),
        ),
        (
            "left header",
            Corruption::LeftHeaderLen(inputs.left_header_len),
        ),
        (
            "right header",
            Corruption::RightHeaderLen(inputs.right_header_len),
        ),
    ]
}

fn check_valid_pcd_equivalence<Reference, Accelerated>(
    reference_app: &TestApplication<'_, Reference>,
    accelerated_app: &TestApplication<'_, Accelerated>,
    reference_pcd: &TestPcd,
    accelerated_pcd: &TestPcd,
    verifier_seed: u64,
    proof_kind: &str,
) -> TestCaseResult
where
    Reference: SelectableBackend,
    Accelerated: SelectableBackend,
{
    let reference_digest = reference_pcd.proof().test_digest();
    prop_assert_eq!(reference_digest, accelerated_pcd.proof().test_digest());

    for (proof_name, pcd) in [
        ("reference", reference_pcd),
        ("accelerated", accelerated_pcd),
    ] {
        let reference_outcome = verifier_outcome(reference_app, pcd, verifier_seed);
        let accelerated_outcome = verifier_outcome(accelerated_app, pcd, verifier_seed);
        prop_assert_eq!(
            reference_outcome,
            accelerated_outcome,
            "verifier result or RNG consumption mismatch for {} {} proof",
            proof_name,
            proof_kind,
        );
        prop_assert_eq!(
            reference_outcome.0,
            VerifierDecision::Accept,
            "valid {} {} proof was rejected",
            proof_name,
            proof_kind,
        );
    }

    Ok(())
}

fn check_corrupted_pcd_equivalence<Reference, Accelerated>(
    reference_app: &TestApplication<'_, Reference>,
    accelerated_app: &TestApplication<'_, Accelerated>,
    pcd: &TestPcd,
    verifier_seed: u64,
    proof_kind: &str,
    corruption_inputs: CorruptionInputs,
) -> TestCaseResult
where
    Reference: SelectableBackend,
    Accelerated: SelectableBackend,
{
    let reference_digest = pcd.proof().test_digest();
    for (corruption_name, corruption) in corruptions(pcd.proof(), corruption_inputs) {
        let mut corrupted = pcd.proof().clone();
        corrupted.corrupt(corruption);
        prop_assert_ne!(
            reference_digest,
            corrupted.test_digest(),
            "proof digest ignored {} corruption in {} proof",
            corruption_name,
            proof_kind,
        );
        let corrupted_pcd = corrupted.carry::<()>(());
        let reference_outcome = verifier_outcome(reference_app, &corrupted_pcd, verifier_seed);
        let accelerated_outcome = verifier_outcome(accelerated_app, &corrupted_pcd, verifier_seed);
        prop_assert_eq!(
            reference_outcome,
            accelerated_outcome,
            "verifier result or RNG consumption mismatch after {} corruption in {} proof",
            corruption_name,
            proof_kind,
        );
        prop_assert_ne!(
            reference_outcome.0,
            VerifierDecision::Accept,
            "verifier accepted {} corruption in {} proof",
            corruption_name,
            proof_kind,
        );
    }

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2))]

    #[test]
    fn reference_and_accelerated_verifiers_reject_padded_circuit_ids(
        proof_seed in edge_u64(),
        verifier_seed in edge_u64(),
        dummy_circuits in arb_dummy_circuit_count(),
        padded_slot_selector in any::<usize>(),
    ) {
        let pasta = Pasta::baked();
        let reference_app = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .register_dummy_circuits(dummy_circuits)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let accelerated_app = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .with_backend::<AcceleratedBackend>()
            .register_dummy_circuits(dummy_circuits)
            .unwrap()
            .finalize(pasta)
            .unwrap();

        prop_assert_eq!(
            reference_app.native_registry.digest(),
            accelerated_app.native_registry.digest(),
        );

        let num_circuits = reference_app.native_registry.num_circuits();
        prop_assume!(!num_circuits.is_power_of_two());
        let domain_size = num_circuits.next_power_of_two();
        let padded_index =
            num_circuits + padded_slot_selector % (domain_size - num_circuits);
        let padded = CircuitIndex::new(padded_index);
        prop_assert!(reference_app.native_registry.circuit_in_domain(padded));
        prop_assert!(accelerated_app.native_registry.circuit_in_domain(padded));

        let mut proof_rng = StdRng::seed_from_u64(proof_seed);
        let (valid_pcd, _) = reference_app
            .seed(&mut proof_rng, Trivial::new(), ())
            .unwrap();
        let valid_reference = verifier_outcome(&reference_app, &valid_pcd, verifier_seed);
        let valid_accelerated = verifier_outcome(&accelerated_app, &valid_pcd, verifier_seed);
        prop_assert_eq!(valid_reference, valid_accelerated);
        prop_assert_eq!(valid_reference.0, VerifierDecision::Accept);

        let valid_digest = valid_pcd.proof().test_digest();
        let mut corrupted = valid_pcd.into_parts().0;
        corrupted.corrupt(Corruption::CircuitId(
            usize::from(padded).try_into().unwrap(),
        ));
        prop_assert_ne!(valid_digest, corrupted.test_digest());
        let corrupted_pcd = corrupted.carry::<()>(());

        let reference_outcome = verifier_outcome(&reference_app, &corrupted_pcd, verifier_seed);
        let accelerated_outcome = verifier_outcome(&accelerated_app, &corrupted_pcd, verifier_seed);
        prop_assert_eq!(reference_outcome, accelerated_outcome);
        prop_assert_eq!(reference_outcome.0, VerifierDecision::Reject);
    }
}

// TODO: Add this end-to-end backend-equivalence property for a generated
// nontrivial Step; Trivial exercises the protocol flow but not application circuitry.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(2))]

    #[test]
    fn reference_and_accelerated_proofs_and_verifiers_are_equivalent(
        proof_seed in edge_u64(),
        verifier_seed in edge_u64(),
        dummy_circuits in arb_dummy_circuit_count(),
        corruption_inputs in arb_corruption_inputs(),
    ) {
        let pasta = Pasta::baked();
        let reference_app = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .register_dummy_circuits(dummy_circuits)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let accelerated_app = ApplicationBuilder::<Pasta, ProductionRank, TEST_HEADER_SIZE>::new()
            .with_backend::<AcceleratedBackend>()
            .register_dummy_circuits(dummy_circuits)
            .unwrap()
            .finalize(pasta)
            .unwrap();

        prop_assert_eq!(
            reference_app.native_registry.digest(),
            accelerated_app.native_registry.digest(),
        );
        prop_assert_eq!(
            reference_app.nested_registry.digest(),
            accelerated_app.nested_registry.digest(),
        );

        let corrupted_circuit = CircuitIndex::from_u32(corruption_inputs.circuit_id);
        prop_assume!(!reference_app
            .native_registry
            .circuit_in_domain(corrupted_circuit));
        prop_assert!(!accelerated_app
            .native_registry
            .circuit_in_domain(corrupted_circuit));

        let mut reference_rng = StdRng::seed_from_u64(proof_seed);
        let mut accelerated_rng = StdRng::seed_from_u64(proof_seed);
        let (reference_leaf1, _) = reference_app
            .seed(&mut reference_rng, Trivial::new(), ())
            .unwrap();
        let (accelerated_leaf1, _) = accelerated_app
            .seed(&mut accelerated_rng, Trivial::new(), ())
            .unwrap();
        let reference_rng_state = rng_fingerprint(&mut reference_rng);
        prop_assert_eq!(reference_rng_state, rng_fingerprint(&mut accelerated_rng));
        check_valid_pcd_equivalence(
            &reference_app,
            &accelerated_app,
            &reference_leaf1,
            &accelerated_leaf1,
            verifier_seed,
            "leaf",
        )?;

        let (reference_leaf2, _) = reference_app
            .seed(&mut reference_rng, Trivial::new(), ())
            .unwrap();
        let (accelerated_leaf2, _) = accelerated_app
            .seed(&mut accelerated_rng, Trivial::new(), ())
            .unwrap();
        let reference_rng_state = rng_fingerprint(&mut reference_rng);
        prop_assert_eq!(reference_rng_state, rng_fingerprint(&mut accelerated_rng));

        let (reference_node, _) = reference_app
            .fuse(
                &mut reference_rng,
                Trivial::new(),
                (),
                reference_leaf1,
                reference_leaf2,
            )
            .unwrap();
        let (accelerated_node, _) = accelerated_app
            .fuse(
                &mut accelerated_rng,
                Trivial::new(),
                (),
                accelerated_leaf1,
                accelerated_leaf2,
            )
            .unwrap();
        let reference_rng_state = rng_fingerprint(&mut reference_rng);
        prop_assert_eq!(reference_rng_state, rng_fingerprint(&mut accelerated_rng));
        check_valid_pcd_equivalence(
            &reference_app,
            &accelerated_app,
            &reference_node,
            &accelerated_node,
            verifier_seed,
            "fused",
        )?;
        check_corrupted_pcd_equivalence(
            &reference_app,
            &accelerated_app,
            &reference_node,
            verifier_seed,
            "fused",
            corruption_inputs,
        )?;
    }
}
