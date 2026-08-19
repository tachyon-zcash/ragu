use proptest::prelude::*;
use proptest::test_runner::TestCaseResult;
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::ff::Field;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_testing::strategies::edge_u64;
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

type TestApplication<'params, B> = Application<'params, Pasta, ProductionRank, 4, B>;
type TestPcd = Pcd<Pasta, ProductionRank, ()>;

fn rng_fingerprint(rng: &mut StdRng) -> [u64; 4] {
    core::array::from_fn(|_| rng.random())
}

fn verifier_outcome<B: SelectableBackend>(
    app: &TestApplication<'_, B>,
    pcd: &TestPcd,
    seed: u64,
) -> (VerifierDecision, [u64; 4]) {
    let mut rng = StdRng::seed_from_u64(seed);
    let decision = match app.verify(pcd, &mut rng) {
        Ok(true) => VerifierDecision::Accept,
        Ok(false) => VerifierDecision::Reject,
        Err(_) => VerifierDecision::Error,
    };
    (decision, rng_fingerprint(&mut rng))
}

fn corruptions(proof: &Proof<Pasta, ProductionRank>) -> [(&'static str, Corruption<Fp>); 9] {
    [
        ("p blind", Corruption::PBlind(Fp::ONE)),
        ("p evaluation", Corruption::PEval(Fp::ONE)),
        ("ab revdot", Corruption::AbC(Fp::ONE)),
        ("circuit id", Corruption::CircuitId(u32::MAX)),
        ("challenge u", Corruption::ChallengeU(proof.u() + Fp::ONE)),
        ("challenge x", Corruption::ChallengeX(proof.x() + Fp::ONE)),
        ("challenge y", Corruption::ChallengeY(proof.y() + Fp::ONE)),
        ("left header", Corruption::LeftHeaderLen(5)),
        ("right header", Corruption::RightHeaderLen(3)),
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
) -> TestCaseResult
where
    Reference: SelectableBackend,
    Accelerated: SelectableBackend,
{
    let reference_digest = pcd.proof().test_digest();
    for (corruption_name, corruption) in corruptions(pcd.proof()) {
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
    fn reference_and_accelerated_proofs_and_verifiers_are_equivalent(
        proof_seed in edge_u64(),
        verifier_seed in edge_u64(),
        dummy_circuits in 0usize..=3,
    ) {
        let pasta = Pasta::baked();
        let reference_app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
            .register_dummy_circuits(dummy_circuits)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let accelerated_app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
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
        )?;
    }
}
