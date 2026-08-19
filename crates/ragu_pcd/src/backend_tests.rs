use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestCaseResult};
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{
    CurveAffine, DeferredField, FixedGenerators,
    ff::{Field, PrimeField},
};
use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{ProductionRank, Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryAt},
};
use ragu_pasta::{Fp, Pasta};
use ragu_testing::strategies::edge_u64;
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    Application, ApplicationBuilder, Pcd, Proof, SelectableBackend, fuzz_utils::Corruption,
    step::internal::trivial::Trivial,
};

pub(crate) struct CanonicalBackend;

impl Backend for CanonicalBackend {
    fn sparse_eval<F: Field, R: Rank>(poly: &sparse::Polynomial<F, R>, point: F) -> F {
        poly.eval(point)
    }

    fn sparse_revdot<F: DeferredField, R: Rank>(
        lhs: &sparse::Polynomial<F, R>,
        rhs: &sparse::Polynomial<F, R>,
    ) -> F {
        lhs.revdot(rhs)
    }

    fn sparse_commit<F: Field, C: CurveAffine<ScalarExt = F>, R: Rank, G: FixedGenerators<C>>(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C::Curve {
        poly.commit(generators)
    }

    fn sparse_commit_to_affine<
        F: Field,
        C: CurveAffine<ScalarExt = F>,
        R: Rank,
        G: FixedGenerators<C>,
    >(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C {
        poly.commit_to_affine(generators)
    }

    fn registry_xy<F: PrimeField, R: Rank>(
        registry: &Registry<'_, F, R>,
        x: F,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        registry.xy(x, y)
    }

    fn registry_circuit_y<F: PrimeField, R: Rank>(
        registry: &Registry<'_, F, R>,
        circuit: CircuitIndex,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        registry.circuit_y(circuit, y)
    }

    fn registry_at_x<F: PrimeField, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        x: F,
    ) -> sparse::Polynomial<F, R> {
        registry.x(x)
    }

    fn registry_at_y<F: PrimeField, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        registry.y(y)
    }

    fn registry_wxy<F: PrimeField, R: Rank>(registry: &Registry<'_, F, R>, w: F, x: F, y: F) -> F {
        registry.wxy(w, x, y)
    }

    fn msm<
        'a,
        C: CurveAffine,
        A: IntoIterator<Item = &'a C::Scalar>,
        Bases: IntoIterator<Item = &'a C>,
    >(
        coeffs: A,
        bases: Bases,
    ) -> C::Curve
    where
        Bases::IntoIter: Clone + Sync,
    {
        ragu_arithmetic::msm(coeffs, bases)
    }
}

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

fn check_valid_pcd_equivalence<Canonical, Reference, Accelerated>(
    canonical_app: &TestApplication<'_, Canonical>,
    reference_app: &TestApplication<'_, Reference>,
    accelerated_app: &TestApplication<'_, Accelerated>,
    canonical_pcd: &TestPcd,
    reference_pcd: &TestPcd,
    accelerated_pcd: &TestPcd,
    verifier_seed: u64,
    proof_kind: &str,
) -> core::result::Result<[u8; 32], TestCaseError>
where
    Canonical: SelectableBackend,
    Reference: SelectableBackend,
    Accelerated: SelectableBackend,
{
    let canonical_digest = canonical_pcd.proof().test_digest();
    prop_assert_eq!(canonical_digest, reference_pcd.proof().test_digest());
    prop_assert_eq!(canonical_digest, accelerated_pcd.proof().test_digest());

    for (proof_name, pcd) in [
        ("canonical", canonical_pcd),
        ("reference", reference_pcd),
        ("accelerated", accelerated_pcd),
    ] {
        let canonical_outcome = verifier_outcome(canonical_app, pcd, verifier_seed);
        let reference_outcome = verifier_outcome(reference_app, pcd, verifier_seed);
        let accelerated_outcome = verifier_outcome(accelerated_app, pcd, verifier_seed);
        prop_assert_eq!(
            canonical_outcome,
            reference_outcome,
            "verifier result or RNG consumption mismatch for {} {} proof",
            proof_name,
            proof_kind,
        );
        prop_assert_eq!(
            canonical_outcome,
            accelerated_outcome,
            "verifier result or RNG consumption mismatch for {} {} proof",
            proof_name,
            proof_kind,
        );
        prop_assert_eq!(
            canonical_outcome.0,
            VerifierDecision::Accept,
            "valid {} {} proof was rejected",
            proof_name,
            proof_kind,
        );
    }

    Ok(canonical_digest)
}

fn check_corrupted_pcd_equivalence<Canonical, Reference, Accelerated>(
    canonical_app: &TestApplication<'_, Canonical>,
    reference_app: &TestApplication<'_, Reference>,
    accelerated_app: &TestApplication<'_, Accelerated>,
    pcd: &TestPcd,
    verifier_seed: u64,
    proof_kind: &str,
) -> TestCaseResult
where
    Canonical: SelectableBackend,
    Reference: SelectableBackend,
    Accelerated: SelectableBackend,
{
    let canonical_digest = pcd.proof().test_digest();
    for (corruption_name, corruption) in corruptions(pcd.proof()) {
        let mut corrupted = pcd.proof().clone();
        corrupted.corrupt(corruption);
        prop_assert_ne!(
            canonical_digest,
            corrupted.test_digest(),
            "proof digest ignored {} corruption in {} proof",
            corruption_name,
            proof_kind,
        );
        let corrupted_pcd = corrupted.carry::<()>(());
        let canonical_outcome = verifier_outcome(canonical_app, &corrupted_pcd, verifier_seed);
        let reference_outcome = verifier_outcome(reference_app, &corrupted_pcd, verifier_seed);
        let accelerated_outcome = verifier_outcome(accelerated_app, &corrupted_pcd, verifier_seed);
        prop_assert_eq!(
            canonical_outcome,
            reference_outcome,
            "verifier result or RNG consumption mismatch after {} corruption in {} proof",
            corruption_name,
            proof_kind,
        );
        prop_assert_eq!(
            canonical_outcome,
            accelerated_outcome,
            "verifier result or RNG consumption mismatch after {} corruption in {} proof",
            corruption_name,
            proof_kind,
        );
        prop_assert_ne!(
            canonical_outcome.0,
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
    fn canonical_reference_and_accelerated_proofs_and_verifiers_are_equivalent(
        proof_seed in edge_u64(),
        verifier_seed in edge_u64(),
        dummy_circuits in 0usize..=3,
    ) {
        let pasta = Pasta::baked();
        let canonical_app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
            .with_backend::<CanonicalBackend>()
            .register_dummy_circuits(dummy_circuits)
            .unwrap()
            .finalize(pasta)
            .unwrap();
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
            canonical_app.native_registry.digest(),
            reference_app.native_registry.digest(),
        );
        prop_assert_eq!(
            canonical_app.native_registry.digest(),
            accelerated_app.native_registry.digest(),
        );
        prop_assert_eq!(
            canonical_app.nested_registry.digest(),
            reference_app.nested_registry.digest(),
        );
        prop_assert_eq!(
            canonical_app.nested_registry.digest(),
            accelerated_app.nested_registry.digest(),
        );

        let mut canonical_rng = StdRng::seed_from_u64(proof_seed);
        let mut reference_rng = StdRng::seed_from_u64(proof_seed);
        let mut accelerated_rng = StdRng::seed_from_u64(proof_seed);
        let (canonical_leaf1, _) = canonical_app
            .seed(&mut canonical_rng, Trivial::new(), ())
            .unwrap();
        let (reference_leaf1, _) = reference_app
            .seed(&mut reference_rng, Trivial::new(), ())
            .unwrap();
        let (accelerated_leaf1, _) = accelerated_app
            .seed(&mut accelerated_rng, Trivial::new(), ())
            .unwrap();
        let canonical_rng_state = rng_fingerprint(&mut canonical_rng);
        prop_assert_eq!(canonical_rng_state, rng_fingerprint(&mut reference_rng));
        prop_assert_eq!(canonical_rng_state, rng_fingerprint(&mut accelerated_rng));
        check_valid_pcd_equivalence(
            &canonical_app,
            &reference_app,
            &accelerated_app,
            &canonical_leaf1,
            &reference_leaf1,
            &accelerated_leaf1,
            verifier_seed,
            "leaf",
        )?;

        let (canonical_leaf2, _) = canonical_app
            .seed(&mut canonical_rng, Trivial::new(), ())
            .unwrap();
        let (reference_leaf2, _) = reference_app
            .seed(&mut reference_rng, Trivial::new(), ())
            .unwrap();
        let (accelerated_leaf2, _) = accelerated_app
            .seed(&mut accelerated_rng, Trivial::new(), ())
            .unwrap();
        let canonical_rng_state = rng_fingerprint(&mut canonical_rng);
        prop_assert_eq!(canonical_rng_state, rng_fingerprint(&mut reference_rng));
        prop_assert_eq!(canonical_rng_state, rng_fingerprint(&mut accelerated_rng));

        let (canonical_node, _) = canonical_app
            .fuse(
                &mut canonical_rng,
                Trivial::new(),
                (),
                canonical_leaf1,
                canonical_leaf2,
            )
            .unwrap();
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
        let canonical_rng_state = rng_fingerprint(&mut canonical_rng);
        prop_assert_eq!(canonical_rng_state, rng_fingerprint(&mut reference_rng));
        prop_assert_eq!(canonical_rng_state, rng_fingerprint(&mut accelerated_rng));
        check_valid_pcd_equivalence(
            &canonical_app,
            &reference_app,
            &accelerated_app,
            &canonical_node,
            &reference_node,
            &accelerated_node,
            verifier_seed,
            "fused",
        )?;
        check_corrupted_pcd_equivalence(
            &canonical_app,
            &reference_app,
            &accelerated_app,
            &canonical_node,
            verifier_seed,
            "fused",
        )?;
    }
}
