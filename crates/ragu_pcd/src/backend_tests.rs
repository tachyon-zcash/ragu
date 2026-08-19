use std::sync::atomic::{AtomicUsize, Ordering};

use proptest::prelude::*;
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
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_testing::strategies::edge_u64;
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    Application, ApplicationBuilder, Pcd, Proof, SelectableBackend, fuzz_utils::Corruption,
    step::internal::trivial::Trivial,
};

static MSM_CALLS: AtomicUsize = AtomicUsize::new(0);
static SPARSE_EVAL_CALLS: AtomicUsize = AtomicUsize::new(0);
static SPARSE_REVDOT_CALLS: AtomicUsize = AtomicUsize::new(0);
static SPARSE_COMMIT_CALLS: AtomicUsize = AtomicUsize::new(0);
static REGISTRY_XY_CALLS: AtomicUsize = AtomicUsize::new(0);
static REGISTRY_CIRCUIT_Y_CALLS: AtomicUsize = AtomicUsize::new(0);
static REGISTRY_AT_CALLS: AtomicUsize = AtomicUsize::new(0);
static REGISTRY_WXY_CALLS: AtomicUsize = AtomicUsize::new(0);

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

pub(crate) struct TrackingBackend;

impl Backend for TrackingBackend {
    fn sparse_eval<F: Field, R: Rank>(poly: &sparse::Polynomial<F, R>, point: F) -> F {
        SPARSE_EVAL_CALLS.fetch_add(1, Ordering::SeqCst);
        CanonicalBackend::sparse_eval(poly, point)
    }

    fn sparse_revdot<F: DeferredField, R: Rank>(
        lhs: &sparse::Polynomial<F, R>,
        rhs: &sparse::Polynomial<F, R>,
    ) -> F {
        SPARSE_REVDOT_CALLS.fetch_add(1, Ordering::SeqCst);
        CanonicalBackend::sparse_revdot(lhs, rhs)
    }

    fn sparse_commit<F: Field, C: CurveAffine<ScalarExt = F>, R: Rank, G: FixedGenerators<C>>(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C::Curve {
        SPARSE_COMMIT_CALLS.fetch_add(1, Ordering::SeqCst);
        CanonicalBackend::sparse_commit(poly, generators)
    }

    fn registry_xy<F: PrimeField, R: Rank>(
        registry: &Registry<'_, F, R>,
        x: F,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        REGISTRY_XY_CALLS.fetch_add(1, Ordering::SeqCst);
        CanonicalBackend::registry_xy(registry, x, y)
    }

    fn registry_circuit_y<F: PrimeField, R: Rank>(
        registry: &Registry<'_, F, R>,
        circuit: CircuitIndex,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        REGISTRY_CIRCUIT_Y_CALLS.fetch_add(1, Ordering::SeqCst);
        CanonicalBackend::registry_circuit_y(registry, circuit, y)
    }

    fn registry_at_x<F: PrimeField, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        x: F,
    ) -> sparse::Polynomial<F, R> {
        REGISTRY_AT_CALLS.fetch_add(1, Ordering::SeqCst);
        CanonicalBackend::registry_at_x(registry, x)
    }

    fn registry_at_y<F: PrimeField, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        REGISTRY_AT_CALLS.fetch_add(1, Ordering::SeqCst);
        CanonicalBackend::registry_at_y(registry, y)
    }

    fn registry_wxy<F: PrimeField, R: Rank>(registry: &Registry<'_, F, R>, w: F, x: F, y: F) -> F {
        REGISTRY_WXY_CALLS.fetch_add(1, Ordering::SeqCst);
        CanonicalBackend::registry_wxy(registry, w, x, y)
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
        MSM_CALLS.fetch_add(1, Ordering::SeqCst);
        CanonicalBackend::msm(coeffs, bases)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerifierDecision {
    Accept,
    Reject,
    Error,
}

fn verifier_outcome<B: SelectableBackend>(
    app: &Application<'_, Pasta, ProductionRank, 4, B>,
    pcd: &Pcd<Pasta, ProductionRank, ()>,
    seed: u64,
) -> (VerifierDecision, u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let decision = match app.verify(pcd, &mut rng) {
        Ok(true) => VerifierDecision::Accept,
        Ok(false) => VerifierDecision::Reject,
        Err(_) => VerifierDecision::Error,
    };
    (decision, rng.random())
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

#[test]
fn selected_backend_dispatches_across_proving_and_verification() -> Result<()> {
    MSM_CALLS.store(0, Ordering::SeqCst);
    SPARSE_EVAL_CALLS.store(0, Ordering::SeqCst);
    SPARSE_REVDOT_CALLS.store(0, Ordering::SeqCst);
    SPARSE_COMMIT_CALLS.store(0, Ordering::SeqCst);
    REGISTRY_XY_CALLS.store(0, Ordering::SeqCst);
    REGISTRY_CIRCUIT_Y_CALLS.store(0, Ordering::SeqCst);
    REGISTRY_AT_CALLS.store(0, Ordering::SeqCst);
    REGISTRY_WXY_CALLS.store(0, Ordering::SeqCst);

    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .with_backend::<TrackingBackend>()
        .register_dummy_circuits(2)?
        .finalize(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);

    let (leaf1, _) = app.seed(&mut rng, Trivial::new(), ())?;
    assert!(
        MSM_CALLS.load(Ordering::SeqCst) > 0,
        "selected backend MSM was not called"
    );
    assert!(app.verify(&leaf1, &mut rng)?);
    assert!(
        SPARSE_EVAL_CALLS.load(Ordering::SeqCst) > 0,
        "selected backend sparse evaluation was not called"
    );
    assert!(
        SPARSE_REVDOT_CALLS.load(Ordering::SeqCst) > 0,
        "selected backend sparse revdot was not called"
    );

    let (leaf2, _) = app.seed(&mut rng, Trivial::new(), ())?;
    assert!(app.verify(&leaf2, &mut rng)?);

    let (node1, _) = app.fuse(&mut rng, Trivial::new(), (), leaf1, leaf2)?;
    assert!(app.verify(&node1, &mut rng)?);

    for (calls, operation) in [
        (&SPARSE_COMMIT_CALLS, "sparse commitment"),
        (&REGISTRY_XY_CALLS, "registry xy restriction"),
        (&REGISTRY_CIRCUIT_Y_CALLS, "registry circuit restriction"),
        (&REGISTRY_AT_CALLS, "cached registry restriction"),
        (&REGISTRY_WXY_CALLS, "registry evaluation"),
    ] {
        assert!(
            calls.load(Ordering::SeqCst) > 0,
            "selected backend {operation} was not called",
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
        let (canonical_pcd, _) = canonical_app
            .seed(&mut canonical_rng, Trivial::new(), ())
            .unwrap();
        let (reference_pcd, _) = reference_app
            .seed(&mut reference_rng, Trivial::new(), ())
            .unwrap();
        let (accelerated_pcd, _) = accelerated_app
            .seed(&mut accelerated_rng, Trivial::new(), ())
            .unwrap();
        let canonical_next_rng = canonical_rng.random::<u64>();
        prop_assert_eq!(canonical_next_rng, reference_rng.random::<u64>());
        prop_assert_eq!(canonical_next_rng, accelerated_rng.random::<u64>());

        let canonical_digest = canonical_pcd.proof().test_digest();
        let reference_digest = reference_pcd.proof().test_digest();
        prop_assert_eq!(canonical_digest, reference_digest);
        prop_assert_eq!(reference_digest, accelerated_pcd.proof().test_digest());

        for (proof_name, pcd) in [
            ("canonical", &canonical_pcd),
            ("reference", &reference_pcd),
            ("accelerated", &accelerated_pcd),
        ] {
            let canonical_outcome = verifier_outcome(&canonical_app, pcd, verifier_seed);
            let reference_outcome = verifier_outcome(&reference_app, pcd, verifier_seed);
            let accelerated_outcome = verifier_outcome(&accelerated_app, pcd, verifier_seed);
            prop_assert_eq!(
                canonical_outcome,
                reference_outcome,
                "verifier result or RNG consumption mismatch for {} proof",
                proof_name,
            );
            prop_assert_eq!(
                canonical_outcome,
                accelerated_outcome,
                "verifier result or RNG consumption mismatch for {} proof",
                proof_name,
            );
            prop_assert_eq!(
                canonical_outcome.0,
                VerifierDecision::Accept,
                "valid {} proof was rejected",
                proof_name,
            );
        }

        for (corruption_name, corruption) in corruptions(canonical_pcd.proof()) {
            let mut corrupted = canonical_pcd.proof().clone();
            corrupted.corrupt(corruption);
            prop_assert_ne!(
                canonical_digest,
                corrupted.test_digest(),
                "proof digest ignored {} corruption",
                corruption_name,
            );
            let corrupted_pcd = corrupted.carry::<()>(());
            let canonical_outcome =
                verifier_outcome(&canonical_app, &corrupted_pcd, verifier_seed);
            let reference_outcome =
                verifier_outcome(&reference_app, &corrupted_pcd, verifier_seed);
            let accelerated_outcome =
                verifier_outcome(&accelerated_app, &corrupted_pcd, verifier_seed);
            prop_assert_eq!(
                canonical_outcome,
                reference_outcome,
                "verifier result or RNG consumption mismatch after {} corruption",
                corruption_name,
            );
            prop_assert_eq!(
                canonical_outcome,
                accelerated_outcome,
                "verifier result or RNG consumption mismatch after {} corruption",
                corruption_name,
            );
            prop_assert_ne!(
                canonical_outcome.0,
                VerifierDecision::Accept,
                "verifier accepted {} corruption",
                corruption_name,
            );
        }
    }
}
