use std::sync::atomic::{AtomicUsize, Ordering};

use ragu_arithmetic::{
    CurveAffine, DeferredField, FixedGenerators, PoseidonPermutation,
    ff::{Field, PrimeField},
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{ProductionRank, Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryAt},
};
use ragu_core::Result;
use ragu_pasta::Pasta;
use rand::{SeedableRng, rngs::StdRng};

use crate::{ApplicationBuilder, step::internal::trivial::Trivial};

static MSM_CALLS: AtomicUsize = AtomicUsize::new(0);
static SPARSE_EVAL_CALLS: AtomicUsize = AtomicUsize::new(0);
static SPARSE_REVDOT_CALLS: AtomicUsize = AtomicUsize::new(0);
static SPARSE_COMMIT_CALLS: AtomicUsize = AtomicUsize::new(0);
static REGISTRY_XY_CALLS: AtomicUsize = AtomicUsize::new(0);
static REGISTRY_CIRCUIT_Y_CALLS: AtomicUsize = AtomicUsize::new(0);
static REGISTRY_AT_CALLS: AtomicUsize = AtomicUsize::new(0);
static REGISTRY_WXY_CALLS: AtomicUsize = AtomicUsize::new(0);
static POSEIDON_CALLS: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct TrackingBackend;

impl Backend for TrackingBackend {
    fn sparse_eval<F: Field, R: Rank>(poly: &sparse::Polynomial<F, R>, point: F) -> F {
        SPARSE_EVAL_CALLS.fetch_add(1, Ordering::SeqCst);
        ReferenceBackend::sparse_eval(poly, point)
    }

    fn sparse_revdot<F: DeferredField, R: Rank>(
        lhs: &sparse::Polynomial<F, R>,
        rhs: &sparse::Polynomial<F, R>,
    ) -> F {
        SPARSE_REVDOT_CALLS.fetch_add(1, Ordering::SeqCst);
        ReferenceBackend::sparse_revdot(lhs, rhs)
    }

    fn sparse_commit<F: Field, C: CurveAffine<ScalarExt = F>, R: Rank, G: FixedGenerators<C>>(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C::Curve {
        SPARSE_COMMIT_CALLS.fetch_add(1, Ordering::SeqCst);
        ReferenceBackend::sparse_commit(poly, generators)
    }

    fn registry_xy<F: PrimeField, R: Rank>(
        registry: &Registry<'_, F, R>,
        x: F,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        REGISTRY_XY_CALLS.fetch_add(1, Ordering::SeqCst);
        ReferenceBackend::registry_xy(registry, x, y)
    }

    fn registry_circuit_y<F: PrimeField, R: Rank>(
        registry: &Registry<'_, F, R>,
        circuit: CircuitIndex,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        REGISTRY_CIRCUIT_Y_CALLS.fetch_add(1, Ordering::SeqCst);
        ReferenceBackend::registry_circuit_y(registry, circuit, y)
    }

    fn registry_at_x<F: PrimeField, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        x: F,
    ) -> sparse::Polynomial<F, R> {
        REGISTRY_AT_CALLS.fetch_add(1, Ordering::SeqCst);
        ReferenceBackend::registry_at_x(registry, x)
    }

    fn registry_at_y<F: PrimeField, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        REGISTRY_AT_CALLS.fetch_add(1, Ordering::SeqCst);
        ReferenceBackend::registry_at_y(registry, y)
    }

    fn registry_wxy<F: PrimeField, R: Rank>(registry: &Registry<'_, F, R>, w: F, x: F, y: F) -> F {
        REGISTRY_WXY_CALLS.fetch_add(1, Ordering::SeqCst);
        ReferenceBackend::registry_wxy(registry, w, x, y)
    }

    fn poseidon_permute<F: Field, P: PoseidonPermutation<F>>(params: &P, state: &mut [F]) {
        POSEIDON_CALLS.fetch_add(1, Ordering::SeqCst);
        ReferenceBackend::poseidon_permute(params, state);
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
        ReferenceBackend::msm(coeffs, bases)
    }
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
    POSEIDON_CALLS.store(0, Ordering::SeqCst);

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
        (&POSEIDON_CALLS, "native Poseidon permutation"),
    ] {
        assert!(
            calls.load(Ordering::SeqCst) > 0,
            "selected backend {operation} was not called",
        );
    }

    Ok(())
}
