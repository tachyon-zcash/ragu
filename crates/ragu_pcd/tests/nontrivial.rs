use std::sync::atomic::{AtomicUsize, Ordering};

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::nontrivial::{Hash2, WitnessLeaf};
use rand::{SeedableRng, rngs::StdRng};

static MSM_CALLS: AtomicUsize = AtomicUsize::new(0);

struct TrackingBackend;

impl Backend for TrackingBackend {
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
fn various_merging_operations() -> Result<()> {
    MSM_CALLS.store(0, Ordering::SeqCst);

    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .with_backend::<TrackingBackend>()
        .register(WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .finalize(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);

    let (leaf1, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    assert!(
        MSM_CALLS.load(Ordering::SeqCst) > 0,
        "selected backend MSM was not called"
    );
    assert!(app.verify(&leaf1, &mut rng)?);

    let (leaf2, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    assert!(app.verify(&leaf2, &mut rng)?);

    let (node1, _) = app.fuse(
        &mut rng,
        Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        leaf1,
        leaf2,
    )?;
    assert!(app.verify(&node1, &mut rng)?);

    Ok(())
}
