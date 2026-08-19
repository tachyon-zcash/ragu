use criterion::{Criterion, criterion_group, criterion_main};
#[cfg(feature = "native-msm")]
use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::nontrivial;
use rand::{SeedableRng, rngs::StdRng};

fn fuse_bench(c: &mut Criterion) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);

    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();
    #[cfg(feature = "native-msm")]
    let accelerated_app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .with_backend::<AcceleratedBackend>()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(1234);

    let (leaf1, _) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();

    let (leaf2, _) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(2u64),
        )
        .unwrap();

    c.bench_function("fuse", |b| {
        b.iter_batched(
            || (leaf1.clone(), leaf2.clone(), StdRng::seed_from_u64(5678)),
            |(l1, l2, mut rng)| {
                app.fuse(&mut rng, nontrivial::Hash2 { poseidon_params }, (), l1, l2)
                    .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });

    #[cfg(feature = "native-msm")]
    c.bench_function("fuse_accelerated_native_msm", |b| {
        b.iter_batched(
            || (leaf1.clone(), leaf2.clone(), StdRng::seed_from_u64(5678)),
            |(l1, l2, mut rng)| {
                accelerated_app
                    .fuse(&mut rng, nontrivial::Hash2 { poseidon_params }, (), l1, l2)
                    .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = fuse_bench
}
criterion_main!(benches);
