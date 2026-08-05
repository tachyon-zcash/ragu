use criterion::{Criterion, criterion_group, criterion_main};
use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::nontrivial;
use rand::{SeedableRng, rngs::StdRng};

fn registry_bench(c: &mut Criterion) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);

    // Time finalize separately: build the ApplicationBuilder, then bench only finalize.
    let make_builder = || {
        ApplicationBuilder::<Pasta, ProductionRank, 4>::new(pasta)
            .register(nontrivial::WitnessLeaf { poseidon_params })
            .unwrap()
            .register(nontrivial::Hash2 { poseidon_params })
            .unwrap()
    };

    c.bench_function("registry::finalize", |b| {
        b.iter_batched(
            make_builder,
            |builder| builder.finalize().unwrap(),
            criterion::BatchSize::PerIteration,
        );
    });

    // Build the finalized app once for evaluation benchmarks.
    let app = make_builder().finalize().unwrap();
    let registry = app.native_registry();

    // Use deterministic "random" field elements.
    let mut rng = StdRng::seed_from_u64(0xdead);
    let w = Fp::random(&mut rng);
    let x = Fp::random(&mut rng);
    let y = Fp::random(&mut rng);

    c.bench_function("registry::wx", |b| {
        b.iter(|| registry.wx(w, x));
    });

    c.bench_function("registry::wy", |b| {
        b.iter(|| registry.wy(w, y));
    });

    c.bench_function("registry::wxy", |b| {
        b.iter(|| registry.wxy(w, x, y));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = registry_bench
}
criterion_main!(benches);
