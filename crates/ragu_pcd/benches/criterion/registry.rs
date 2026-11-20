use criterion::{Criterion, criterion_group, criterion_main};
use ragu_circuits::polynomials::WalletRank;
use ragu_core::{
    Cycle,
    pasta::{Fp, Pasta},
};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::nontrivial;
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::field::Field;

fn registry_bench(c: &mut Criterion) {
    let pasta = ragu_pcd::pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);

    // Time finalize separately: build the ApplicationBuilder, then bench only finalize.
    let make_builder = || {
        ApplicationBuilder::<Pasta, WalletRank, 4>::new()
            .register(nontrivial::WitnessLeaf { poseidon_params })
            .unwrap()
            .register(nontrivial::Hash2 { poseidon_params })
            .unwrap()
    };

    // `finalize` also builds the bootstrap proof (one internal fuse), which
    // dominates its cost; keep the sample count low so this stays runnable.
    let mut finalize_group = c.benchmark_group("registry");
    finalize_group.sample_size(10);
    finalize_group.bench_function("finalize", |b| {
        b.iter_batched(
            make_builder,
            |builder| builder.finalize(pasta).unwrap(),
            criterion::BatchSize::PerIteration,
        );
    });
    finalize_group.finish();

    // Build the finalized app once for evaluation benchmarks.
    let app = make_builder().finalize(pasta).unwrap();
    let registry = app.native_registry();

    // Use deterministic "random" field elements.
    let mut rng = StdRng::seed_from_u64(0xdead);
    let w = Fp::random(|bytes| rng.fill_bytes(bytes));
    let x = Fp::random(|bytes| rng.fill_bytes(bytes));
    let y = Fp::random(|bytes| rng.fill_bytes(bytes));

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
