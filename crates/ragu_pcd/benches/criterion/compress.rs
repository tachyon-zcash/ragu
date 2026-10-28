//! Compression and compressed verification at the production rank, with one
//! or all available workers.
//! Compares reference and accelerated MSM and independent-work scheduling.
//!
//! Run with `cargo bench -p ragu_pcd --features multicore --bench criterion_compress`.
//! Construction, RNG initialization, verification and destruction are outside
//! the reported compression duration. Every timed proof is verified.
//! Compressed verification is timed separately using an existing proof.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use criterion::Criterion;
use ragu_acceleration::AcceleratedBackend;
use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{ApplicationBuilder, SelectableBackend};
use ragu_testing::pcd::nontrivial;
use rand::{SeedableRng, rngs::StdRng};

fn bench_compression<B: SelectableBackend>(
    c: &mut Criterion,
    backend: &str,
    mode: &str,
    workers: usize,
) {
    let pasta = ragu_pcd::pasta::baked_aggregator();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .with_backend::<B>()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .register(nontrivial::Merge2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0x899);
    let leaves = [1, 2, 3, 4].map(|value| {
        app.seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(value),
        )
        .unwrap()
        .0
    });
    let [l1, l2, l3, l4] = leaves;
    let (p1, _) = app
        .fuse(&mut rng, nontrivial::Hash2 { poseidon_params }, (), l1, l2)
        .unwrap();
    let (p2, _) = app
        .fuse(&mut rng, nontrivial::Hash2 { poseidon_params }, (), l3, l4)
        .unwrap();
    let (root, _) = app
        .fuse(&mut rng, nontrivial::Merge2 { poseidon_params }, (), p1, p2)
        .unwrap();
    assert!(app.verify_uncompressed(&root, &mut rng).unwrap());

    c.bench_function(
        &format!("compress/{mode}/{workers}-workers/{backend}"),
        |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    // Identical work even when Criterion chooses different
                    // iteration counts during warmup on the two revisions.
                    let mut rng = StdRng::seed_from_u64(5678);
                    let start = Instant::now();
                    let compressed = app.compress(black_box(&root), &mut rng).unwrap();
                    elapsed += start.elapsed();
                    assert_eq!(compressed.data(), root.data());
                    assert!(app.verify_compressed(black_box(&compressed)).unwrap());
                    black_box(compressed);
                }
                elapsed
            });
        },
    );

    let compressed = app.compress(&root, &mut StdRng::seed_from_u64(0)).unwrap();
    c.bench_function(
        &format!("verify_compressed/{mode}/{workers}-workers/{backend}"),
        |b| {
            b.iter(|| {
                assert!(app.verify_compressed(black_box(&compressed)).unwrap());
            });
        },
    );
}

fn main() {
    let available = std::thread::available_parallelism().unwrap().get();
    for (mode, workers) in [("serial", 1), ("parallel", available)] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        pool.install(|| {
            let mut c = Criterion::default().sample_size(10).configure_from_args();
            bench_compression::<ReferenceBackend>(&mut c, "reference", mode, workers);
            bench_compression::<AcceleratedBackend>(&mut c, "accelerated", mode, workers);
            c.final_summary();
        });
    }
}
