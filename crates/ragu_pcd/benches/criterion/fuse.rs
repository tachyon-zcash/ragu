//! Complete Fuse at the production rank, with one or all available workers.
//!
//! Run with `cargo bench -p ragu_pcd --features multicore --bench criterion_fuse`.
//! Child construction, cloning, RNG initialization, verification and destruction
//! are outside the reported duration. Every timed proof is verified. Each
//! iteration uses the same seed so rejection sampling does not change the work
//! between backends or revisions.

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

fn fuse_bench<B: SelectableBackend>(c: &mut Criterion, backend: &str, mode: &str, workers: usize) {
    let pasta = ragu_pcd::pasta::baked();
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
    let mut rng = StdRng::seed_from_u64(1234);
    let [l1, l2, l3, l4] = [1, 2, 3, 4].map(|value| {
        app.seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(value),
        )
        .unwrap()
        .0
    });
    let (left, _) = app
        .fuse(&mut rng, nontrivial::Hash2 { poseidon_params }, (), l1, l2)
        .unwrap();
    let (right, _) = app
        .fuse(&mut rng, nontrivial::Hash2 { poseidon_params }, (), l3, l4)
        .unwrap();

    c.bench_function(&format!("fuse/{mode}/{workers}-workers/{backend}"), |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let (left, right) = (left.clone(), right.clone());
                let mut rng = StdRng::seed_from_u64(5678);
                let start = Instant::now();
                let (proof, ()) = app
                    .fuse(
                        &mut rng,
                        nontrivial::Merge2 { poseidon_params },
                        (),
                        black_box(left),
                        black_box(right),
                    )
                    .unwrap();
                elapsed += start.elapsed();
                assert!(
                    app.verify(black_box(&proof), StdRng::seed_from_u64(0xfeed))
                        .unwrap()
                );
                black_box(proof);
            }
            elapsed
        });
    });
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
            fuse_bench::<ReferenceBackend>(&mut c, "reference", mode, workers);
            fuse_bench::<AcceleratedBackend>(&mut c, "accelerated", mode, workers);
            c.final_summary();
        });
    }
}
