#![allow(clippy::type_complexity)]

mod setup;

use gungraun::{
    Callgrind, FlamegraphConfig, LibraryBenchmarkConfig, library_benchmark,
    library_benchmark_group, main,
};

fn bench_config() -> LibraryBenchmarkConfig {
    let mut callgrind = Callgrind::default();
    if std::env::var("RAGU_FLAMEGRAPH").is_ok() {
        callgrind.flamegraph(FlamegraphConfig::default());
    }
    LibraryBenchmarkConfig::default().tool(callgrind).clone()
}
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use ragu_testing::pcd::nontrivial;
use rand::rngs::StdRng;
use setup::{
    setup_finalize, setup_fuse, setup_register, setup_seed, setup_verify_leaf, setup_verify_node,
};
use std::hint::black_box;

#[library_benchmark(setup = setup_register)]
#[bench::register()]
fn register(
    (leaf, hash): (
        nontrivial::WitnessLeaf<'static, Pasta>,
        nontrivial::Hash2<'static, Pasta>,
    ),
) {
    black_box(
        ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
            .register(leaf)
            .unwrap()
            .register(hash)
            .unwrap(),
    );
}

#[library_benchmark(setup = setup_finalize)]
#[bench::finalize()]
fn finalize(
    (app, pasta): (
        ApplicationBuilder<'static, Pasta, ProductionRank, 4>,
        &'static <Pasta as Cycle>::Params,
    ),
) {
    black_box(app.finalize(pasta)).unwrap();
}

library_benchmark_group!(
    name = app_setup;
    benchmarks = register, finalize
);

#[library_benchmark(setup = setup_seed)]
#[bench::seed()]
fn seed(
    (app, poseidon_params, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
    ),
) {
    black_box(app.seed(
        &mut rng,
        nontrivial::WitnessLeaf { poseidon_params },
        Fp::from(42u64),
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_fuse)]
#[bench::fuse()]
fn fuse(
    (app, leaf1, leaf2, poseidon_params, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        Pcd<'static, Pasta, ProductionRank, nontrivial::LeafNode>,
        Pcd<'static, Pasta, ProductionRank, nontrivial::LeafNode>,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        nontrivial::Hash2 { poseidon_params },
        (),
        leaf1,
        leaf2,
    ))
    .unwrap();
}

library_benchmark_group!(
    name = app_proof;
    benchmarks = seed, fuse
);

#[library_benchmark(setup = setup_verify_leaf)]
#[bench::verify_leaf()]
fn verify_leaf(
    (app, leaf, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        Pcd<'static, Pasta, ProductionRank, nontrivial::LeafNode>,
        StdRng,
    ),
) {
    black_box(app.verify(&leaf, &mut rng)).unwrap();
}

#[library_benchmark(setup = setup_verify_node)]
#[bench::verify_node()]
fn verify_node(
    (app, node, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        Pcd<'static, Pasta, ProductionRank, nontrivial::InternalNode>,
        StdRng,
    ),
) {
    black_box(app.verify(&node, &mut rng)).unwrap();
}

#[library_benchmark(setup = setup_verify_node)]
#[bench::rerandomize()]
fn rerandomize(
    (app, node, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        Pcd<'static, Pasta, ProductionRank, nontrivial::InternalNode>,
        StdRng,
    ),
) {
    black_box(app.rerandomize(node, &mut rng)).unwrap();
}

library_benchmark_group!(
    name = app_verify;
    benchmarks = verify_leaf, verify_node, rerandomize
);

main!(
    config = bench_config();
    library_benchmark_groups = app_setup, app_proof, app_verify
);
