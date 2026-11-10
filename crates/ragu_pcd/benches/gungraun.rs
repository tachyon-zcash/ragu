#![allow(clippy::type_complexity)]

mod setup;

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_acceleration::AcceleratedBackend;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use ragu_testing::pcd::nontrivial;
use rand::rngs::StdRng;
use setup::{
    setup_finalize, setup_fuse, setup_fuse_accelerated, setup_register, setup_seed,
    setup_verify_compressed_leaf, setup_verify_compressed_node, setup_verify_leaf,
    setup_verify_node,
};

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
        Pcd<Pasta, ragu_pcd::Uncompressed<ProductionRank>, nontrivial::LeafNode>,
        Pcd<Pasta, ragu_pcd::Uncompressed<ProductionRank>, nontrivial::LeafNode>,
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

// The accelerated counterpart to `fuse`. Comparing the two tracked baselines
// is how a regression in an overridden backend operation surfaces.
#[library_benchmark(setup = setup_fuse_accelerated)]
#[bench::fuse_accelerated()]
fn fuse_accelerated(
    (app, leaf1, leaf2, poseidon_params, mut rng): (
        Application<'static, Pasta, ProductionRank, 4, AcceleratedBackend>,
        Pcd<Pasta, ragu_pcd::Uncompressed<ProductionRank>, nontrivial::LeafNode>,
        Pcd<Pasta, ragu_pcd::Uncompressed<ProductionRank>, nontrivial::LeafNode>,
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
    name = app_proof_accelerated;
    benchmarks = fuse_accelerated
);

// `verify_leaf` and `verify_node` measure the uncompressed test oracle;
// the production path is `compress_node`, `verify_compressed_leaf` and
// `verify_compressed_node` below.
#[library_benchmark(setup = setup_verify_leaf)]
#[bench::verify_leaf()]
fn verify_leaf(
    (app, leaf, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        Pcd<Pasta, ragu_pcd::Uncompressed<ProductionRank>, nontrivial::LeafNode>,
        StdRng,
    ),
) {
    black_box(app.verify_uncompressed(&leaf, &mut rng)).unwrap();
}

#[library_benchmark(setup = setup_verify_node)]
#[bench::verify_node()]
fn verify_node(
    (app, node, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        Pcd<Pasta, ragu_pcd::Uncompressed<ProductionRank>, nontrivial::InternalNode>,
        StdRng,
    ),
) {
    black_box(app.verify_uncompressed(&node, &mut rng)).unwrap();
}

#[library_benchmark(setup = setup_verify_node)]
#[bench::rerandomize()]
fn rerandomize(
    (app, node, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        Pcd<Pasta, ragu_pcd::Uncompressed<ProductionRank>, nontrivial::InternalNode>,
        StdRng,
    ),
) {
    black_box(app.rerandomize(node, &mut rng)).unwrap();
}

library_benchmark_group!(
    name = app_verify;
    benchmarks = verify_leaf, verify_node, rerandomize
);

// The production verification path: compress a proof, then verify the
// compressed proof. Compression is set up outside the two verification
// measurements so each tracks its own cost.
#[library_benchmark(setup = setup_verify_node)]
#[bench::compress_node()]
fn compress_node(
    (app, node, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        Pcd<Pasta, ragu_pcd::Uncompressed<ProductionRank>, nontrivial::InternalNode>,
        StdRng,
    ),
) {
    black_box(app.compress(&node, &mut rng)).unwrap();
}

#[library_benchmark(setup = setup_verify_compressed_leaf)]
#[bench::verify_compressed_leaf()]
fn verify_compressed_leaf(
    (app, compressed): (
        Application<'static, Pasta, ProductionRank, 4>,
        ragu_pcd::Pcd<Pasta, ragu_pcd::Compressed, nontrivial::LeafNode>,
    ),
) {
    black_box(app.verify_compressed(&compressed)).unwrap();
}

#[library_benchmark(setup = setup_verify_compressed_node)]
#[bench::verify_compressed_node()]
fn verify_compressed_node(
    (app, compressed): (
        Application<'static, Pasta, ProductionRank, 4>,
        ragu_pcd::Pcd<Pasta, ragu_pcd::Compressed, nontrivial::InternalNode>,
    ),
) {
    black_box(app.verify_compressed(&compressed)).unwrap();
}

library_benchmark_group!(
    name = app_verify_compressed;
    benchmarks = compress_node, verify_compressed_leaf, verify_compressed_node
);

main!(
    library_benchmark_groups = app_setup,
    app_proof,
    app_proof_accelerated,
    app_verify,
    app_verify_compressed
);
