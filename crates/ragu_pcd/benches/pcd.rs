#![allow(clippy::type_complexity)]

mod setup;

use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{Application, ApplicationBuilder, Pcd, StepHandle};
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
    let mut builder = ApplicationBuilder::<Pasta, ProductionRank, 4>::new();
    builder.register(leaf).unwrap();
    builder.register(hash).unwrap();
    black_box(builder);
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
    (app, leaf_handle, _hash_handle, poseidon_params, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        StepHandle<nontrivial::WitnessLeaf<'static, Pasta>>,
        StepHandle<nontrivial::Hash2<'static, Pasta>>,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
    ),
) {
    black_box(app.seed(
        &mut rng,
        &leaf_handle,
        nontrivial::WitnessLeaf { poseidon_params },
        Fp::from(42u64),
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_fuse)]
#[bench::fuse()]
fn fuse(
    (app, leaf1, leaf2, hash_handle, poseidon_params, mut rng): (
        Application<'static, Pasta, ProductionRank, 4>,
        Pcd<'static, Pasta, ProductionRank, nontrivial::LeafNode>,
        Pcd<'static, Pasta, ProductionRank, nontrivial::LeafNode>,
        StepHandle<nontrivial::Hash2<'static, Pasta>>,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        &hash_handle,
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

main!(library_benchmark_groups = app_setup, app_proof, app_verify);
