#![allow(clippy::type_complexity)]

mod ggm_setup;

use std::hint::black_box;

use ggm_setup::{
    App, GGM_CHUNK_SIZE, GGM_DEPTH, NoteFields, setup_blind, setup_delegate, setup_final,
    setup_node_step, setup_seed, setup_walk, walk_measured,
};
use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::Pcd;
use ragu_testing::pcd::ggm::{
    GgmBlindStep, GgmDelegateHeader, GgmDelegateStep, GgmMasterHeader, GgmMasterSeed, GgmNodeStep,
    GgmNullifierStep, GgmPrivateHeader,
};
use rand::rngs::StdRng;

#[library_benchmark(setup = setup_seed)]
#[bench::seed()]
fn seed(
    (app, poseidon_params, mut rng, note_fields): (
        App,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
        NoteFields,
    ),
) {
    black_box(app.seed(
        &mut rng,
        GgmMasterSeed::<Pasta> { poseidon_params },
        note_fields,
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_node_step)]
#[bench::step()]
fn step(
    (app, poseidon_params, mut rng, node_pcd, trivial_pcd): (
        App,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
        Pcd<Pasta, ProductionRank, ()>,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        GgmNodeStep::<Pasta, GGM_CHUNK_SIZE, GGM_DEPTH> { poseidon_params },
        0u8,
        node_pcd,
        trivial_pcd,
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_walk)]
#[bench::walk()]
fn walk(
    (app, poseidon, mut rng, master): (
        App,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<Pasta, ProductionRank, GgmMasterHeader>,
    ),
) {
    black_box(walk_measured::<GGM_CHUNK_SIZE, GGM_DEPTH>(
        &app, poseidon, &mut rng, master,
    ));
}

#[library_benchmark(setup = setup_blind)]
#[bench::blind()]
fn blind(
    (app, poseidon_params, mut rng, node_pcd, trivial_pcd, trap): (
        App,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
        Pcd<Pasta, ProductionRank, ()>,
        Fp,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        GgmBlindStep::<Pasta> { poseidon_params },
        trap,
        node_pcd,
        trivial_pcd,
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_delegate)]
#[bench::delegate()]
fn delegate(
    (app, poseidon_params, mut rng, delegate_pcd, trivial_pcd): (
        App,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
        Pcd<Pasta, ProductionRank, ()>,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        GgmDelegateStep::<Pasta, GGM_CHUNK_SIZE, GGM_DEPTH> { poseidon_params },
        0u8,
        delegate_pcd,
        trivial_pcd,
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_final)]
#[bench::nullifier()]
fn nullifier(
    (app, poseidon_params, mut rng, delegate_pcd, trivial_pcd): (
        App,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
        Pcd<Pasta, ProductionRank, ()>,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        GgmNullifierStep::<Pasta, GGM_DEPTH> { poseidon_params },
        (),
        delegate_pcd,
        trivial_pcd,
    ))
    .unwrap();
}

library_benchmark_group!(
    name = ggm;
    benchmarks = seed, step, walk, blind, delegate, nullifier
);

main!(library_benchmark_groups = ggm);
