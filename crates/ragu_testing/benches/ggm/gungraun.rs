#![allow(clippy::type_complexity)]

#[path = "../../fixtures/ggm.rs"]
mod fixtures;

use std::{hint::black_box, sync::MutexGuard};

use fixtures::{
    NK, note, setup_blind, setup_delegate, setup_final, setup_master_step, setup_node_step,
    setup_seed, trap,
};
use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::Pasta;
use ragu_pcd::Pcd;
use ragu_testing::apps::ggm::{
    ChunkWitness, GGM_CHUNK_SIZE, GgmBlindStep, GgmDelegateHeader, GgmDelegateStep,
    GgmMasterHeader, GgmMasterSeed, GgmMasterStep, GgmNodeStep, GgmNullifierStep, GgmPrivateHeader,
};
use rand::rngs::StdRng;

#[library_benchmark(setup = setup_seed)]
#[bench::seed()]
fn seed((app, mut rng): (MutexGuard<'static, fixtures::App<Pasta>>, StdRng)) {
    black_box(app.seed(
        &mut rng,
        GgmMasterSeed::<Pasta> {
            poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
        },
        (NK, note()),
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_master_step)]
#[bench::master_step()]
fn master_step(
    (app, mut rng, master_pcd, trivial_pcd): (
        MutexGuard<'static, fixtures::App<Pasta>>,
        StdRng,
        Pcd<Pasta, ProductionRank, GgmMasterHeader>,
        Pcd<Pasta, ProductionRank, ()>,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        GgmMasterStep::<Pasta> {
            poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
        },
        ChunkWitness([false; GGM_CHUNK_SIZE as usize]),
        master_pcd,
        trivial_pcd,
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_node_step)]
#[bench::step()]
fn step(
    (app, mut rng, node_pcd, trivial_pcd): (
        MutexGuard<'static, fixtures::App<Pasta>>,
        StdRng,
        Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
        Pcd<Pasta, ProductionRank, ()>,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        GgmNodeStep::<Pasta> {
            poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
        },
        ChunkWitness([false; GGM_CHUNK_SIZE as usize]),
        node_pcd,
        trivial_pcd,
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_blind)]
#[bench::blind()]
fn blind(
    (app, mut rng, node_pcd, trivial_pcd): (
        MutexGuard<'static, fixtures::App<Pasta>>,
        StdRng,
        Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
        Pcd<Pasta, ProductionRank, ()>,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        GgmBlindStep::<Pasta> {
            poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
        },
        trap(),
        node_pcd,
        trivial_pcd,
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_delegate)]
#[bench::delegate()]
fn delegate(
    (app, mut rng, delegate_pcd, trivial_pcd): (
        MutexGuard<'static, fixtures::App<Pasta>>,
        StdRng,
        Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
        Pcd<Pasta, ProductionRank, ()>,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        GgmDelegateStep::<Pasta> {
            poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
        },
        ChunkWitness([false; GGM_CHUNK_SIZE as usize]),
        delegate_pcd,
        trivial_pcd,
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_final)]
#[bench::nullifier()]
fn nullifier(
    (app, mut rng, delegate_pcd, trivial_pcd): (
        MutexGuard<'static, fixtures::App<Pasta>>,
        StdRng,
        Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
        Pcd<Pasta, ProductionRank, ()>,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        GgmNullifierStep::<Pasta> {
            poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
        },
        (),
        delegate_pcd,
        trivial_pcd,
    ))
    .unwrap();
}

library_benchmark_group!(
    name = ggm;
    benchmarks = seed, master_step, step, blind, delegate, nullifier
);

main!(library_benchmark_groups = ggm);
