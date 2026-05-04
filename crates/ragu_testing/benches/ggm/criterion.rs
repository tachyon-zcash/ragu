#[path = "../../fixtures/ggm.rs"]
mod fixtures;

use criterion::{Criterion, criterion_group, criterion_main};
use fixtures::{
    NK, note, setup_blind, setup_delegate, setup_final, setup_master_step, setup_node_step,
    setup_seed, trap,
};
use ragu_arithmetic::Cycle;
use ragu_pasta::Pasta;
use ragu_testing::apps::ggm::{
    ChunkWitness, GGM_CHUNK_SIZE, GgmBlindStep, GgmDelegateStep, GgmMasterSeed, GgmMasterStep,
    GgmNodeStep, GgmNullifierStep,
};

fn ggm_seed(c: &mut Criterion) {
    c.bench_function("ggm_seed", |b| {
        b.iter_batched(
            setup_seed,
            |(app, mut rng)| {
                app.seed(
                    &mut rng,
                    GgmMasterSeed::<Pasta> {
                        poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
                    },
                    (NK, note()),
                )
                .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn ggm_master_step(c: &mut Criterion) {
    c.bench_function("ggm_master_step", |b| {
        b.iter_batched(
            setup_master_step,
            |(app, mut rng, master_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmMasterStep::<Pasta> {
                        poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
                    },
                    ChunkWitness([false; GGM_CHUNK_SIZE as usize]),
                    master_pcd,
                    trivial_pcd,
                )
                .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn ggm_step(c: &mut Criterion) {
    c.bench_function("ggm_step", |b| {
        b.iter_batched(
            setup_node_step,
            |(app, mut rng, node_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmNodeStep::<Pasta> {
                        poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
                    },
                    ChunkWitness([false; GGM_CHUNK_SIZE as usize]),
                    node_pcd,
                    trivial_pcd,
                )
                .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn ggm_blind(c: &mut Criterion) {
    c.bench_function("ggm_blind", |b| {
        b.iter_batched(
            setup_blind,
            |(app, mut rng, node_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmBlindStep::<Pasta> {
                        poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
                    },
                    trap(),
                    node_pcd,
                    trivial_pcd,
                )
                .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn ggm_delegate(c: &mut Criterion) {
    c.bench_function("ggm_delegate", |b| {
        b.iter_batched(
            setup_delegate,
            |(app, mut rng, delegate_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmDelegateStep::<Pasta> {
                        poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
                    },
                    ChunkWitness([false; GGM_CHUNK_SIZE as usize]),
                    delegate_pcd,
                    trivial_pcd,
                )
                .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn ggm_nullifier(c: &mut Criterion) {
    c.bench_function("ggm_nullifier", |b| {
        b.iter_batched(
            setup_final,
            |(app, mut rng, delegate_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmNullifierStep::<Pasta> {
                        poseidon_params: Pasta::circuit_poseidon(Pasta::baked()),
                    },
                    (),
                    delegate_pcd,
                    trivial_pcd,
                )
                .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = ggm_seed, ggm_master_step, ggm_step, ggm_blind, ggm_delegate, ggm_nullifier
}
criterion_main!(benches);
