use criterion::{Criterion, criterion_group, criterion_main};
use ragu_arithmetic::Cycle;
use ragu_pasta::Pasta;
use ragu_testing::apps::ggm::{
    GgmBlindStep, GgmDelegateStep, GgmMasterSeed, GgmNodeStep, GgmNullifierStep,
    fixtures::{self, walk_measured},
};

fn ggm_seed(c: &mut Criterion) {
    c.bench_function("ggm_seed", |b| {
        b.iter_batched(
            || {
                let params = Pasta::baked();
                let poseidon = Pasta::circuit_poseidon(params);
                fixtures::setup_seed::<Pasta>(params, poseidon)
            },
            |(app, poseidon_params, mut rng, seed)| {
                app.seed(&mut rng, GgmMasterSeed::<Pasta> { poseidon_params }, seed)
                    .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn ggm_step(c: &mut Criterion) {
    c.bench_function("ggm_step", |b| {
        b.iter_batched(
            || {
                let params = Pasta::baked();
                let poseidon = Pasta::circuit_poseidon(params);
                fixtures::setup_node_step::<Pasta>(params, poseidon)
            },
            |(app, poseidon_params, mut rng, node_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmNodeStep::<Pasta> { poseidon_params },
                    0u8,
                    node_pcd,
                    trivial_pcd,
                )
                .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn ggm_walk(c: &mut Criterion) {
    c.bench_function("ggm_walk", |b| {
        b.iter_batched(
            || {
                let params = Pasta::baked();
                let poseidon = Pasta::circuit_poseidon(params);
                fixtures::setup_walk::<Pasta>(params, poseidon)
            },
            |(app, poseidon_params, mut rng, master)| {
                walk_measured(&app, poseidon_params, &mut rng, master)
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn ggm_blind(c: &mut Criterion) {
    c.bench_function("ggm_blind", |b| {
        b.iter_batched(
            || {
                let params = Pasta::baked();
                let poseidon = Pasta::circuit_poseidon(params);
                fixtures::setup_blind::<Pasta>(params, poseidon)
            },
            |(app, poseidon_params, mut rng, node_pcd, trivial_pcd, trap)| {
                app.fuse(
                    &mut rng,
                    GgmBlindStep::<Pasta> { poseidon_params },
                    trap,
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
            || {
                let params = Pasta::baked();
                let poseidon = Pasta::circuit_poseidon(params);
                fixtures::setup_delegate::<Pasta>(params, poseidon)
            },
            |(app, poseidon_params, mut rng, delegate_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmDelegateStep::<Pasta> { poseidon_params },
                    0u8,
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
            || {
                let params = Pasta::baked();
                let poseidon = Pasta::circuit_poseidon(params);
                fixtures::setup_final::<Pasta>(params, poseidon)
            },
            |(app, poseidon_params, mut rng, delegate_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmNullifierStep::<Pasta> { poseidon_params },
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
    targets = ggm_seed, ggm_step, ggm_walk, ggm_blind, ggm_delegate, ggm_nullifier
}
criterion_main!(benches);
