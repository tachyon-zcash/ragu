//! Criterion (wall-clock) benchmarks for the GGM fixtures.
//!
//! Self-contained in the style of [`fuse.rs`](./fuse.rs): all helpers and
//! PCD precomputation live in this file, done once per target outside
//! the measured region. The `mod setup;` / `benches/setup/mod.rs`
//! convention is reserved for the gungraun benches in
//! [`benches/ggm.rs`](../ggm.rs), which use the same setup logic via a
//! parallel set of helpers there.
//!
//! Targets:
//! * `ggm_seed` — one `GgmSeed` seed call.
//! * `ggm_step` — one `GgmStep<DEPTH>` fuse.
//! * `ggm_walk` — full tree descent from a seeded `MasterHeader` to a
//!   depth-`DEPTH` `DelegationHeader`: one `GgmFirstStep` plus
//!   `DEPTH - 1` `GgmSteps`. Excludes the leaf step.
//! * `ggm_leaf` — one `GgmLeaf<DEPTH>` fuse.

use criterion::{Criterion, criterion_group, criterion_main};
use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use ragu_testing::pcd::ggm::{
    DelegationHeader, GgmFirstStep, GgmLeaf, GgmSeed, GgmStep, MasterHeader,
};
use rand::{SeedableRng, rngs::StdRng};

const HEADER_SIZE: usize = 5;
const DEPTH: u8 = 6;

type App = Application<'static, Pasta, ProductionRank, HEADER_SIZE>;

fn build_app() -> (App, &'static <Pasta as Cycle>::CircuitPoseidon) {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);

    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(GgmSeed::<Pasta> {
            poseidon_params: poseidon,
        })
        .unwrap()
        .register(GgmFirstStep::<Pasta> {
            poseidon_params: poseidon,
        })
        .unwrap()
        .register(GgmStep::<Pasta, DEPTH> {
            poseidon_params: poseidon,
        })
        .unwrap()
        .register(GgmLeaf::<DEPTH>)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    (app, poseidon)
}

fn sample_note_fields(rng: &mut StdRng) -> (Fp, Fp, Fp, Fp, Fp, Fp) {
    (
        Fp::random(&mut *rng),
        Fp::random(&mut *rng),
        Fp::from(100_000_000u64),
        Fp::random(&mut *rng),
        Fp::random(&mut *rng),
        Fp::random(&mut *rng),
    )
}

fn seed_master(
    app: &App,
    poseidon: &<Pasta as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
) -> Pcd<Pasta, ProductionRank, MasterHeader> {
    let note_fields = sample_note_fields(rng);
    app.seed(
        rng,
        GgmSeed::<Pasta> {
            poseidon_params: poseidon,
        },
        note_fields,
    )
    .unwrap()
    .0
}

fn first_step(
    app: &App,
    poseidon: &<Pasta as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    master: Pcd<Pasta, ProductionRank, MasterHeader>,
) -> Pcd<Pasta, ProductionRank, DelegationHeader> {
    let trivial = app.seeded_trivial_pcd(rng);
    app.fuse(
        rng,
        GgmFirstStep::<Pasta> {
            poseidon_params: poseidon,
        },
        false,
        master,
        trivial,
    )
    .unwrap()
    .0
}

fn advance_levels(
    app: &App,
    poseidon: &<Pasta as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    mut pcd: Pcd<Pasta, ProductionRank, DelegationHeader>,
    levels: u8,
) -> Pcd<Pasta, ProductionRank, DelegationHeader> {
    for _ in 0..levels {
        let trivial = app.seeded_trivial_pcd(rng);
        let (next, _) = app
            .fuse(
                rng,
                GgmStep::<Pasta, DEPTH> {
                    poseidon_params: poseidon,
                },
                false,
                pcd,
                trivial,
            )
            .unwrap();
        pcd = next;
    }
    pcd
}

fn ggm_seed(c: &mut Criterion) {
    c.bench_function("ggm_seed", |b| {
        b.iter_batched(
            || {
                let (app, poseidon_params) = build_app();
                let mut rng = StdRng::seed_from_u64(1234);
                let note_fields = sample_note_fields(&mut rng);
                (app, poseidon_params, rng, note_fields)
            },
            |(app, poseidon_params, mut rng, note_fields)| {
                app.seed(
                    &mut rng,
                    GgmSeed::<Pasta> { poseidon_params },
                    note_fields,
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
            || {
                let (app, poseidon_params) = build_app();
                let mut rng = StdRng::seed_from_u64(1234);
                let master = seed_master(&app, poseidon_params, &mut rng);
                let depth_1 = first_step(&app, poseidon_params, &mut rng, master);
                let trivial = app.seeded_trivial_pcd(&mut rng);
                (app, depth_1, trivial, rng, poseidon_params)
            },
            |(app, pcd, trivial, mut rng, poseidon_params)| {
                app.fuse(
                    &mut rng,
                    GgmStep::<Pasta, DEPTH> { poseidon_params },
                    false,
                    pcd,
                    trivial,
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
                let (app, poseidon_params) = build_app();
                let mut rng = StdRng::seed_from_u64(1234);
                let master = seed_master(&app, poseidon_params, &mut rng);
                (app, poseidon_params, rng, master)
            },
            |(app, poseidon_params, mut rng, master)| {
                let depth_1 = first_step(&app, poseidon_params, &mut rng, master);
                advance_levels(&app, poseidon_params, &mut rng, depth_1, DEPTH - 1)
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn ggm_leaf(c: &mut Criterion) {
    c.bench_function("ggm_leaf", |b| {
        b.iter_batched(
            || {
                let (app, poseidon_params) = build_app();
                let mut rng = StdRng::seed_from_u64(1234);
                let master = seed_master(&app, poseidon_params, &mut rng);
                let depth_1 = first_step(&app, poseidon_params, &mut rng, master);
                let depth_last =
                    advance_levels(&app, poseidon_params, &mut rng, depth_1, DEPTH - 1);
                let trivial = app.seeded_trivial_pcd(&mut rng);
                (app, rng, depth_last, trivial)
            },
            |(app, mut rng, pcd, trivial)| {
                app.fuse(&mut rng, GgmLeaf::<DEPTH>, (), pcd, trivial)
                    .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = ggm_seed, ggm_step, ggm_walk, ggm_leaf
}
criterion_main!(benches);
