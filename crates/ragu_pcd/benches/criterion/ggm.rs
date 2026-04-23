use criterion::{Criterion, criterion_group, criterion_main};
use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use ragu_testing::pcd::ggm::{
    GGM_CHUNK_SIZE, GGM_DEPTH, GgmBlindStep, GgmDelegateHeader, GgmDelegateStep, GgmMasterHeader,
    GgmMasterSeed, GgmMasterStep, GgmNodeStep, GgmNullifierStep, GgmPrivateHeader, HEADER_SIZE,
};
use rand::{SeedableRng, rngs::StdRng};

type App = Application<'static, Pasta, ProductionRank, HEADER_SIZE>;

type NoteFields = (Fp, Fp, Fp, Fp, Fp);

fn build_app<const CHUNK_SIZE: u8, const DEPTH: u8>()
-> (App, &'static <Pasta as Cycle>::CircuitPoseidon) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);

    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(GgmMasterSeed::<Pasta> { poseidon_params })
        .unwrap()
        .register(GgmMasterStep::<Pasta, CHUNK_SIZE> { poseidon_params })
        .unwrap()
        .register(GgmNodeStep::<Pasta, CHUNK_SIZE, DEPTH> { poseidon_params })
        .unwrap()
        .register(GgmBlindStep::<Pasta> { poseidon_params })
        .unwrap()
        .register(GgmDelegateStep::<Pasta, CHUNK_SIZE, DEPTH> { poseidon_params })
        .unwrap()
        .register(GgmNullifierStep::<Pasta, DEPTH> { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();

    (app, poseidon_params)
}

fn sample_note_fields(rng: &mut StdRng) -> NoteFields {
    (
        Fp::random(&mut *rng),
        Fp::random(&mut *rng),
        Fp::from(100_000_000u64),
        Fp::random(&mut *rng),
        Fp::random(&mut *rng),
    )
}

fn seed_master(
    app: &App,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
) -> Pcd<Pasta, ProductionRank, GgmMasterHeader> {
    let note_fields = sample_note_fields(rng);
    app.seed(rng, GgmMasterSeed::<Pasta> { poseidon_params }, note_fields)
        .unwrap()
        .0
}

fn master_step<const CHUNK_SIZE: u8>(
    app: &App,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    master: Pcd<Pasta, ProductionRank, GgmMasterHeader>,
) -> Pcd<Pasta, ProductionRank, GgmPrivateHeader> {
    let trivial_pcd = app.seeded_trivial_pcd(rng);
    app.fuse(
        rng,
        GgmMasterStep::<Pasta, CHUNK_SIZE> { poseidon_params },
        0u8,
        master,
        trivial_pcd,
    )
    .unwrap()
    .0
}

fn node_step<const CHUNK_SIZE: u8, const DEPTH: u8>(
    app: &App,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    node_pcd: Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
) -> Pcd<Pasta, ProductionRank, GgmPrivateHeader> {
    let trivial_pcd = app.seeded_trivial_pcd(rng);
    app.fuse(
        rng,
        GgmNodeStep::<Pasta, CHUNK_SIZE, DEPTH> { poseidon_params },
        0u8,
        node_pcd,
        trivial_pcd,
    )
    .unwrap()
    .0
}

fn blind_step(
    app: &App,
    poseidon_params: &<Pasta as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    node_pcd: Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
    trap: Fp,
) -> Pcd<Pasta, ProductionRank, GgmDelegateHeader> {
    let trivial_pcd = app.seeded_trivial_pcd(rng);
    app.fuse(
        rng,
        GgmBlindStep::<Pasta> { poseidon_params },
        trap,
        node_pcd,
        trivial_pcd,
    )
    .unwrap()
    .0
}

fn descend_pre_blind<const CHUNK_SIZE: u8, const DEPTH: u8>(
    app: &App,
    poseidon: &<Pasta as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    master: Pcd<Pasta, ProductionRank, GgmMasterHeader>,
) -> Pcd<Pasta, ProductionRank, GgmPrivateHeader> {
    let mut node_pcd = master_step::<CHUNK_SIZE>(app, poseidon, rng, master);
    for _ in 1..DEPTH {
        node_pcd = node_step::<CHUNK_SIZE, DEPTH>(app, poseidon, rng, node_pcd);
    }
    node_pcd
}

fn ggm_seed(c: &mut Criterion) {
    c.bench_function("ggm_seed", |b| {
        b.iter_batched(
            || {
                let (app, poseidon_params) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
                let mut rng = StdRng::seed_from_u64(1234);
                let note_fields = sample_note_fields(&mut rng);
                (app, poseidon_params, rng, note_fields)
            },
            |(app, poseidon_params, mut rng, note_fields)| {
                app.seed(
                    &mut rng,
                    GgmMasterSeed::<Pasta> { poseidon_params },
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
                let (app, poseidon_params) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
                let mut rng = StdRng::seed_from_u64(1234);
                let master = seed_master(&app, poseidon_params, &mut rng);
                let depth_1 =
                    master_step::<GGM_CHUNK_SIZE>(&app, poseidon_params, &mut rng, master);
                let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
                (app, poseidon_params, rng, depth_1, trivial_pcd)
            },
            |(app, poseidon_params, mut rng, node_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmNodeStep::<Pasta, GGM_CHUNK_SIZE, GGM_DEPTH> { poseidon_params },
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
                let (app, poseidon_params) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
                let mut rng = StdRng::seed_from_u64(1234);
                let master = seed_master(&app, poseidon_params, &mut rng);
                (app, poseidon_params, rng, master)
            },
            |(app, poseidon_params, mut rng, master)| {
                let mut node_pcd =
                    master_step::<GGM_CHUNK_SIZE>(&app, poseidon_params, &mut rng, master);
                for _ in 1..GGM_DEPTH {
                    node_pcd = node_step::<GGM_CHUNK_SIZE, GGM_DEPTH>(
                        &app,
                        poseidon_params,
                        &mut rng,
                        node_pcd,
                    );
                }
                node_pcd
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

fn ggm_blind(c: &mut Criterion) {
    c.bench_function("ggm_blind", |b| {
        b.iter_batched(
            || {
                let (app, poseidon_params) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
                let mut rng = StdRng::seed_from_u64(1234);
                let master = seed_master(&app, poseidon_params, &mut rng);
                let node_pcd = descend_pre_blind::<GGM_CHUNK_SIZE, GGM_DEPTH>(
                    &app,
                    poseidon_params,
                    &mut rng,
                    master,
                );
                let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
                let trap = Fp::random(&mut rng);
                (app, poseidon_params, rng, node_pcd, trivial_pcd, trap)
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
                let (app, poseidon_params) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
                let mut rng = StdRng::seed_from_u64(1234);
                let master = seed_master(&app, poseidon_params, &mut rng);
                let node_pcd =
                    master_step::<GGM_CHUNK_SIZE>(&app, poseidon_params, &mut rng, master);
                let trap = Fp::random(&mut rng);
                let delegate_pcd = blind_step(&app, poseidon_params, &mut rng, node_pcd, trap);
                let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
                (app, poseidon_params, rng, delegate_pcd, trivial_pcd)
            },
            |(app, poseidon_params, mut rng, delegate_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmDelegateStep::<Pasta, GGM_CHUNK_SIZE, GGM_DEPTH> { poseidon_params },
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
                let (app, poseidon_params) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
                let mut rng = StdRng::seed_from_u64(1234);
                let master = seed_master(&app, poseidon_params, &mut rng);
                let node_pcd = descend_pre_blind::<GGM_CHUNK_SIZE, GGM_DEPTH>(
                    &app,
                    poseidon_params,
                    &mut rng,
                    master,
                );
                let trap = Fp::random(&mut rng);
                let delegate_pcd = blind_step(&app, poseidon_params, &mut rng, node_pcd, trap);
                let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
                (app, poseidon_params, rng, delegate_pcd, trivial_pcd)
            },
            |(app, poseidon_params, mut rng, delegate_pcd, trivial_pcd)| {
                app.fuse(
                    &mut rng,
                    GgmNullifierStep::<Pasta, GGM_DEPTH> { poseidon_params },
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
