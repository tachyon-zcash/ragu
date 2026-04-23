//! Setup functions for GGM benches.

#![allow(clippy::type_complexity)]

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
pub use ragu_testing::pcd::ggm::{GGM_CHUNK_SIZE, GGM_DEPTH, HEADER_SIZE};
use ragu_testing::pcd::ggm::{
    GgmBlindStep, GgmDelegateHeader, GgmDelegateStep, GgmMasterHeader, GgmMasterSeed,
    GgmMasterStep, GgmNodeStep, GgmNullifierStep, GgmPrivateHeader,
};
use rand::{SeedableRng, rngs::StdRng};

pub type App = Application<'static, Pasta, ProductionRank, HEADER_SIZE>;

/// (nk, pk, value, psi, rcm)
pub type NoteFields = (Fp, Fp, Fp, Fp, Fp);

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

pub fn walk_measured<const CHUNK_SIZE: u8, const DEPTH: u8>(
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

pub fn setup_seed() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
    NoteFields,
) {
    let (app, poseidon) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
    let mut rng = StdRng::seed_from_u64(1234);
    let note_fields = sample_note_fields(&mut rng);
    (app, poseidon, rng, note_fields)
}

pub fn setup_node_step() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
    Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (app, poseidon) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
    let mut rng = StdRng::seed_from_u64(1234);
    let master = seed_master(&app, poseidon, &mut rng);
    let depth_1 = master_step::<GGM_CHUNK_SIZE>(&app, poseidon, &mut rng, master);
    let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
    (app, poseidon, rng, depth_1, trivial_pcd)
}

pub fn setup_walk() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
    Pcd<Pasta, ProductionRank, GgmMasterHeader>,
) {
    let (app, poseidon) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
    let mut rng = StdRng::seed_from_u64(1234);
    let master = seed_master(&app, poseidon, &mut rng);
    (app, poseidon, rng, master)
}

pub fn setup_blind() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
    Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
    Fp,
) {
    let (app, poseidon) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
    let mut rng = StdRng::seed_from_u64(1234);
    let master = seed_master(&app, poseidon, &mut rng);
    let mut node_pcd = master_step::<GGM_CHUNK_SIZE>(&app, poseidon, &mut rng, master);
    for _ in 1..GGM_DEPTH {
        node_pcd = node_step::<GGM_CHUNK_SIZE, GGM_DEPTH>(&app, poseidon, &mut rng, node_pcd);
    }
    let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
    let trap = Fp::random(&mut rng);
    (app, poseidon, rng, node_pcd, trivial_pcd, trap)
}

pub fn setup_delegate() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
    Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (app, poseidon) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
    let mut rng = StdRng::seed_from_u64(1234);
    let master = seed_master(&app, poseidon, &mut rng);
    let node_pcd = master_step::<GGM_CHUNK_SIZE>(&app, poseidon, &mut rng, master);
    let trap = Fp::random(&mut rng);
    let delegate_pcd = blind_step(&app, poseidon, &mut rng, node_pcd, trap);
    let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
    (app, poseidon, rng, delegate_pcd, trivial_pcd)
}

pub fn setup_final() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
    Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (app, poseidon) = build_app::<GGM_CHUNK_SIZE, GGM_DEPTH>();
    let mut rng = StdRng::seed_from_u64(1234);
    let master = seed_master(&app, poseidon, &mut rng);
    let mut node_pcd = master_step::<GGM_CHUNK_SIZE>(&app, poseidon, &mut rng, master);
    for _ in 1..GGM_DEPTH {
        node_pcd = node_step::<GGM_CHUNK_SIZE, GGM_DEPTH>(&app, poseidon, &mut rng, node_pcd);
    }
    let trap = Fp::random(&mut rng);
    let delegate_pcd = blind_step(&app, poseidon, &mut rng, node_pcd, trap);
    let trivial_pcd = app.seeded_trivial_pcd(&mut rng);
    (app, poseidon, rng, delegate_pcd, trivial_pcd)
}
