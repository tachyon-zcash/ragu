//! Setup functions for the GGM gungraun benches.
//!
//! Each `setup_ggm_*` function returns a tuple ready to feed into a
//! `#[library_benchmark]` in [`benches/ggm.rs`]. All PCD precomputation
//! (building the `Application`, seeding a `MasterHeader`, advancing to
//! the depth a given bench needs) happens here so the measured region
//! inside each library benchmark is exactly one `app.seed` / `app.fuse`
//! (or one full tree walk for the `walk` bench).

#![allow(clippy::type_complexity)]

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use ragu_testing::pcd::ggm::{
    DelegationHeader, GgmFirstStep, GgmLeaf, GgmSeed, GgmStep, MasterHeader,
};
use rand::{SeedableRng, rngs::StdRng};

/// Tight to the widest GGM header: DelegationHeader carries 4 field
/// elements, and the slot at HEADER_SIZE-1 is reserved for the suffix
/// tag.
pub const HEADER_SIZE: usize = 5;
/// GGM tree depth used throughout the GGM benches.
pub const DEPTH: u8 = 6;

/// The concrete `Application` type used by all GGM benches.
pub type App = Application<'static, Pasta, ProductionRank, HEADER_SIZE>;

/// Note-field tuple fed into `GgmSeed`, matching `GgmSeed::Witness`:
/// `(nk, pk, value, psi, rcm, trap)`.
pub type NoteFields = (Fp, Fp, Fp, Fp, Fp, Fp);

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

fn sample_note_fields(rng: &mut StdRng) -> NoteFields {
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

pub fn setup_seed() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
    NoteFields,
) {
    let (app, poseidon) = build_app();
    let mut rng = StdRng::seed_from_u64(1234);
    let note_fields = sample_note_fields(&mut rng);
    (app, poseidon, rng, note_fields)
}

pub fn setup_step() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
    Pcd<Pasta, ProductionRank, DelegationHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (app, poseidon) = build_app();
    let mut rng = StdRng::seed_from_u64(1234);
    let master = seed_master(&app, poseidon, &mut rng);
    let depth_1 = first_step(&app, poseidon, &mut rng, master);
    let trivial = app.seeded_trivial_pcd(&mut rng);
    (app, poseidon, rng, depth_1, trivial)
}

pub fn setup_walk() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
    Pcd<Pasta, ProductionRank, MasterHeader>,
) {
    let (app, poseidon) = build_app();
    let mut rng = StdRng::seed_from_u64(1234);
    let master = seed_master(&app, poseidon, &mut rng);
    (app, poseidon, rng, master)
}

pub fn setup_leaf() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
    Pcd<Pasta, ProductionRank, DelegationHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (app, poseidon) = build_app();
    let mut rng = StdRng::seed_from_u64(1234);
    let master = seed_master(&app, poseidon, &mut rng);
    let depth_1 = first_step(&app, poseidon, &mut rng, master);
    let depth_last = advance_levels(&app, poseidon, &mut rng, depth_1, DEPTH - 1);
    let trivial = app.seeded_trivial_pcd(&mut rng);
    (app, poseidon, rng, depth_last, trivial)
}

/// Measured region of the `walk` bench: `first_step` + `DEPTH - 1`
/// inner steps.
pub fn walk_measured(
    app: &App,
    poseidon: &<Pasta as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    master: Pcd<Pasta, ProductionRank, MasterHeader>,
) -> Pcd<Pasta, ProductionRank, DelegationHeader> {
    let depth_1 = first_step(app, poseidon, rng, master);
    advance_levels(app, poseidon, rng, depth_1, DEPTH - 1)
}
