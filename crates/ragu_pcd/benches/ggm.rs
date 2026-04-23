//! Gungraun (instrumented) benchmarks for the GGM fixtures.
//!
//! Each `#[library_benchmark]` measures one `app.seed` or `app.fuse`
//! call (or one full tree walk for `walk`). All PCD precomputation is
//! done in the corresponding `setup_*` function in [`ggm_setup`].
//!
//! Targets, grouped as `ggm`:
//! * `seed` — one `GgmSeed` seed call.
//! * `step` — one `GgmStep<DEPTH>` fuse.
//! * `walk` — full tree descent from a seeded `MasterHeader` to a
//!   depth-`DEPTH` `DelegationHeader`: one `GgmFirstStep` plus
//!   `DEPTH - 1` `GgmStep` fuses. Excludes the leaf step.
//! * `leaf` — one `GgmLeaf<DEPTH>` fuse.

#![allow(clippy::type_complexity)]

mod ggm_setup;

use std::hint::black_box;

use ggm_setup::{
    App, DEPTH, NoteFields, setup_leaf, setup_seed, setup_step, setup_walk, walk_measured,
};
use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::Pasta;
use ragu_pcd::Pcd;
use ragu_testing::pcd::ggm::{DelegationHeader, GgmLeaf, GgmSeed, GgmStep, MasterHeader};
use rand::rngs::StdRng;

#[library_benchmark(setup = setup_seed)]
#[bench::seed()]
fn seed(
    (app, poseidon, mut rng, note_fields): (
        App,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
        NoteFields,
    ),
) {
    black_box(app.seed(
        &mut rng,
        GgmSeed::<Pasta> {
            poseidon_params: poseidon,
        },
        note_fields,
    ))
    .unwrap();
}

#[library_benchmark(setup = setup_step)]
#[bench::step()]
fn step(
    (app, poseidon, mut rng, pcd, trivial): (
        App,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<Pasta, ProductionRank, DelegationHeader>,
        Pcd<Pasta, ProductionRank, ()>,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        GgmStep::<Pasta, DEPTH> {
            poseidon_params: poseidon,
        },
        false,
        pcd,
        trivial,
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
        Pcd<Pasta, ProductionRank, MasterHeader>,
    ),
) {
    black_box(walk_measured(&app, poseidon, &mut rng, master));
}

#[library_benchmark(setup = setup_leaf)]
#[bench::leaf()]
fn leaf(
    (app, _poseidon, mut rng, pcd, trivial): (
        App,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
        Pcd<Pasta, ProductionRank, DelegationHeader>,
        Pcd<Pasta, ProductionRank, ()>,
    ),
) {
    black_box(app.fuse(&mut rng, GgmLeaf::<DEPTH>, (), pcd, trivial)).unwrap();
}

library_benchmark_group!(
    name = ggm;
    benchmarks = seed, step, walk, leaf
);

main!(library_benchmark_groups = ggm);
