//! Setup functions for GGM benches.

#![allow(clippy::type_complexity)]

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::Pcd;
pub use ragu_testing::pcd::ggm::{GgmSeed, fixtures::walk_measured};

pub type App = ragu_testing::pcd::ggm::fixtures::App<Pasta>;

fn params() -> (
    &'static <Pasta as Cycle>::Params,
    &'static <Pasta as Cycle>::CircuitPoseidon,
) {
    let params = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(params);
    (params, poseidon)
}

pub fn setup_seed() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    rand::rngs::StdRng,
    GgmSeed<Fp>,
) {
    let (params, poseidon) = params();
    ragu_testing::pcd::ggm::fixtures::setup_seed::<Pasta>(params, poseidon)
}

pub fn setup_node_step() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    rand::rngs::StdRng,
    Pcd<Pasta, ProductionRank, ragu_testing::pcd::ggm::GgmPrivateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (params, poseidon) = params();
    ragu_testing::pcd::ggm::fixtures::setup_node_step::<Pasta>(params, poseidon)
}

pub fn setup_walk() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    rand::rngs::StdRng,
    Pcd<Pasta, ProductionRank, ragu_testing::pcd::ggm::GgmMasterHeader>,
) {
    let (params, poseidon) = params();
    ragu_testing::pcd::ggm::fixtures::setup_walk::<Pasta>(params, poseidon)
}

pub fn setup_blind() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    rand::rngs::StdRng,
    Pcd<Pasta, ProductionRank, ragu_testing::pcd::ggm::GgmPrivateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
    Fp,
) {
    let (params, poseidon) = params();
    ragu_testing::pcd::ggm::fixtures::setup_blind::<Pasta>(params, poseidon)
}

pub fn setup_delegate() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    rand::rngs::StdRng,
    Pcd<Pasta, ProductionRank, ragu_testing::pcd::ggm::GgmDelegateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (params, poseidon) = params();
    ragu_testing::pcd::ggm::fixtures::setup_delegate::<Pasta>(params, poseidon)
}

pub fn setup_final() -> (
    App,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    rand::rngs::StdRng,
    Pcd<Pasta, ProductionRank, ragu_testing::pcd::ggm::GgmDelegateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (params, poseidon) = params();
    ragu_testing::pcd::ggm::fixtures::setup_final::<Pasta>(params, poseidon)
}
