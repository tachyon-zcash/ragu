use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{Application, ApplicationBuilder, Pcd, StepHandle};
use ragu_testing::pcd::nontrivial;
use rand::SeedableRng;
use rand::rngs::StdRng;

pub fn setup_register() -> (
    nontrivial::WitnessLeaf<'static, Pasta>,
    nontrivial::Hash2<'static, Pasta>,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    (
        nontrivial::WitnessLeaf { poseidon_params },
        nontrivial::Hash2 { poseidon_params },
    )
}

pub fn setup_finalize() -> (
    ApplicationBuilder<'static, Pasta, ProductionRank, 4>,
    &'static <Pasta as Cycle>::Params,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let mut builder = ApplicationBuilder::<Pasta, ProductionRank, 4>::new();
    builder
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap();
    builder
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap();
    (builder, pasta)
}

fn build_app() -> (
    Application<'static, Pasta, ProductionRank, 4>,
    StepHandle<nontrivial::WitnessLeaf<'static, Pasta>>,
    StepHandle<nontrivial::Hash2<'static, Pasta>>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let mut builder = ApplicationBuilder::<Pasta, ProductionRank, 4>::new();
    let leaf_handle = builder
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap();
    let hash_handle = builder
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap();
    let app = builder.finalize(pasta).unwrap();
    (app, leaf_handle, hash_handle, poseidon_params)
}

pub fn setup_seed() -> (
    Application<'static, Pasta, ProductionRank, 4>,
    StepHandle<nontrivial::WitnessLeaf<'static, Pasta>>,
    StepHandle<nontrivial::Hash2<'static, Pasta>>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
) {
    let (app, leaf_handle, hash_handle, poseidon_params) = build_app();
    (
        app,
        leaf_handle,
        hash_handle,
        poseidon_params,
        StdRng::seed_from_u64(1234),
    )
}

pub fn setup_fuse() -> (
    Application<'static, Pasta, ProductionRank, 4>,
    Pcd<'static, Pasta, ProductionRank, nontrivial::LeafNode>,
    Pcd<'static, Pasta, ProductionRank, nontrivial::LeafNode>,
    StepHandle<nontrivial::Hash2<'static, Pasta>>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
) {
    let (app, leaf_handle, hash_handle, poseidon_params, mut rng) = setup_seed();

    let (proof1, aux1) = app
        .seed(
            &mut rng,
            &leaf_handle,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf1 = proof1.carry::<nontrivial::LeafNode>(aux1);

    let (proof2, aux2) = app
        .seed(
            &mut rng,
            &leaf_handle,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(2u64),
        )
        .unwrap();
    let leaf2 = proof2.carry::<nontrivial::LeafNode>(aux2);

    (app, leaf1, leaf2, hash_handle, poseidon_params, rng)
}

pub fn setup_verify_leaf() -> (
    Application<'static, Pasta, ProductionRank, 4>,
    Pcd<'static, Pasta, ProductionRank, nontrivial::LeafNode>,
    StdRng,
) {
    let (app, leaf_handle, _, poseidon_params, mut rng) = setup_seed();

    let (proof, aux) = app
        .seed(
            &mut rng,
            &leaf_handle,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf = proof.carry::<nontrivial::LeafNode>(aux);

    (app, leaf, rng)
}

pub fn setup_verify_node() -> (
    Application<'static, Pasta, ProductionRank, 4>,
    Pcd<'static, Pasta, ProductionRank, nontrivial::InternalNode>,
    StdRng,
) {
    let (app, leaf_handle, hash_handle, poseidon_params, mut rng) = setup_seed();

    let (proof1, aux1) = app
        .seed(
            &mut rng,
            &leaf_handle,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf1 = proof1.carry::<nontrivial::LeafNode>(aux1);

    let (proof2, aux2) = app
        .seed(
            &mut rng,
            &leaf_handle,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(2u64),
        )
        .unwrap();
    let leaf2 = proof2.carry::<nontrivial::LeafNode>(aux2);

    let (proof, aux) = app
        .fuse(
            &mut rng,
            &hash_handle,
            nontrivial::Hash2 { poseidon_params },
            (),
            leaf1,
            leaf2,
        )
        .unwrap();
    let node = proof.carry::<nontrivial::InternalNode>(aux);

    (app, node, rng)
}
