use arithmetic::Cycle;
use ragu_circuits::polynomials::R;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::test_fixtures::nontrivial;
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
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
    ApplicationBuilder<'static, Pasta, R<13>, 4>,
    &'static <Pasta as Cycle>::Params,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap();
    (app, pasta)
}

pub fn setup_seed() -> (
    Application<'static, Pasta, R<13>, 4>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();
    (app, poseidon_params, StdRng::seed_from_u64(1234))
}

pub fn setup_fuse() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
    Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
) {
    let (app, poseidon_params, mut rng) = setup_seed();

    let (proof1, aux1) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf1 = proof1.carry::<nontrivial::LeafNode>(aux1);

    let (proof2, aux2) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(2u64),
        )
        .unwrap();
    let leaf2 = proof2.carry::<nontrivial::LeafNode>(aux2);

    (app, leaf1, leaf2, poseidon_params, rng)
}

pub fn setup_verify_leaf() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
    StdRng,
) {
    let (app, poseidon_params, mut rng) = setup_seed();

    let (proof, aux) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf = proof.carry::<nontrivial::LeafNode>(aux);

    (app, leaf, rng)
}

pub fn setup_verify_node() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::InternalNode>,
    StdRng,
) {
    let (app, poseidon_params, mut rng) = setup_seed();

    let (proof1, aux1) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf1 = proof1.carry::<nontrivial::LeafNode>(aux1);

    let (proof2, aux2) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(2u64),
        )
        .unwrap();
    let leaf2 = proof2.carry::<nontrivial::LeafNode>(aux2);

    let (proof, aux) = app
        .fuse(
            &mut rng,
            nontrivial::Hash2 { poseidon_params },
            (),
            leaf1,
            leaf2,
        )
        .unwrap();
    let node = proof.carry::<nontrivial::InternalNode>(aux);

    (app, node, rng)
}
