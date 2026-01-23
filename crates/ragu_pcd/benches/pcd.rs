use arithmetic::Cycle;
use criterion::{Criterion, criterion_group, criterion_main};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::test_fixtures::nontrivial;
use rand::rngs::mock::StepRng;

fn mock_rng() -> StepRng {
    let seed_bytes: [u8; 8] = "innocent".as_bytes().try_into().unwrap();
    StepRng::new(u64::from_le_bytes(seed_bytes), 0xF2EE_CAFE_BABE_2DA7)
}

fn bench_application_build(c: &mut Criterion) {
    let pasta = Pasta::baked();

    c.bench_function("pcd/poseidon/application_build", |b| {
        b.iter(|| nontrivial::build_app::<Pasta>(pasta))
    });
}

fn bench_seed(c: &mut Criterion) {
    let pasta = Pasta::baked();

    c.bench_function("pcd/poseidon/seed", |b| {
        let app = nontrivial::build_app::<Pasta>(pasta);
        let mut rng = mock_rng();
        b.iter(|| {
            let leaf1 = app
                .seed(
                    &mut rng,
                    nontrivial::WitnessLeaf {
                        poseidon_params: Pasta::circuit_poseidon(pasta),
                    },
                    Fp::from(42u64),
                )
                .unwrap();

            let leaf2 = app
                .seed(
                    &mut rng,
                    nontrivial::WitnessLeaf {
                        poseidon_params: Pasta::circuit_poseidon(pasta),
                    },
                    Fp::from(42u64),
                )
                .unwrap();

            (leaf1, leaf2)
        })
    });
}

fn bench_fuse(c: &mut Criterion) {
    let pasta = Pasta::baked();

    c.bench_function("pcd/poseidon/fuse", |b| {
        let app = nontrivial::build_app::<Pasta>(pasta);

        let mut rng = mock_rng();

        let (proof1, aux1) = app
            .seed(
                &mut rng,
                nontrivial::WitnessLeaf {
                    poseidon_params: Pasta::circuit_poseidon(pasta),
                },
                Fp::from(1u64),
            )
            .unwrap();
        let leaf1 = proof1.carry(aux1);

        let (proof2, aux2) = app
            .seed(
                &mut rng,
                nontrivial::WitnessLeaf {
                    poseidon_params: Pasta::circuit_poseidon(pasta),
                },
                Fp::from(2u64),
            )
            .unwrap();
        let leaf2 = proof2.carry(aux2);

        b.iter(|| {
            let (proof, aux) = app
                .fuse(
                    &mut rng,
                    nontrivial::Hash2 {
                        poseidon_params: Pasta::circuit_poseidon(pasta),
                    },
                    (),
                    leaf1.clone(),
                    leaf2.clone(),
                )
                .unwrap();
            proof.carry::<nontrivial::InternalNode>(aux);
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let pasta = Pasta::baked();
    let app = nontrivial::build_app::<Pasta>(pasta);

    let mut rng = mock_rng();

    let leaf1 = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf {
                poseidon_params: Pasta::circuit_poseidon(pasta),
            },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf1 = leaf1.0.carry(leaf1.1);

    c.bench_function("pcd/poseidon/verify_leaf", |b| {
        b.iter(|| assert!(app.verify(&leaf1, &mut rng).unwrap()))
    });

    let leaf2 = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf {
                poseidon_params: Pasta::circuit_poseidon(pasta),
            },
            Fp::from(2u64),
        )
        .unwrap();
    let leaf2 = leaf2.0.carry(leaf2.1);

    let node1 = app
        .fuse(
            &mut rng,
            nontrivial::Hash2 {
                poseidon_params: Pasta::circuit_poseidon(pasta),
            },
            (),
            leaf1.clone(),
            leaf2.clone(),
        )
        .unwrap();
    let node1 = node1.0.carry::<nontrivial::InternalNode>(node1.1);

    c.bench_function("pcd/poseidon/verify_node1", |b| {
        b.iter(|| assert!(app.verify(&node1, &mut rng).unwrap()))
    });

    c.bench_function("pcd/poseidon/rerandomize", |b| {
        b.iter(|| app.rerandomize(node1.clone(), &mut rng).unwrap())
    });
}

criterion_group! {
    name = poseidon;
    config = Criterion::default();
    targets =
        bench_application_build,
        bench_seed,
        bench_fuse,
        bench_verify,
}

criterion_main!(poseidon);
