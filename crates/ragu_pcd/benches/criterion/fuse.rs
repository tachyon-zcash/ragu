use criterion::{Criterion, criterion_group, criterion_main};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::nontrivial;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn fuse_bench(c: &mut Criterion) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);

    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(1234);

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

    c.bench_function("fuse", |b| {
        b.iter_batched(
            || (leaf1.clone(), leaf2.clone(), StdRng::seed_from_u64(5678)),
            |(l1, l2, mut rng)| {
                app.fuse(&mut rng, nontrivial::Hash2 { poseidon_params }, (), l1, l2)
                    .unwrap()
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = fuse_bench
}
criterion_main!(benches);
