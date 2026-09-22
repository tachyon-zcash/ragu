//! Reference verification at the production rank, excluding proof construction.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::nontrivial;
use rand::{SeedableRng, rngs::StdRng};

fn verify_bench(c: &mut Criterion) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();

    // Build real proofs once, outside the timed verification loop.
    let mut rng = StdRng::seed_from_u64(1234);
    let (left, _) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let (right, _) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(2u64),
        )
        .unwrap();
    let (fused, _) = app
        .fuse(
            &mut rng,
            nontrivial::Hash2 { poseidon_params },
            (),
            left,
            right,
        )
        .unwrap();
    let rerandomized = app.rerandomize(fused.clone(), &mut rng).unwrap();
    // The fused proof stripped to its primary fields, expanded inside the
    // timed loop.
    let stripped = fused.proof().clone().strip();
    let stripped_data = *fused.data();

    let proofs = [
        ("verify_fused", fused, true),
        ("verify_rerandomized", rerandomized, true),
    ];
    #[cfg(feature = "unstable-fuzzing")]
    let proofs = {
        use ragu_pasta::Fq;
        use ragu_pcd::fuzzing::corrupt::{Binding, Corruption, NativeRx, NestedRx, RxComponent};

        let mut proofs = Vec::from(proofs);
        for (name, corruption) in [
            (
                "verify_corrupted_native_coefficient",
                Corruption::NativeCoeff {
                    component: RxComponent::Rx(NativeRx::Application),
                    coeff: 0,
                    delta: Fp::from(7u64),
                },
            ),
            (
                "verify_corrupted_nested_coefficient",
                Corruption::NestedCoeff {
                    index: NestedRx::BridgeEval,
                    coeff: 0,
                    delta: Fq::from(7u64),
                },
            ),
        ] {
            let (mut proof, data) = proofs[0].1.clone().into_parts();
            assert_eq!(proof.corrupt(corruption), Binding::MustReject);
            proofs.push((name, proof.carry::<nontrivial::InternalNode>(data), false));
        }
        proofs
    };

    for (name, proof, expected) in &proofs {
        c.bench_function(name, |b| {
            b.iter_batched(
                || StdRng::seed_from_u64(5678),
                |rng| assert_eq!(app.verify(black_box(proof), rng).unwrap(), *expected),
                criterion::BatchSize::PerIteration,
            );
        });
    }
    c.bench_function("verify_stripped_fused", |b| {
        b.iter_batched(
            || StdRng::seed_from_u64(5678),
            |rng| {
                assert!(
                    app.verify_stripped::<_, nontrivial::InternalNode>(
                        black_box(&stripped),
                        &stripped_data,
                        rng
                    )
                    .unwrap()
                )
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = verify_bench
}
criterion_main!(benches);
