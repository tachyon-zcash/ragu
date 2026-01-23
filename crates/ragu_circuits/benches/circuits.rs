use arithmetic::Cycle;
use criterion::{Criterion, criterion_group, criterion_main};
use ff::Field;
use ragu_circuits::CircuitExt;
use ragu_circuits::polynomials::{R, structured, unstructured};
use ragu_circuits::registry::RegistryBuilder;
use ragu_circuits::test_fixtures::{MySimpleCircuit, SquareCircuit};
use ragu_pasta::{Fp, Pasta};
use rand::rngs::mock::StepRng;

fn mock_rng() -> StepRng {
    let seed_bytes: [u8; 8] = "didnothn".as_bytes().try_into().unwrap();
    StepRng::new(u64::from_le_bytes(seed_bytes), 0xF2EE_CAFE_D00D_2DA7)
}

fn bench_structured(c: &mut Criterion) {
    let generators = Pasta::host_generators(Pasta::baked());
    let mut rng = mock_rng();

    c.bench_function("circuits/poly_commits/structured", |b| {
        b.iter_batched(
            || {
                (
                    structured::Polynomial::<Fp, R<13>>::random(&mut rng),
                    Fp::random(&mut rng),
                )
            },
            |(poly, blind)| poly.commit(generators, blind),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_unstructured(c: &mut Criterion) {
    let generators = Pasta::host_generators(Pasta::baked());
    let mut rng = mock_rng();

    c.bench_function("circuits/poly_commits/unstructured", |b| {
        b.iter_batched(
            || {
                (
                    unstructured::Polynomial::<Fp, R<13>>::random(&mut rng),
                    Fp::random(&mut rng),
                )
            },
            |(poly, blind)| poly.commit(generators, blind),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_revdot(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("circuits/poly_ops/revdot", |b| {
        b.iter_batched(
            || {
                (
                    structured::Polynomial::<Fp, R<13>>::random(&mut rng),
                    structured::Polynomial::<Fp, R<13>>::random(&mut rng),
                )
            },
            |(poly1, poly2)| poly1.revdot(&poly2),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_fold(c: &mut Criterion) {
    let mut rng = mock_rng();
    c.bench_function("circuits/poly_ops/fold", |b| {
        b.iter_batched(
            || {
                let polys: Vec<structured::Polynomial<Fp, R<13>>> = (0..8)
                    .map(|_| structured::Polynomial::random(&mut rng))
                    .collect();
                let scale = Fp::random(&mut rng);
                (polys, scale)
            },
            |(polys, scale)| structured::Polynomial::fold(polys.iter(), scale),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_eval(c: &mut Criterion) {
    let mut rng = mock_rng();
    c.bench_function("circuits/poly_ops/eval", |b| {
        b.iter_batched(
            || {
                (
                    structured::Polynomial::<Fp, R<13>>::random(&mut rng),
                    Fp::random(&mut rng),
                )
            },
            |(poly, x)| poly.eval(x),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_dilate(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("circuits/poly_ops/dilate", |b| {
        b.iter_batched(
            || {
                (
                    structured::Polynomial::<Fp, R<13>>::random(&mut rng),
                    Fp::random(&mut rng),
                )
            },
            |(mut poly, z)| {
                poly.dilate(z);
                poly
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

// ============ CIRCUIT SYNTHESIS BENCHMARKS ============

fn bench_circuit_into_object(c: &mut Criterion) {
    c.bench_function("circuits/synthesis/into_object", |b| {
        b.iter(|| CircuitExt::<Fp>::into_object::<R<5>>(MySimpleCircuit))
    });
}

fn bench_circuit_rx(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("circuits/witness/rx", |b| {
        b.iter_batched(
            || {
                (
                    (Fp::random(&mut rng), Fp::random(&mut rng)),
                    Fp::random(&mut rng),
                )
            },
            |(witness, key)| MySimpleCircuit.rx::<R<5>>(witness, key),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_circuit_ky(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("circuits/instance/ky", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |instance| MySimpleCircuit.ky(instance),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_square_circuit_into_object(c: &mut Criterion) {
    for times in [2, 10] {
        c.bench_function(
            &format!("circuits/synthesis/square_into_object_times_{}", times),
            |b| b.iter(|| CircuitExt::<Fp>::into_object::<R<13>>(SquareCircuit { times })),
        );
    }
}

fn bench_square_circuit_rx(c: &mut Criterion) {
    let mut rng = mock_rng();

    for times in [2, 10] {
        c.bench_function(
            &format!("circuits/witness/square_rx_times_{}", times),
            |b| {
                b.iter_batched(
                    || (Fp::random(&mut rng), Fp::random(&mut rng)),
                    |(witness, key)| SquareCircuit { times }.rx::<R<13>>(witness, key),
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }
}

// ============ REGISTRY BENCHMARKS ============

fn bench_registry_finalize(c: &mut Criterion) {
    let poseidon = Pasta::circuit_poseidon(Pasta::baked());

    // Correlates to test_registry_circuit_consistency using varied SquareCircuit configurations
    c.bench_function("circuits/registry/finalize_8_square_circuits", |b| {
        b.iter(|| {
            RegistryBuilder::<Fp, R<25>>::new()
                .register_circuit(SquareCircuit { times: 2 })
                .unwrap()
                .register_circuit(SquareCircuit { times: 5 })
                .unwrap()
                .register_circuit(SquareCircuit { times: 10 })
                .unwrap()
                .register_circuit(SquareCircuit { times: 11 })
                .unwrap()
                .register_circuit(SquareCircuit { times: 19 })
                .unwrap()
                .register_circuit(SquareCircuit { times: 19 })
                .unwrap()
                .register_circuit(SquareCircuit { times: 19 })
                .unwrap()
                .register_circuit(SquareCircuit { times: 19 })
                .unwrap()
                .finalize(poseidon)
        })
    });
}

fn bench_registry_evaluations(c: &mut Criterion) {
    let poseidon = Pasta::circuit_poseidon(Pasta::baked());
    let registry = RegistryBuilder::<Fp, R<5>>::new()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .finalize(poseidon)
        .unwrap();

    let mut rng = mock_rng();

    c.bench_function("circuits/registry/xy", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |(x, y)| registry.xy(x, y),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/registry/wy", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |(w, y)| registry.wy(w, y),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/registry/wx", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |(w, x)| registry.wx(w, x),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/registry/wxy", |b| {
        b.iter_batched(
            || {
                (
                    Fp::random(&mut rng),
                    Fp::random(&mut rng),
                    Fp::random(&mut rng),
                )
            },
            |(w, x, y)| registry.wxy(w, x, y),
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = poly_commits;
    config = Criterion::default();
    targets =
        bench_structured,
        bench_unstructured
}

criterion_group! {
    name = poly_ops;
    config = Criterion::default();
    targets =
        bench_revdot,
        bench_fold,
        bench_eval,
        bench_dilate
}

criterion_group! {
    name = circuit_synthesis;
    config = Criterion::default();
    targets =
        bench_circuit_into_object,
        bench_circuit_rx,
        bench_circuit_ky,
        bench_square_circuit_into_object,
        bench_square_circuit_rx
}

criterion_group! {
    name = registry_ops;
    config = Criterion::default();
    targets =
        bench_registry_finalize,
        bench_registry_evaluations
}

criterion_main!(poly_commits, poly_ops, circuit_synthesis, registry_ops);
