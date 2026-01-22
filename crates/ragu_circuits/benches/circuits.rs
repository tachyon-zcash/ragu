use arithmetic::Cycle;
use criterion::{Criterion, criterion_group, criterion_main};
use ff::Field;
use ragu_circuits::CircuitExt;
use ragu_circuits::mesh::MeshBuilder;
use ragu_circuits::polynomials::{R, structured, unstructured};
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

// ============ SQUARE CIRCUIT BENCHMARKS ============
// These benchmarks correlate to the test cases in mesh.rs and staging/mask.rs

fn bench_square_circuit_into_object(c: &mut Criterion) {
    // Correlates to test_single_circuit_mesh using SquareCircuit { times: 1 }
    c.bench_function("circuits/synthesis/square_into_object_times_2", |b| {
        b.iter(|| CircuitExt::<Fp>::into_object::<R<13>>(SquareCircuit { times: 2 }))
    });

    // Larger circuit with more multiplications
    c.bench_function("circuits/synthesis/square_into_object_times_10", |b| {
        b.iter(|| CircuitExt::<Fp>::into_object::<R<13>>(SquareCircuit { times: 10 }))
    });
}

fn bench_square_circuit_rx(c: &mut Criterion) {
    let mut rng = mock_rng();

    // Correlates to test cases using SquareCircuit { times: 2 }
    c.bench_function("circuits/witness/square_rx_times_2", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |(witness, key)| SquareCircuit { times: 2 }.rx::<R<13>>(witness, key),
            criterion::BatchSize::SmallInput,
        )
    });

    // Larger circuit with more multiplications (correlates to test_mesh_circuit_consistency)
    c.bench_function("circuits/witness/square_rx_times_10", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |(witness, key)| SquareCircuit { times: 10 }.rx::<R<13>>(witness, key),
            criterion::BatchSize::SmallInput,
        )
    });
}

// ============ MESH BENCHMARKS ============

fn bench_mesh_finalize(c: &mut Criterion) {
    let poseidon = Pasta::circuit_poseidon(Pasta::baked());

    c.bench_function("circuits/mesh/finalize_4_circuits", |b| {
        b.iter(|| {
            MeshBuilder::<Fp, R<5>>::new()
                .register_circuit(MySimpleCircuit)
                .unwrap()
                .register_circuit(MySimpleCircuit)
                .unwrap()
                .register_circuit(MySimpleCircuit)
                .unwrap()
                .register_circuit(MySimpleCircuit)
                .unwrap()
                .finalize(poseidon)
        })
    });

    // Correlates to test_mesh_circuit_consistency using varied SquareCircuit configurations
    c.bench_function("circuits/mesh/finalize_8_square_circuits", |b| {
        b.iter(|| {
            MeshBuilder::<Fp, R<25>>::new()
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

fn bench_mesh_evaluations(c: &mut Criterion) {
    let poseidon = Pasta::circuit_poseidon(Pasta::baked());
    let mesh = MeshBuilder::<Fp, R<5>>::new()
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

    c.bench_function("circuits/mesh/xy", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |(x, y)| mesh.xy(x, y),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/mesh/wy", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |(w, y)| mesh.wy(w, y),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/mesh/wx", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |(w, x)| mesh.wx(w, x),
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/mesh/wxy", |b| {
        b.iter_batched(
            || {
                (
                    Fp::random(&mut rng),
                    Fp::random(&mut rng),
                    Fp::random(&mut rng),
                )
            },
            |(w, x, y)| mesh.wxy(w, x, y),
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
    name = mesh_ops;
    config = Criterion::default();
    targets =
        bench_mesh_finalize,
        bench_mesh_evaluations
}

criterion_main!(poly_commits, poly_ops, circuit_synthesis, mesh_ops);
