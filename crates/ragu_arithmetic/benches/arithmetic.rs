use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ff::Field;
use pasta_curves::group::prime::PrimeCurveAffine;
use pasta_curves::{EpAffine, Fp, Fq};
use ragu_arithmetic::{Domain, dot, eval, factor, geosum, mul, poly_with_roots};
use rand::rngs::mock::StepRng;

fn mock_rng() -> StepRng {
    let seed_bytes: [u8; 8] = "arithben".as_bytes().try_into().unwrap();
    StepRng::new(u64::from_le_bytes(seed_bytes), 0xCAFE_BABE_DEAD_BEEF)
}

fn bench_msm_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    for size in [64, 256, 1024, 4096] {
        c.bench_function(&format!("arithmetic/msm/mul_{}", size), |b| {
            b.iter_batched(
                || {
                    let coeffs: Vec<Fq> = (0..size).map(|_| Fq::random(&mut rng)).collect();
                    let bases: Vec<EpAffine> = (0..size)
                        .map(|_| (EpAffine::generator() * Fq::random(&mut rng)).into())
                        .collect();
                    (coeffs, bases)
                },
                |(coeffs, bases)| mul(coeffs.iter(), bases.iter()),
                BatchSize::SmallInput,
            )
        });
    }
}

fn bench_fft_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    for k in [10, 14, 18] {
        let domain = Domain::<Fp>::new(k);
        let n = domain.n();

        c.bench_function(&format!("arithmetic/fft/fft_2_{}", k), |b| {
            b.iter_batched(
                || (0..n).map(|_| Fp::random(&mut rng)).collect::<Vec<_>>(),
                |mut data| {
                    domain.fft(&mut data);
                    data
                },
                BatchSize::SmallInput,
            )
        });

        c.bench_function(&format!("arithmetic/fft/ifft_2_{}", k), |b| {
            b.iter_batched(
                || (0..n).map(|_| Fp::random(&mut rng)).collect::<Vec<_>>(),
                |mut data| {
                    domain.ifft(&mut data);
                    data
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn bench_domain_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    // ell benchmarks - full domain evaluation
    for k in [10, 14] {
        let domain = Domain::<Fp>::new(k);
        let n = domain.n();

        c.bench_function(&format!("arithmetic/domain/ell_2_{}_full", k), |b| {
            b.iter_batched(
                || Fp::random(&mut rng),
                |x| domain.ell(x, n),
                BatchSize::SmallInput,
            )
        });
    }

    // Partial ell evaluation
    let domain = Domain::<Fp>::new(10);
    c.bench_function("arithmetic/domain/ell_2_10_partial_256", |b| {
        b.iter_batched(
            || Fp::random(&mut rng),
            |x| domain.ell(x, 256),
            BatchSize::SmallInput,
        )
    });
}

fn bench_poly_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    // poly_with_roots
    for size in [16, 64, 256, 1024] {
        c.bench_function(&format!("arithmetic/poly/poly_with_roots_{}", size), |b| {
            b.iter_batched(
                || (0..size).map(|_| Fp::random(&mut rng)).collect::<Vec<_>>(),
                |roots| poly_with_roots(&roots),
                BatchSize::SmallInput,
            )
        });
    }

    // eval (Horner's method)
    for size in [256, 4096, 65536] {
        c.bench_function(&format!("arithmetic/poly/eval_{}", size), |b| {
            b.iter_batched(
                || {
                    let coeffs: Vec<Fp> = (0..size).map(|_| Fp::random(&mut rng)).collect();
                    let x = Fp::random(&mut rng);
                    (coeffs, x)
                },
                |(coeffs, x)| eval(&coeffs, x),
                BatchSize::SmallInput,
            )
        });
    }

    // factor (polynomial division)
    for size in [256, 4096] {
        c.bench_function(&format!("arithmetic/poly/factor_{}", size), |b| {
            b.iter_batched(
                || {
                    let coeffs: Vec<Fp> = (0..size).map(|_| Fp::random(&mut rng)).collect();
                    let x = Fp::random(&mut rng);
                    (coeffs, x)
                },
                |(coeffs, x)| factor(coeffs, x),
                BatchSize::SmallInput,
            )
        });
    }
}

fn bench_field_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    // dot product
    for size in [256, 4096, 65536] {
        c.bench_function(&format!("arithmetic/field/dot_{}", size), |b| {
            b.iter_batched(
                || {
                    let a: Vec<Fp> = (0..size).map(|_| Fp::random(&mut rng)).collect();
                    let b: Vec<Fp> = (0..size).map(|_| Fp::random(&mut rng)).collect();
                    (a, b)
                },
                |(a, b)| dot(&a, &b),
                BatchSize::SmallInput,
            )
        });
    }

    // geosum
    for m in [256, 4096] {
        c.bench_function(&format!("arithmetic/field/geosum_{}", m), |b| {
            b.iter_batched(
                || Fp::random(&mut rng),
                |r| geosum(r, m),
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group! {
    name = msm_ops;
    config = Criterion::default();
    targets = bench_msm_ops
}

criterion_group! {
    name = fft_ops;
    config = Criterion::default();
    targets = bench_fft_ops
}

criterion_group! {
    name = domain_ops;
    config = Criterion::default();
    targets = bench_domain_ops
}

criterion_group! {
    name = poly_ops;
    config = Criterion::default();
    targets = bench_poly_ops
}

criterion_group! {
    name = field_ops;
    config = Criterion::default();
    targets = bench_field_ops
}

criterion_main!(msm_ops, fft_ops, domain_ops, poly_ops, field_ops);
