use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ff::Field;
use pasta_curves::Fp;
use ragu_arithmetic::Domain;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn fft_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("fft");

    for log2_n in [10, 14, 18] {
        let mut rng = StdRng::seed_from_u64(1234);
        let domain = Domain::<Fp>::new(log2_n);
        let data: Vec<Fp> = (0..domain.n()).map(|_| Fp::random(&mut rng)).collect();

        group.bench_with_input(BenchmarkId::from_parameter(log2_n), &log2_n, |b, _| {
            b.iter_batched(
                || data.clone(),
                |mut buf| domain.fft(&mut buf),
                criterion::BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

fn ifft_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ifft");

    for log2_n in [10, 14, 18] {
        let mut rng = StdRng::seed_from_u64(1234);
        let domain = Domain::<Fp>::new(log2_n);
        let data: Vec<Fp> = (0..domain.n()).map(|_| Fp::random(&mut rng)).collect();

        group.bench_with_input(BenchmarkId::from_parameter(log2_n), &log2_n, |b, _| {
            b.iter_batched(
                || data.clone(),
                |mut buf| domain.ifft(&mut buf),
                criterion::BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, fft_bench, ifft_bench);
criterion_main!(benches);
