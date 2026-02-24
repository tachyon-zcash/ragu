use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ff::Field;
use pasta_curves::EpAffine;
use pasta_curves::Fq;
use pasta_curves::group::prime::PrimeCurveAffine;
use ragu_arithmetic::mul;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn msm_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("msm");

    for size in [64, 256, 1024, 4096, 8192] {
        let mut rng = StdRng::seed_from_u64(1234);
        let coeffs: Vec<Fq> = (0..size).map(|_| Fq::random(&mut rng)).collect();
        let bases: Vec<EpAffine> = (0..size)
            .map(|_| (EpAffine::generator() * Fq::random(&mut rng)).into())
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| mul(coeffs.iter(), bases.iter()));
        });
    }

    group.finish();
}

criterion_group!(benches, msm_bench);
criterion_main!(benches);
