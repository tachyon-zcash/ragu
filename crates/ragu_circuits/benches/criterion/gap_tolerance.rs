//! Criterion benchmarks to determine the optimal `GAP_TOLERANCE` value for
//! sparse polynomial block splitting.
//!
//! Directly compares the two strategies for skipping a gap of g zeros:
//!
//! **eval** — inline does 1 field mul per zero (`result = result * z + 0`):
//!   - "pow":    result *= z.pow_vartime([g])
//!   - "horner": for _ in 0..g { result *= z }
//!
//! **dilate** — inline does 2 field muls per zero (`0 *= power; power *= z`):
//!   - "pow":    power *= z.pow_vartime([g])
//!   - "dilate": for _ in 0..g { dummy *= power; power *= z }

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ff::Field;
use ragu_pasta::Fp;
use rand::SeedableRng;
use rand::rngs::StdRng;

const GAP_SIZES: &[usize] = &[1, 2, 3, 4, 5, 6, 8, 12, 16, 24, 32];

fn bench_pow_vs_horner(c: &mut Criterion) {
    let mut group = c.benchmark_group("gap_tolerance/pow_vs_horner");
    let mut rng = StdRng::seed_from_u64(42);
    let z = Fp::random(&mut rng);
    let result = Fp::random(&mut rng);

    for &gap in GAP_SIZES {
        group.bench_with_input(BenchmarkId::new("pow", gap), &gap, |b, &gap| {
            b.iter(|| {
                let mut r = result;
                r *= z.pow_vartime([gap as u64]);
                black_box(r)
            });
        });
        group.bench_with_input(BenchmarkId::new("horner", gap), &gap, |b, &gap| {
            b.iter(|| {
                let mut r = result;
                for _ in 0..gap {
                    r *= z;
                }
                black_box(r)
            });
        });
    }
    group.finish();
}

fn bench_pow_vs_dilate(c: &mut Criterion) {
    let mut group = c.benchmark_group("gap_tolerance/pow_vs_dilate");
    let mut rng = StdRng::seed_from_u64(42);
    let z = Fp::random(&mut rng);
    let power = Fp::random(&mut rng);
    let coeff = Fp::ZERO;

    for &gap in GAP_SIZES {
        group.bench_with_input(BenchmarkId::new("pow", gap), &gap, |b, &gap| {
            b.iter(|| {
                let mut p = power;
                p *= z.pow_vartime([gap as u64]);
                black_box(p)
            });
        });
        group.bench_with_input(BenchmarkId::new("dilate", gap), &gap, |b, &gap| {
            b.iter(|| {
                let mut p = power;
                let mut c = coeff;
                for _ in 0..gap {
                    c *= p;
                    p *= z;
                }
                black_box((c, p))
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_pow_vs_horner,
    bench_pow_vs_dilate,
);
criterion_main!(benches);
