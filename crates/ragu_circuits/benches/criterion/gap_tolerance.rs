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

// MSM scaling: commit cost as a function of total stored coefficients
//
// Builds polynomials with a single large gap in the middle (always >
// GAP_TOLERANCE so it splits into two blocks). The gap size determines how
// many coefficients are excluded from the MSM. Sweeps from 0 excluded
// (fully dense, 8192 elements in MSM) up to 4096 excluded (half the
// polynomial is a gap).
fn bench_msm_scaling(c: &mut Criterion) {
    use ragu_arithmetic::Cycle;
    use ragu_circuits::polynomials::{ProductionRank, Rank, sparse};
    use ragu_pasta::Pasta;

    let mut group = c.benchmark_group("gap_tolerance/msm_scaling");
    let generators = Pasta::host_generators(Pasta::baked());
    let mut rng = StdRng::seed_from_u64(42);
    let blind = Fp::random(&mut rng);

    let n = ProductionRank::num_coeffs();

    // Fully nonzero baseline coefficients.
    let all_nonzero: Vec<Fp> = (0..n)
        .map(|_| {
            loop {
                let v = Fp::random(&mut rng);
                if !bool::from(v.is_zero()) {
                    break v;
                }
            }
        })
        .collect();

    for excluded in [0, 10, 50, 200, 500, 1000, 2000, 4096] {
        let half = (n - excluded) / 2;
        let mut coeffs = Vec::with_capacity(n);
        coeffs.extend_from_slice(&all_nonzero[..half]);
        if excluded > 0 {
            coeffs.extend(core::iter::repeat_n(Fp::ZERO, excluded));
        }
        coeffs.extend_from_slice(&all_nonzero[half..half + (n - half - excluded)]);
        assert_eq!(coeffs.len(), n);
        let poly = sparse::Polynomial::<Fp, ProductionRank>::from_coeffs(coeffs);

        let msm_size = if excluded > 4 { n - excluded } else { n };
        group.bench_function(format!("{msm_size}_in_msm"), |b| {
            b.iter(|| black_box(poly.commit_to_affine(generators, blind)));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_pow_vs_horner,
    bench_pow_vs_dilate,
    bench_msm_scaling,
);
criterion_main!(benches);
