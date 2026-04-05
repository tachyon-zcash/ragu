//! Criterion benchmarks to determine the optimal `GAP_TOLERANCE` value for
//! sparse polynomial block splitting.
//!
//! Directly compares the two strategies for skipping a gap of g zeros:
//!
//! **eval** — inline does 1 mul per zero (`result = result * z + 0`):
//!   - "pow":    result *= z.pow_vartime([g])
//!   - "horner": for _ in 0..g { result *= z }
//!
//! **dilate** — inline does 2 muls per zero (`0 *= power; power *= z`):
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

// ---------------------------------------------------------------------------
// combine_assign: many tight clusters vs fewer wide clusters
//
// Constructs pairs of polynomials with matching block structure (both have
// the same number of gaps at the same positions — the realistic case from
// fold_add_assign in fuse). Sweeps gap size with a fixed number of gaps.
//
// With the current GAP_TOLERANCE=4:
//   - gap <= 4: zeros are inline, both polys are 1 block. combine_assign
//     gets the single-LHS-block fast path (reuse allocation). The dense
//     buffer includes the inline zeros: allocated, copied, op'd, and
//     scanned by extend_runs.
//   - gap > 4: zeros cause splits, both polys have 11 blocks. Clusters
//     align perfectly (same positions). Each cluster is tight — no wasted
//     gap material in the buffer. But there are 11 clusters, each with
//     its own extend_runs call.
//
// The benchmark shows the crossover: at what gap size does the per-cluster
// overhead of 11 tight clusters exceed the cost of processing inline zeros
// in one wide cluster?
// ---------------------------------------------------------------------------

fn bench_combine_assign_matched(c: &mut Criterion) {
    use ragu_circuits::polynomials::{ProductionRank, Rank, sparse};

    let mut group = c.benchmark_group("gap_tolerance/combine_assign_matched");
    let mut rng = StdRng::seed_from_u64(42);

    const NUM_GAPS: usize = 10;

    for &gap in GAP_SIZES {
        let n = ProductionRank::num_coeffs();
        let total_zeros = gap * NUM_GAPS;
        if total_zeros >= n {
            continue;
        }

        // Build two polynomials with identical gap positions but different
        // nonzero values — the realistic case for fold_add_assign.
        let nonzero_total = n - total_zeros;
        let make_poly = |rng: &mut StdRng| {
            let mut coeffs = Vec::with_capacity(n);
            for g in 0..=NUM_GAPS {
                let run_len = nonzero_total / (NUM_GAPS + 1)
                    + usize::from(g < nonzero_total % (NUM_GAPS + 1));
                for _ in 0..run_len {
                    loop {
                        let v = Fp::random(&mut *rng);
                        if !bool::from(v.is_zero()) {
                            coeffs.push(v);
                            break;
                        }
                    }
                }
                if g < NUM_GAPS {
                    coeffs.extend(core::iter::repeat_n(Fp::ZERO, gap));
                }
            }
            assert_eq!(coeffs.len(), n);
            sparse::Polynomial::<Fp, ProductionRank>::from_coeffs(coeffs)
        };

        let poly_a = make_poly(&mut rng);
        let poly_b = make_poly(&mut rng);

        group.bench_with_input(BenchmarkId::from_parameter(gap), &gap, |b, _| {
            b.iter_batched(
                || poly_a.clone(),
                |mut p| {
                    p.add_assign(&poly_b);
                    black_box(p);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_pow_vs_horner,
    bench_pow_vs_dilate,
    bench_combine_assign_matched,
);
criterion_main!(benches);
