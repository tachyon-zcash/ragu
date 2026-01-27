mod setup;

use gungraun::{library_benchmark, library_benchmark_group, main};
use pasta_curves::{EpAffine, Fp, Fq};
use ragu_arithmetic::{Domain, dot, eval, factor, geosum, mul, poly_with_roots};
use setup::{f, setup_domain_ell, setup_domain_fft, setup_rng, setup_with_rng, vec_affine, vec_f};
use std::hint::black_box;

#[library_benchmark(setup = setup_rng)]
#[benches::with_setup(
    ((vec_f::< 64, Fq>, vec_affine::< 64>)),
    ((vec_f::< 256, Fq>, vec_affine::< 256>)),
    ((vec_f::< 1024, Fq>, vec_affine::< 1024>)),
    ((vec_f::< 4096, Fq>, vec_affine::< 4096>)),
)]
fn msm_mul((coeffs, bases): (Vec<Fq>, Vec<EpAffine>)) {
    black_box(mul(coeffs.iter(), bases.iter()));
}

library_benchmark_group!(
    name = msm_ops;
    benchmarks = msm_mul
);

#[library_benchmark(setup = setup_domain_fft)]
#[benches::multiple(10, 14, 18)]
fn fft((domain, mut data): (Domain<Fp>, Vec<Fp>)) {
    domain.fft(&mut data);
    black_box(data);
}

#[library_benchmark(setup = setup_domain_ell)]
#[benches::multiple(10, 14)]
fn ell((domain, x, n): (Domain<Fp>, Fp, usize)) {
    black_box(domain.ell(x, n));
}

library_benchmark_group!(
    name = domain_ops;
    benchmarks = fft, ell
);

#[library_benchmark(setup = setup_rng)]
#[benches::with_setup(
    ((vec_f::< 16, Fp>,)),
    ((vec_f::< 64, Fp>,)),
    ((vec_f::< 256, Fp>,)),
    ((vec_f::< 1024, Fp>,)),
)]
fn with_roots((roots,): (Vec<Fp>,)) {
    black_box(poly_with_roots(&roots));
}

#[library_benchmark(setup = setup_rng)]
#[benches::with_setup(
    ((vec_f::< 256, Fp>, f)),
    ((vec_f::< 4096, Fp>, f)),
    ((vec_f::< 65536, Fp>, f)),
)]
fn poly_eval((coeffs, x): (Vec<Fp>, Fp)) {
    black_box(eval(&coeffs, x));
}

#[library_benchmark(setup = setup_rng)]
#[benches::with_setup(
    ((vec_f::< 256, Fp>, f::<Fp>)),
    ((vec_f::< 4096, Fp>, f::<Fp>)),
)]
fn poly_factor((coeffs, x): (Vec<Fp>, Fp)) {
    black_box(factor(coeffs, x));
}

library_benchmark_group!(
    name = poly_ops;
    benchmarks = with_roots, poly_eval, poly_factor
);

#[library_benchmark(setup = setup_rng)]
#[benches::with_setup(
    ((vec_f::< 256, Fp>, vec_f::< 256, Fp>)),
    ((vec_f::< 4096, Fp>, vec_f::< 4096, Fp>)),
    ((vec_f::< 65536, Fp>, vec_f::< 65536, Fp>)),
)]
fn field_dot((a, b): (Vec<Fp>, Vec<Fp>)) {
    black_box(dot(&a, &b));
}

#[library_benchmark(setup = setup_with_rng)]
#[benches::with_setup((256, (f,)), (4096, (f,)))]
fn field_geosum((n, (r,)): (usize, (Fp,))) {
    black_box(geosum(r, n));
}

library_benchmark_group!(
    name = field_ops;
    benchmarks = field_dot, field_geosum
);

main!(
    library_benchmark_groups = msm_ops,
    domain_ops,
    poly_ops,
    field_ops
);
