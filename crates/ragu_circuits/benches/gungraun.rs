#![allow(clippy::type_complexity)]

mod setup;

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_circuits::{
    Circuit, CircuitExt,
    polynomials::{ProductionRank, TestRank, sparse},
    registry::{Registry, RegistryBuilder},
    testing::synthesis_counts,
};
use ragu_core::{
    Cycle,
    pasta::{Fp, Pasta},
};
use ragu_testing::circuits::{MySimpleCircuit, SquareCircuit};
use setup::{
    builder_squares, f, rand_sparse_poly, rand_sparse_poly_vec, registry_heavy_routines,
    registry_simple, setup_rng, setup_with_rng,
};

#[library_benchmark(setup = setup_with_rng)]
#[bench::sparse(Pasta::host_generators(ragu_pcd::pasta::baked()), (rand_sparse_poly,))]
fn commit_sparse(
    (generators, (poly,)): (
        &'static <Pasta as Cycle>::HostGenerators,
        (sparse::Polynomial<Fp, ProductionRank>,),
    ),
) {
    black_box(poly.commit_to_affine(generators));
}

library_benchmark_group!(
    name = poly_commits;
    benchmarks = commit_sparse
);

#[library_benchmark(setup = setup_rng)]
#[bench::revdot((rand_sparse_poly, rand_sparse_poly))]
fn revdot(
    (poly1, poly2): (
        sparse::Polynomial<Fp, ProductionRank>,
        sparse::Polynomial<Fp, ProductionRank>,
    ),
) {
    black_box(poly1.revdot(&poly2));
}

#[library_benchmark(setup = setup_rng)]
#[bench::fold((rand_sparse_poly_vec::<8>, f))]
fn fold((polys, scale): (Vec<sparse::Polynomial<Fp, ProductionRank>>, Fp)) {
    black_box(sparse::Polynomial::fold(polys.iter(), scale));
}

#[library_benchmark(setup = setup_rng)]
#[bench::eval((rand_sparse_poly, f))]
fn eval((poly, x): (sparse::Polynomial<Fp, ProductionRank>, Fp)) {
    black_box(poly.eval(x));
}

#[library_benchmark(setup = setup_rng)]
#[bench::dilate((rand_sparse_poly, f))]
fn dilate((mut poly, z): (sparse::Polynomial<Fp, ProductionRank>, Fp)) {
    poly.dilate(z);
    black_box(poly);
}

library_benchmark_group!(
    name = poly_ops;
    benchmarks = revdot, fold, eval, dilate
);

#[library_benchmark(setup = setup_rng)]
#[bench::eval_ky((f, f, f))]
fn eval_ky((a, b, y): (Fp, Fp, Fp)) {
    black_box(MySimpleCircuit.ky((a, b), y)).unwrap();
}

#[library_benchmark]
#[bench::simple(MySimpleCircuit)]
fn metrics_simple(circuit: impl Circuit<Fp> + 'static) {
    black_box(synthesis_counts(&circuit)).unwrap();
}

#[library_benchmark]
#[benches::multiple( SquareCircuit { times: 2 }, SquareCircuit { times: 10 },)]
fn metrics_square(circuit: impl Circuit<Fp> + 'static) {
    black_box(synthesis_counts(&circuit)).unwrap();
}

#[library_benchmark(setup = setup_rng)]
#[bench::trace_test_rank((f, f))]
fn trace_test_rank((witness0, witness1): (Fp, Fp)) {
    black_box(MySimpleCircuit.trace((witness0, witness1))).unwrap();
}

#[library_benchmark(setup = setup_with_rng)]
#[benches::multiple(
        (SquareCircuit { times: 2 }, (f,)),
        (SquareCircuit { times: 10 }, (f,)),
    )]
fn trace_production_rank((circuit, (witness,)): (SquareCircuit, (Fp,))) {
    black_box(circuit.trace(witness)).unwrap();
}

library_benchmark_group!(
    name = circuit_synthesis;
    benchmarks = metrics_simple, metrics_square, eval_ky, trace_test_rank, trace_production_rank,
);

#[library_benchmark]
#[bench::register()]
fn register() {
    black_box(builder_squares());
}

#[library_benchmark]
#[bench::finalize(builder_squares())]
fn finalize(builder: RegistryBuilder<Fp, ProductionRank>) {
    black_box(builder.finalize()).unwrap();
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::xy(registry_simple(), (f, f))]
fn xy((registry, (x, y)): (Registry<'_, Fp, TestRank>, (Fp, Fp))) {
    black_box(registry.xy(x, y));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::wy(registry_simple(), (f, f))]
fn wy((registry, (w, y)): (Registry<'_, Fp, TestRank>, (Fp, Fp))) {
    black_box(registry.wy(w, y));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::wx(registry_simple(), (f, f))]
fn wx((registry, (w, x)): (Registry<'_, Fp, TestRank>, (Fp, Fp))) {
    black_box(registry.wx(w, x));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::wxy(registry_simple(), (f, f, f))]
fn wxy((registry, (w, x, y)): (Registry<'_, Fp, TestRank>, (Fp, Fp, Fp))) {
    black_box(registry.wxy(w, x, y));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::xy_heavy_routines(registry_heavy_routines(), (f, f))]
fn xy_heavy_routines((registry, (x, y)): (Registry<'_, Fp, ProductionRank>, (Fp, Fp))) {
    black_box(registry.xy(x, y));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::wxy_heavy_routines(registry_heavy_routines(), (f, f, f))]
fn wxy_heavy_routines((registry, (w, x, y)): (Registry<'_, Fp, ProductionRank>, (Fp, Fp, Fp))) {
    black_box(registry.wxy(w, x, y));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::wxy_combined_heavy_routines(registry_heavy_routines(), (f, f, f))]
fn wxy_combined_heavy_routines(
    (registry, (w, x, y)): (Registry<'_, Fp, ProductionRank>, (Fp, Fp, Fp)),
) {
    black_box(registry.wxy_combined(w, x, y));
}

library_benchmark_group!(
    name = registry_ops;
    benchmarks = register, finalize, xy, wy, wx, wxy, xy_heavy_routines, wxy_heavy_routines, wxy_combined_heavy_routines
);

main!(
    library_benchmark_groups = poly_commits,
    poly_ops,
    circuit_synthesis,
    registry_ops
);
