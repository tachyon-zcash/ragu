#![allow(clippy::type_complexity)]

mod setup;

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{ProductionRank, TestRank, sparse};
use ragu_circuits::registry::CircuitIndex;
use ragu_circuits::registry::{Registry, RegistryBuilder};
use ragu_circuits::{Circuit, CircuitExt};
use ragu_pasta::{Fp, Pasta};
use ragu_testing::circuits::{MySimpleCircuit, SquareCircuit};
use setup::{
    builder_squares, f, rand_sparse_poly, rand_sparse_poly_vec, registry_simple, setup_rng,
    setup_with_rng,
};

#[library_benchmark(setup = setup_with_rng)]
#[bench::sparse(Pasta::host_generators(Pasta::baked()), (rand_sparse_poly,))]
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
fn constraint_counts_simple(circuit: impl Circuit<Fp> + 'static) {
    let registry = RegistryBuilder::<Fp, TestRank>::new()
        .register_internal_circuit(circuit)
        .unwrap()
        .finalize()
        .unwrap();
    black_box(registry.constraint_counts(CircuitIndex::new(0)));
}

#[library_benchmark]
#[benches::multiple( SquareCircuit { times: 2 }, SquareCircuit { times: 10 },)]
fn constraint_counts_square(circuit: impl Circuit<Fp> + 'static) {
    let registry = RegistryBuilder::<Fp, TestRank>::new()
        .register_internal_circuit(circuit)
        .unwrap()
        .finalize()
        .unwrap();
    black_box(registry.constraint_counts(CircuitIndex::new(0)));
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
    benchmarks = constraint_counts_simple, constraint_counts_square, eval_ky, trace_test_rank, trace_production_rank,
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

library_benchmark_group!(
    name = registry_ops;
    benchmarks = register, finalize, xy, wy, wx, wxy
);

main!(
    library_benchmark_groups = poly_commits,
    poly_ops,
    circuit_synthesis,
    registry_ops
);
