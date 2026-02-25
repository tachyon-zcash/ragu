#![allow(clippy::type_complexity)]

mod setup;

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{ProductionRank, TestRank, structured, unstructured};
use ragu_circuits::registry::{Registry, RegistryBuilder};
use ragu_circuits::{Circuit, CircuitExt};
use ragu_pasta::{Fp, Pasta};
use ragu_testing::circuits::{MySimpleCircuit, SquareCircuit};
use setup::{
    builder_squares, f, rand_structured_poly, rand_structured_poly_vec, rand_unstructured_poly,
    registry_heavy_routines, registry_simple, setup_rng, setup_with_rng,
};

#[library_benchmark(setup = setup_with_rng)]
#[bench::structured(
    Pasta::host_generators(Pasta::baked()),
    (rand_structured_poly, f),
)]
fn commit_structured(
    (generators, (poly, blind)): (
        &'static <Pasta as Cycle>::HostGenerators,
        (structured::Polynomial<Fp, ProductionRank>, Fp),
    ),
) {
    black_box(poly.commit(generators, blind));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::unstructured(Pasta::host_generators(Pasta::baked()), (rand_unstructured_poly, f))]
fn commit_unstructured(
    (generators, (poly, blind)): (
        &'static <Pasta as Cycle>::HostGenerators,
        (unstructured::Polynomial<Fp, ProductionRank>, Fp),
    ),
) {
    black_box(poly.commit(generators, blind));
}

library_benchmark_group!(
    name = poly_commits;
    benchmarks = commit_structured, commit_unstructured
);

#[library_benchmark(setup = setup_rng)]
#[bench::revdot((rand_structured_poly, rand_structured_poly))]
fn revdot(
    (poly1, poly2): (
        structured::Polynomial<Fp, ProductionRank>,
        structured::Polynomial<Fp, ProductionRank>,
    ),
) {
    black_box(poly1.revdot(&poly2));
}

#[library_benchmark(setup = setup_rng)]
#[bench::fold((rand_structured_poly_vec::<8>, f))]
fn fold((polys, scale): (Vec<structured::Polynomial<Fp, ProductionRank>>, Fp)) {
    black_box(structured::Polynomial::fold(polys.iter(), scale));
}

#[library_benchmark(setup = setup_rng)]
#[bench::eval((rand_structured_poly, f))]
fn eval((poly, x): (structured::Polynomial<Fp, ProductionRank>, Fp)) {
    black_box(poly.eval(x));
}

#[library_benchmark(setup = setup_rng)]
#[bench::dilate((rand_structured_poly, f))]
fn dilate((mut poly, z): (structured::Polynomial<Fp, ProductionRank>, Fp)) {
    poly.dilate(z);
    black_box(poly);
}

library_benchmark_group!(
    name = poly_ops;
    benchmarks = revdot, fold, eval, dilate
);

#[library_benchmark(setup = setup_rng)]
#[bench::ky((f, f))]
fn ky((a, b): (Fp, Fp)) {
    black_box(MySimpleCircuit.ky((a, b))).unwrap();
}

#[library_benchmark]
#[bench::into_object_r5(MySimpleCircuit)]
fn into_object_r5(circuit: impl Circuit<Fp>) {
    black_box(CircuitExt::<Fp>::into_object::<TestRank>(circuit)).unwrap();
}

#[library_benchmark]
#[benches::multiple( SquareCircuit { times: 2 }, SquareCircuit { times: 10 },)]
fn into_object_r13(circuit: impl Circuit<Fp>) {
    black_box(CircuitExt::<Fp>::into_object::<ProductionRank>(circuit)).unwrap();
}

#[library_benchmark(setup = setup_rng)]
#[bench::rx_r5((f, f))]
fn rx_r5((witness0, witness1): (Fp, Fp)) {
    black_box(MySimpleCircuit.rx((witness0, witness1))).unwrap();
}

#[library_benchmark(setup = setup_with_rng)]
#[benches::multiple(
        (SquareCircuit { times: 2 }, (f,)),
        (SquareCircuit { times: 10 }, (f,)),
    )]
fn rx_r13((circuit, (witness,)): (SquareCircuit, (Fp,))) {
    black_box(circuit.rx(witness)).unwrap();
}

library_benchmark_group!(
    name = circuit_synthesis;
    benchmarks = into_object_r5, into_object_r13, ky, rx_r5, rx_r13,
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
    benchmarks = register, finalize, xy, wy, wx, wxy, wxy_heavy_routines, wxy_combined_heavy_routines
);

main!(
    library_benchmark_groups = poly_commits,
    poly_ops,
    circuit_synthesis,
    registry_ops
);
