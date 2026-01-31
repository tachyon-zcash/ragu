#![allow(clippy::type_complexity)]

mod setup;

use std::hint::black_box;

use arithmetic::Cycle;
use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_circuits::polynomials::{R, structured, unstructured};
use ragu_circuits::registry::{Key, Registry, RegistryBuilder};
use ragu_circuits::test_fixtures::{MySimpleCircuit, SquareCircuit};
use ragu_circuits::{Circuit, CircuitExt};
use ragu_pasta::{Fp, Pasta};
use setup::{
    builder_squares, f, key, rand_structured_poly, rand_structured_poly_vec,
    rand_unstructured_poly, registry_simple, setup_poseidon, setup_rng, setup_with_rng,
};

#[library_benchmark(setup = setup_with_rng)]
#[bench::structured(
    Pasta::host_generators(Pasta::baked()),
    (rand_structured_poly, f),
)]
fn commit_structured(
    (generators, (poly, blind)): (
        &'static <Pasta as Cycle>::HostGenerators,
        (structured::Polynomial<Fp, R<13>>, Fp),
    ),
) {
    black_box(poly.commit(generators, blind));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::unstructured(Pasta::host_generators(Pasta::baked()), (rand_unstructured_poly, f))]
fn commit_unstructured(
    (generators, (poly, blind)): (
        &'static <Pasta as Cycle>::HostGenerators,
        (unstructured::Polynomial<Fp, R<13>>, Fp),
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
        structured::Polynomial<Fp, R<13>>,
        structured::Polynomial<Fp, R<13>>,
    ),
) {
    black_box(poly1.revdot(&poly2));
}

#[library_benchmark(setup = setup_rng)]
#[bench::fold((rand_structured_poly_vec::<8>, f))]
fn fold((polys, scale): (Vec<structured::Polynomial<Fp, R<13>>>, Fp)) {
    black_box(structured::Polynomial::fold(polys.iter(), scale));
}

#[library_benchmark(setup = setup_rng)]
#[bench::eval((rand_structured_poly, f))]
fn eval((poly, x): (structured::Polynomial<Fp, R<13>>, Fp)) {
    black_box(poly.eval(x));
}

#[library_benchmark(setup = setup_rng)]
#[bench::dilate((rand_structured_poly, f))]
fn dilate((mut poly, z): (structured::Polynomial<Fp, R<13>>, Fp)) {
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
    black_box(CircuitExt::<Fp>::into_object::<R<5>>(circuit)).unwrap();
}

#[library_benchmark]
#[benches::multiple( SquareCircuit { times: 2 }, SquareCircuit { times: 10 },)]
fn into_object_r13(circuit: impl Circuit<Fp>) {
    black_box(CircuitExt::<Fp>::into_object::<R<13>>(circuit)).unwrap();
}

#[library_benchmark(setup = setup_rng)]
#[bench::rx_r5((f, f, key))]
fn rx_r5((witness0, witness1, key): (Fp, Fp, Key<Fp>)) {
    black_box(MySimpleCircuit.rx::<R<5>>((witness0, witness1), &key)).unwrap();
}

#[library_benchmark(setup = setup_with_rng)]
#[benches::multiple(
        (SquareCircuit { times: 2 }, (f, key)),
        (SquareCircuit { times: 10 }, (f, key)),
    )]
fn rx_r13((circuit, (witness, key)): (SquareCircuit, (Fp, Key<Fp>))) {
    black_box(circuit.rx::<R<13>>(witness, &key)).unwrap();
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
#[bench::finalize(setup_poseidon(), builder_squares())]
fn finalize(poseidon: &<Pasta as Cycle>::CircuitPoseidon, builder: RegistryBuilder<Fp, R<25>, 0>) {
    black_box(builder.finalize(poseidon)).unwrap();
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::xy(registry_simple(), (f, f))]
fn xy((registry, (x, y)): (Registry<'_, Fp, R<5>>, (Fp, Fp))) {
    black_box(registry.xy(x, y));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::wy(registry_simple(), (f, f))]
fn wy((registry, (w, y)): (Registry<'_, Fp, R<5>>, (Fp, Fp))) {
    black_box(registry.wy(w, y));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::wx(registry_simple(), (f, f))]
fn wx((registry, (w, x)): (Registry<'_, Fp, R<5>>, (Fp, Fp))) {
    black_box(registry.wx(w, x));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::wxy(registry_simple(), (f, f, f))]
fn wxy((registry, (w, x, y)): (Registry<'_, Fp, R<5>>, (Fp, Fp, Fp))) {
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
