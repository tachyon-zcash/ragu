#![allow(clippy::type_complexity)]

mod setup;

use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_pasta::{EpAffine, Fp, PoseidonFp};
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Boolean, Element, Endoscalar, Point, multiadd, multipack};
use setup::{
    BenchEmu, alloc_bools, alloc_coeffs, alloc_elem, alloc_elems, alloc_endo, alloc_point,
    alloc_sponge, setup_emu,
};
use std::hint::black_box;

#[library_benchmark(setup = setup_emu)]
#[bench::element_mul((alloc_elem, alloc_elem))]
fn element_mul(
    (mut emu, (a, b)): (
        BenchEmu,
        (Element<'static, BenchEmu>, Element<'static, BenchEmu>),
    ),
) {
    black_box(a.mul(&mut emu, &b)).unwrap();
}

#[library_benchmark(setup = setup_emu)]
#[bench::element_invert((alloc_elem,))]
fn element_invert((mut emu, (elem,)): (BenchEmu, (Element<'static, BenchEmu>,))) {
    black_box(elem.invert(&mut emu)).unwrap();
}

#[library_benchmark(setup = setup_emu)]
#[bench::element_fold((alloc_elems::<8>, alloc_elem))]
fn element_fold(
    (mut emu, (elements, scale)): (
        BenchEmu,
        (Vec<Element<'static, BenchEmu>>, Element<'static, BenchEmu>),
    ),
) {
    black_box(Element::fold(&mut emu, &elements, &scale)).unwrap();
}

#[library_benchmark(setup = setup_emu)]
#[bench::element_is_zero((alloc_elem,))]
fn element_is_zero((mut emu, (elem,)): (BenchEmu, (Element<'static, BenchEmu>,))) {
    black_box(elem.is_zero(&mut emu)).unwrap();
}

#[library_benchmark(setup = setup_emu)]
#[bench::element_multiadd((alloc_elems::<8>, alloc_coeffs::<8>))]
fn element_multiadd(
    (mut emu, (elements, coeffs)): (BenchEmu, (Vec<Element<'static, BenchEmu>>, Vec<Fp>)),
) {
    black_box(multiadd(&mut emu, &elements, &coeffs)).unwrap();
}

library_benchmark_group!(
    name = element_ops;
    benchmarks = element_mul, element_invert, element_fold, element_is_zero, element_multiadd
);

#[library_benchmark(setup = setup_emu)]
#[bench::point_double((alloc_point,))]
fn point_double((mut emu, (point,)): (BenchEmu, (Point<'static, BenchEmu, EpAffine>,))) {
    black_box(point.double(&mut emu)).unwrap();
}

#[library_benchmark(setup = setup_emu)]
#[bench::point_add_incomplete((alloc_point, alloc_point))]
fn point_add_incomplete(
    (mut emu, (p1, p2)): (
        BenchEmu,
        (
            Point<'static, BenchEmu, EpAffine>,
            Point<'static, BenchEmu, EpAffine>,
        ),
    ),
) {
    black_box(p1.add_incomplete(&mut emu, &p2, None)).unwrap();
}

#[library_benchmark(setup = setup_emu)]
#[bench::point_double_and_add_incomplete((alloc_point, alloc_point))]
fn point_double_and_add_incomplete(
    (mut emu, (p1, p2)): (
        BenchEmu,
        (
            Point<'static, BenchEmu, EpAffine>,
            Point<'static, BenchEmu, EpAffine>,
        ),
    ),
) {
    black_box(p1.double_and_add_incomplete(&mut emu, &p2)).unwrap();
}

#[library_benchmark(setup = setup_emu)]
#[bench::point_endo((alloc_point,))]
fn point_endo((mut emu, (point,)): (BenchEmu, (Point<'static, BenchEmu, EpAffine>,))) {
    black_box(point.endo(&mut emu)).unwrap();
}

library_benchmark_group!(
    name = point_ops;
    benchmarks = point_double, point_add_incomplete, point_double_and_add_incomplete, point_endo
);

#[library_benchmark(setup = setup_emu)]
#[bench::boolean_multipack((alloc_bools::<256>,))]
fn boolean_multipack((mut emu, (bools,)): (BenchEmu, (Vec<Boolean<'static, BenchEmu>>,))) {
    black_box(multipack(&mut emu, &bools)).unwrap();
}

library_benchmark_group!(
    name = boolean_ops;
    benchmarks = boolean_multipack
);

#[library_benchmark(setup = setup_emu)]
#[bench::sponge_absorb_squeeze((alloc_sponge, alloc_elem))]
fn sponge_absorb_squeeze(
    (mut emu, (mut sponge, elem)): (
        BenchEmu,
        (
            Sponge<'static, BenchEmu, PoseidonFp>,
            Element<'static, BenchEmu>,
        ),
    ),
) {
    sponge.absorb(&mut emu, &elem).unwrap();
    black_box(sponge.squeeze(&mut emu)).unwrap();
}

library_benchmark_group!(
    name = sponge_ops;
    benchmarks = sponge_absorb_squeeze
);

#[library_benchmark(setup = setup_emu)]
#[bench::endoscalar_group_scale((alloc_point, alloc_endo))]
fn endoscalar_group_scale(
    (mut emu, (p, scalar)): (
        BenchEmu,
        (
            Point<'static, BenchEmu, EpAffine>,
            Endoscalar<'static, BenchEmu>,
        ),
    ),
) {
    black_box(scalar.group_scale(&mut emu, &p)).unwrap();
}

#[library_benchmark(setup = setup_emu)]
#[bench::endoscalar_extract((alloc_elem,))]
fn endoscalar_extract((mut emu, (elem,)): (BenchEmu, (Element<'static, BenchEmu>,))) {
    black_box(Endoscalar::extract(&mut emu, elem)).unwrap();
}

#[library_benchmark(setup = setup_emu)]
#[bench::endoscalar_field_scale((alloc_endo,))]
fn endoscalar_field_scale((mut emu, (endo,)): (BenchEmu, (Endoscalar<'static, BenchEmu>,))) {
    black_box(endo.field_scale(&mut emu)).unwrap();
}

library_benchmark_group!(
    name = endoscalar_ops;
    benchmarks = endoscalar_group_scale, endoscalar_extract, endoscalar_field_scale
);

main!(
    library_benchmark_groups = element_ops,
    point_ops,
    boolean_ops,
    sponge_ops,
    endoscalar_ops
);
