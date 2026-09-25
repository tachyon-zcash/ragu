//! The claims evaluated from openings against the decider's claim builder on
//! the bootstrap proof: the same claims in the same order, each landing on
//! the builder's polynomials evaluated at the query point, and each holding
//! against its target.

use alloc::borrow::Cow;

use ragu_arithmetic::{
    DeferredField,
    ff::{Field, PrimeField},
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_backend::ReferenceBackend;
use ragu_circuits::{
    polynomials::{ProductionRank, sparse},
    registry::{CircuitIndex, Registry},
};
use ragu_pasta::{Fp, Fq, Pasta};

use super::{Evaluated, NativePolys, NestedPolys, Opened};
use crate::{
    Application, ApplicationBuilder,
    internal::{
        claims::Builder,
        ky::{self, NativeKy, NestedKy},
        native, nested,
    },
};

type TestR = ProductionRank;
const HEADER_SIZE: usize = 4;

fn create_test_app() -> Application<'static, Pasta, TestR, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .finalize(Pasta::baked())
        .expect("failed to create test application")
}

/// Holds the evaluated claims to the builder's polynomials at `r` and to
/// the targets.
fn check<F: PrimeField + DeferredField>(
    evaluated: &[Evaluated<F>],
    builder_a: &[Cow<'_, sparse::Polynomial<F, TestR>>],
    builder_b: &[Cow<'_, sparse::Polynomial<F, TestR>>],
    r: F,
) {
    assert_eq!(evaluated.len(), builder_a.len());
    for (i, (claim, (a, b))) in evaluated
        .iter()
        .zip(builder_a.iter().zip(builder_b))
        .enumerate()
    {
        assert_eq!(claim.a, a.eval(r), "a of claim {i} at r");
        assert_eq!(claim.b, b.eval(r), "b of claim {i} at r");
        assert_eq!(claim.k, a.revdot(b), "target of claim {i}");
    }
}

/// The openings of `poly` at `r` and at `rz`.
fn open<F: PrimeField>(poly: &sparse::Polynomial<F, TestR>, r: F, z: F) -> Opened<F> {
    Opened {
        at_r: poly.eval(r),
        at_rz: poly.eval(r * z),
    }
}

/// A circuit's wiring restriction $s(X, y)$ at `r`.
fn restriction<F: PrimeField>(
    registry: &Registry<'_, F, TestR>,
    y: F,
    r: F,
) -> impl Fn(CircuitIndex) -> F {
    move |circuit| registry.circuit_y(circuit, y).eval(r)
}

#[test]
fn native_evaluations_match_the_decider() {
    let app = create_test_app();
    let pcd = app.bootstrap_pcd();
    let proof = pcd.proof();
    let mut rng = StdRng::seed_from_u64(1);
    let (y, z, r) = (
        Fp::random(&mut rng),
        Fp::random(&mut rng),
        Fp::random(&mut rng),
    );

    let mut builder = Builder::<_, Fp, TestR, ReferenceBackend>::new(&app.native_registry, y, z);
    native::claims::build(&NativePolys(proof), &mut builder).unwrap();

    let targets = NativeKy {
        c: Some(proof.native_c()),
        ..ky::native_ky::<Pasta, TestR, (), HEADER_SIZE>(&pcd, y).unwrap()
    };
    let evaluated = super::native::<TestR, _>(
        proof.circuit_id(),
        r,
        z,
        |component| open(&proof[component], r, z),
        restriction(&app.native_registry, y, r),
        &targets,
        &[],
    )
    .unwrap();

    check(&evaluated, &builder.a, &builder.b, r);
}

#[test]
fn nested_evaluations_match_the_decider() {
    let app = create_test_app();
    let pcd = app.bootstrap_pcd();
    let proof = pcd.proof();
    let mut rng = StdRng::seed_from_u64(2);
    let (y, z, r) = (
        Fq::random(&mut rng),
        Fq::random(&mut rng),
        Fq::random(&mut rng),
    );

    let mut builder = Builder::<_, Fq, TestR, ReferenceBackend>::new(&app.nested_registry, y, z);
    nested::claims::build(&NestedPolys(proof), &mut builder).unwrap();

    let targets = NestedKy {
        c: proof.nested_c(),
        unified: ky::nested_ky(proof, y).unwrap(),
    };
    let evaluated = super::nested::<TestR, _>(
        r,
        z,
        |component| open(&proof[component], r, z),
        restriction(&app.nested_registry, y, r),
        &targets,
        &[],
    )
    .unwrap();

    check(&evaluated, &builder.a, &builder.b, r);
}
