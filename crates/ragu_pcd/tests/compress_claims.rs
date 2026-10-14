//! The claims' shapes against the decider's claim builder on the bootstrap
//! proof: the same claims in the same order, each shape's weighted sum of
//! components landing on the builder's $a$, and each kind giving the
//! builder's $b$ from that $a$ and the public parts.

use alloc::{borrow::Cow, vec::Vec};

use ragu_backend::ReferenceBackend;
use ragu_circuits::{
    polynomials::{ProductionRank, Rank, sparse},
    registry::Registry,
};
use ragu_core::pasta::{Fp, Fq, Pasta};
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::{
    super::prover::{NativePolys, NestedPolys},
    Kind, Masked, Shape,
};
use crate::{
    Application, ApplicationBuilder,
    internal::{claims::Builder, native, nested},
};

type TestR = ProductionRank;
const HEADER_SIZE: usize = 4;

fn create_test_app() -> Application<'static, Pasta, TestR, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .finalize(crate::pasta::baked())
        .expect("failed to create test application")
}

fn coeffs<F: Field>(poly: &sparse::Polynomial<F, TestR>) -> Vec<F> {
    poly.iter_coeffs().collect()
}

/// The weighted sum of components a shape's side lists.
fn sum<F: Field, Id: Copy>(
    side: &[(F, Id)],
    poly: &impl Fn(Id) -> sparse::Polynomial<F, TestR>,
) -> sparse::Polynomial<F, TestR> {
    let mut acc = sparse::Polynomial::default();
    for &(weight, id) in side {
        let mut term = poly(id);
        term.scale(weight);
        acc.add_assign(&term);
    }
    acc
}

/// Holds the shapes to the builder's polynomials: each $a$ is the shape's
/// sum, and each $b$ follows from the kind.
fn check<F: Field, Id: Copy>(
    shapes: &[Shape<Id, F>],
    poly: impl Fn(Id) -> sparse::Polynomial<F, TestR>,
    registry: &Registry<'_, F, TestR>,
    y: F,
    z: F,
    builder_a: &[Cow<'_, sparse::Polynomial<F, TestR>>],
    builder_b: &[Cow<'_, sparse::Polynomial<F, TestR>>],
) {
    assert_eq!(shapes.len(), builder_a.len());
    for (i, (shape, (a, b))) in shapes
        .iter()
        .zip(builder_a.iter().zip(builder_b))
        .enumerate()
    {
        let shaped = sum(&shape.a, &poly);
        assert_eq!(coeffs(&shaped), coeffs(a), "a of claim {i}");
        let expected = match shape.kind {
            Kind::Raw => sum(&shape.b, &poly),
            Kind::Circuit(circuit) => {
                assert!(shape.b.is_empty());
                let mut b = shaped;
                b.dilate(z);
                b.add_assign(&registry.circuit_y(circuit, y));
                b.add_assign(&TestR::tz(z));
                b
            }
            Kind::Bonding(circuit) => {
                assert!(shape.b.is_empty());
                registry.circuit_y(circuit, y)
            }
            Kind::Masked(_) => panic!("the builder lists no wire bindings"),
        };
        assert_eq!(coeffs(&expected), coeffs(b), "b of claim {i}");
    }
}

#[test]
fn native_shapes_match_the_decider() {
    let app = create_test_app();
    let pcd = app.bootstrap_pcd();
    let proof = pcd.proof();
    let mut rng = StdRng::seed_from_u64(1);
    let (y, z) = (
        Fp::random(|bytes| rng.fill_bytes(bytes)),
        Fp::random(|bytes| rng.fill_bytes(bytes)),
    );

    let mut builder = Builder::<_, Fp, TestR, ReferenceBackend>::new(&app.native_registry, y, z);
    native::claims::build(&NativePolys(proof), &mut builder).unwrap();

    let shapes = super::native_shapes(proof.circuit_ids(), z, &[]).unwrap();
    assert_eq!(shapes[0].kind, Kind::Raw);
    for (slot, id) in proof.circuit_ids().into_iter().enumerate() {
        assert_eq!(shapes[1 + slot].kind, Kind::Circuit(id));
    }
    check(
        &shapes,
        |component| proof[component].clone(),
        &app.native_registry,
        y,
        z,
        &builder.a,
        &builder.b,
    );
}

#[test]
fn nested_shapes_match_the_decider() {
    let app = create_test_app();
    let pcd = app.bootstrap_pcd();
    let proof = pcd.proof();
    let mut rng = StdRng::seed_from_u64(2);
    let (y, z) = (
        Fq::random(|bytes| rng.fill_bytes(bytes)),
        Fq::random(|bytes| rng.fill_bytes(bytes)),
    );

    let mut builder = Builder::<_, Fq, TestR, ReferenceBackend>::new(&app.nested_registry, y, z);
    nested::claims::build(&NestedPolys(proof), &mut builder).unwrap();

    let shapes = super::nested_shapes(z, &[]).unwrap();
    assert_eq!(shapes[0].kind, Kind::Raw);
    check(
        &shapes,
        |component| proof[component].clone(),
        &app.nested_registry,
        y,
        z,
        &builder.a,
        &builder.b,
    );
}

#[test]
fn wire_bindings_follow_the_claims() {
    let app = create_test_app();
    let proof = app.bootstrap_pcd().into_parts().0;
    let z = Fp::from(3);
    let poly = native::RxComponent::Rx(native::RxIndex::Eval);
    let masked = [Masked::new(
        poly,
        alloc::vec![2, 5],
        alloc::vec![Fp::ONE, Fp::ZERO],
        Fp::from(7),
    )];
    let shapes = super::native_shapes(proof.circuit_ids(), z, &masked).unwrap();
    let unmasked = super::native_shapes(proof.circuit_ids(), z, &[]).unwrap();
    assert_eq!(shapes.len(), unmasked.len() + 1);
    let last = shapes.last().unwrap();
    assert_eq!(last.kind, Kind::Masked(0));
    assert_eq!(last.a, alloc::vec![(Fp::ONE, poly)]);
    assert!(last.b.is_empty());
}

#[test]
#[should_panic(expected = "one value per wire")]
fn binding_rejects_a_missing_value() {
    let _ = Masked::<(), Fp>::new((), alloc::vec![0, 1], alloc::vec![Fp::ONE], Fp::ONE);
}

#[test]
#[should_panic(expected = "lists degree 3 twice")]
fn binding_rejects_a_repeated_degree() {
    let _ = Masked::<(), Fp>::new(
        (),
        alloc::vec![3, 3],
        alloc::vec![Fp::ONE, Fp::ONE],
        Fp::ONE,
    );
}
