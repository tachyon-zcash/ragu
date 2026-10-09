//! The instance of the bootstrap proof against the decider: the replayed
//! challenges are the proof's, the targets are the decider's, the recomputed
//! stages commit as claimed, every wire binding revdots to zero on the real
//! stages and evaluates from openings to what the polynomials give, and the
//! extra openings hold against the polynomials.

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::{ProductionRank, Rank, sparse};
use ragu_core::{
    Cycle,
    pasta::{Fp, Fq, Pasta},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::Instance;
use crate::{
    Application, ApplicationBuilder, Pcd, RAGU_TAG,
    compress::revdot::{
        claims::{self, Kind, Masked},
        fold::Derived,
    },
    internal::{ky, native, nested},
    ipa::CycleTranscript,
};

type TestR = ProductionRank;
const HEADER_SIZE: usize = 4;

fn create_test_app() -> Application<'static, Pasta, TestR, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .finalize(crate::pasta::baked())
        .expect("failed to create test application")
}

fn setup() -> (
    Application<'static, Pasta, TestR, HEADER_SIZE>,
    Pcd<Pasta, TestR, ()>,
    Instance<Pasta>,
) {
    let app = create_test_app();
    let pcd = app.bootstrap_pcd();
    let instance = Instance::of::<TestR, HEADER_SIZE>(pcd.proof()).unwrap();
    (app, pcd, instance)
}

/// The fuse's challenges, replayed on a transcript under the fuse's tag.
fn replay(instance: &Instance<Pasta>) -> nested::Challenges<Fp> {
    let mut transcript = CycleTranscript::<Pasta>::new(crate::pasta::baked(), RAGU_TAG).unwrap();
    instance
        .challenges(&mut transcript)
        .unwrap()
        .expect("pre_beta is in range")
}

#[test]
fn replays_the_proofs_challenges() {
    let (_, pcd, instance) = setup();
    let replayed = replay(&instance);
    assert_eq!(replayed.in_order(), pcd.proof().challenges().in_order());
}

#[test]
fn targets_match_the_decider() {
    let (_, pcd, instance) = setup();
    let challenges = replay(&instance);
    let mut rng = StdRng::seed_from_u64(1);
    let (y, nested_y) = (
        Fp::random(|bytes| rng.fill_bytes(bytes)),
        Fq::random(|bytes| rng.fill_bytes(bytes)),
    );

    let header = ky::output_header::<Pasta, (), HEADER_SIZE>(()).unwrap();
    let (native, nested) = instance
        .targets::<HEADER_SIZE>(&challenges, &header, y, nested_y)
        .unwrap();
    let expected = ky::native_ky::<Pasta, TestR, (), HEADER_SIZE>(&pcd, y).unwrap();
    assert_eq!(native.c, Some(pcd.proof().native_c()));
    assert_eq!(native.application, expected.application);
    assert_eq!(native.unified_bridge, expected.unified_bridge);
    assert_eq!(native.unified, expected.unified);
    assert_eq!(nested.c, pcd.proof().nested_c());
    assert_eq!(
        nested.unified,
        ky::nested_ky(pcd.proof(), nested_y).unwrap()
    );
}

#[test]
fn recomputed_stages_match() {
    let (_, _, instance) = setup();
    let challenges = replay(&instance);
    let generators = Pasta::nested_generators(crate::pasta::baked());
    assert!(
        instance
            .stages_match::<TestR, ReferenceBackend, HEADER_SIZE>(&challenges, generators)
            .unwrap()
    );

    let mut tampered = instance.clone();
    tampered.bridge_alpha += Fq::ONE;
    assert!(
        !tampered
            .stages_match::<TestR, ReferenceBackend, HEADER_SIZE>(&challenges, generators)
            .unwrap()
    );
}

/// Every masked claim revdots to zero on the real stage polynomials, and
/// its evaluation from openings at `r` is the polynomials' evaluation.
fn check_bindings<F, Id, R>(
    masked: &[Masked<Id, F>],
    poly: impl Fn(Id) -> sparse::Polynomial<F, R>,
    r: F,
) where
    F: Field,
    Id: Copy + core::fmt::Debug,
    R: Rank,
{
    for (i, claim) in masked.iter().enumerate() {
        let mut a = poly(claim.poly);
        a.sub_assign(&claim.expected::<R>());
        let b = claim.mask::<R>();
        assert_eq!(a.revdot(&b), F::ZERO, "binding {i} on {:?}", claim.poly);
        assert_eq!(a.eval(r), poly(claim.poly).eval(r) - claim.expected_at(r));
        assert_eq!(b.eval(r), claim.mask_at::<R>(r));
        assert!(!claim.wires.is_empty());
    }
}

#[test]
fn wire_bindings_hold() {
    let (app, pcd, instance) = setup();
    let proof = pcd.proof();
    let challenges = replay(&instance);
    let mut rng = StdRng::seed_from_u64(2);
    let (sigma, r) = (
        Fp::random(|bytes| rng.fill_bytes(bytes)),
        Fp::random(|bytes| rng.fill_bytes(bytes)),
    );
    let (nested_sigma, nested_r) = (
        Fq::random(|bytes| rng.fill_bytes(bytes)),
        Fq::random(|bytes| rng.fill_bytes(bytes)),
    );

    let native = instance
        .native_bindings::<TestR, ReferenceBackend, HEADER_SIZE>(
            &challenges,
            &app.native_registry,
            sigma,
        )
        .unwrap();
    assert_eq!(native.len(), 5);
    check_bindings(&native, |component| proof[component].clone(), r);

    let nested = instance
        .nested_bindings::<TestR, ReferenceBackend>(&challenges, &app.nested_registry, nested_sigma)
        .unwrap();
    assert_eq!(nested.len(), 3);
    check_bindings(&nested, |component| proof[component].clone(), nested_r);

    // The shapes append the bindings after the decider's claims, each over
    // its stage polynomial alone.
    let z = Fp::random(|bytes| rng.fill_bytes(bytes));
    let shapes = claims::native_shapes(instance.circuit_ids, z, &native).unwrap();
    let tail = &shapes[shapes.len() - native.len()..];
    for ((m, shape), masked) in tail.iter().enumerate().zip(&native) {
        assert_eq!(shape.kind, Kind::Masked(m));
        assert_eq!(shape.a, alloc::vec![(Fp::ONE, masked.poly)]);
        assert!(shape.b.is_empty());
    }

    // A wrong supplied wire breaks its binding.
    let mut wrong = instance.clone();
    wrong.a_at_u += Fp::ONE;
    let native = wrong
        .native_bindings::<TestR, ReferenceBackend, HEADER_SIZE>(
            &challenges,
            &app.native_registry,
            sigma,
        )
        .unwrap();
    let eval = native
        .iter()
        .find(|m| m.poly == native::RxComponent::Rx(native::RxIndex::Eval))
        .unwrap();
    let mut a = proof[eval.poly].clone();
    a.sub_assign(&eval.expected::<TestR>());
    assert_ne!(a.revdot(&eval.mask::<TestR>()), Fp::ZERO);
}

/// Every wire a binding lists is pinned from the polynomial's side: with
/// the instance left honest, raising the stage polynomial at that wire's
/// degree makes the binding's revdot nonzero, so a prover cannot move a
/// bound wire without moving the value the instance carries or the
/// registry gives. This is what the length and distinctness checks in
/// [`Masked::new`] protect: a wire dropped from the list would pass here.
fn check_pinned<F, Id, R>(masked: &[Masked<Id, F>], poly: impl Fn(Id) -> sparse::Polynomial<F, R>)
where
    F: Field,
    Id: Copy + core::fmt::Debug,
    R: Rank,
{
    for claim in masked {
        let mask = claim.mask::<R>();
        for &(degree, _) in &claim.wires {
            let mut bump = alloc::vec![F::ZERO; R::num_coeffs()];
            bump[degree] = F::ONE;
            let mut a = poly(claim.poly);
            a.add_assign(&sparse::Polynomial::from_coeffs(bump));
            a.sub_assign(&claim.expected::<R>());
            assert_ne!(
                a.revdot(&mask),
                F::ZERO,
                "the wire at degree {degree} of {:?} is not pinned",
                claim.poly
            );
        }
    }
}

#[test]
fn every_bound_wire_is_pinned() {
    let (app, pcd, instance) = setup();
    let proof = pcd.proof();
    let challenges = replay(&instance);
    let mut rng = StdRng::seed_from_u64(4);

    let native = instance
        .native_bindings::<TestR, ReferenceBackend, HEADER_SIZE>(
            &challenges,
            &app.native_registry,
            Fp::random(|bytes| rng.fill_bytes(bytes)),
        )
        .unwrap();
    check_pinned(&native, |component| proof[component].clone());

    let nested = instance
        .nested_bindings::<TestR, ReferenceBackend>(
            &challenges,
            &app.nested_registry,
            Fq::random(|bytes| rng.fill_bytes(bytes)),
        )
        .unwrap();
    check_pinned(&nested, |component| proof[component].clone());
}

#[test]
fn extra_openings_hold() {
    let (app, pcd, instance) = setup();
    let proof = pcd.proof();
    let challenges = replay(&instance);
    let mut rng = StdRng::seed_from_u64(3);
    let (w, nested_w) = (
        Fp::random(|bytes| rng.fill_bytes(bytes)),
        Fq::random(|bytes| rng.fill_bytes(bytes)),
    );
    let base = Derived::ALL.len() + 2;

    let (polys, claims) = instance.native_openings::<TestR, ReferenceBackend>(
        &challenges,
        &app.native_registry,
        w,
        base,
    );
    let (a, b) = (native::RxComponent::AbA, native::RxComponent::AbB);
    assert_eq!(polys[0], proof.native_registry_xy_commitment());
    assert_eq!(polys[1], proof.native_p_commitment());
    assert_eq!(polys[2], proof.native_commitment(a));
    assert_eq!(polys[3], proof.native_commitment(b));
    let opened = [
        proof.native_registry_xy_poly(),
        proof.native_p_poly(),
        &proof[a],
        &proof[b],
    ];
    assert_eq!(claims.len(), opened.len());
    for (i, claim) in claims.iter().enumerate() {
        assert_eq!(claim.poly, base + i);
        assert_eq!(
            claim.value,
            opened[i].eval(claim.point),
            "native opening {i}"
        );
    }
    assert_eq!(claims[1].value, proof.v());

    let (polys, claims) = instance
        .nested_openings::<TestR, ReferenceBackend>(
            &challenges,
            &app.nested_registry,
            nested_w,
            base,
        )
        .unwrap();
    let (a, b) = (nested::RxComponent::AbA, nested::RxComponent::AbB);
    assert_eq!(polys[0], proof.nested_registry_xy_commitment());
    assert_eq!(polys[1], proof.nested_p_commitment());
    assert_eq!(polys[2], proof.nested_a_commitment());
    assert_eq!(polys[3], proof.nested_b_commitment());
    let opened = [
        proof.nested_registry_xy_poly(),
        proof.nested_p_poly(),
        &proof[a],
        &proof[b],
    ];
    assert_eq!(claims.len(), opened.len());
    for (i, claim) in claims.iter().enumerate() {
        assert_eq!(claim.poly, base + i);
        assert_eq!(
            claim.value,
            opened[i].eval(claim.point),
            "nested opening {i}"
        );
    }
    assert_eq!(claims[1].value, proof.nested_v().unwrap());
}
