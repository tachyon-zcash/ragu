//! The instance of the bootstrap proof against the decider: the replayed
//! challenges are the proof's, the targets are the decider's, the recomputed
//! stages commit as claimed, every wire binding revdots to zero on the real
//! stages and evaluates from openings to what the polynomials give, and the
//! extra openings hold against the polynomials.

use alloc::vec::Vec;

use ragu_arithmetic::{
    Cycle,
    ff::Field,
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::{ProductionRank, Rank, sparse};
use ragu_pasta::{Fp, Fq, Pasta};

use super::Instance;
use crate::{
    Application, ApplicationBuilder, Pcd, RAGU_TAG,
    compress::{
        claims::{self, Masked, Opened},
        revdot::{Witness, native_components, nested_components},
    },
    internal::{ky, native, nested},
    ipa::CycleTranscript,
};

type TestR = ProductionRank;
const HEADER_SIZE: usize = 4;

fn create_test_app() -> Application<'static, Pasta, TestR, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .finalize(Pasta::baked())
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
    let mut transcript = CycleTranscript::<Pasta>::new(Pasta::baked(), RAGU_TAG).unwrap();
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
    let (y, nested_y) = (Fp::random(&mut rng), Fq::random(&mut rng));

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
    let generators = Pasta::nested_generators(Pasta::baked());
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
    F: ragu_arithmetic::ff::PrimeField + ragu_arithmetic::DeferredField,
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
    let (sigma, r) = (Fp::random(&mut rng), Fp::random(&mut rng));
    let (nested_sigma, nested_r) = (Fq::random(&mut rng), Fq::random(&mut rng));

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

    // The evaluator appends the bindings after the decider's claims, as
    // (a(r), b(r), 0).
    let (y, z) = (Fp::random(&mut rng), Fp::random(&mut rng));
    let header = ky::output_header::<Pasta, (), HEADER_SIZE>(()).unwrap();
    let targets = instance
        .targets::<HEADER_SIZE>(&challenges, &header, y, Fq::ONE)
        .unwrap()
        .0;
    let evaluated = claims::native::<TestR, _>(
        instance.circuit_id,
        r,
        z,
        |component| Opened {
            at_r: proof[component].eval(r),
            at_rz: proof[component].eval(r * z),
        },
        |circuit| app.native_registry.circuit_y(circuit, y).eval(r),
        &targets,
        &native,
    )
    .unwrap();
    let tail = &evaluated[evaluated.len() - native.len()..];
    for (claim, masked) in tail.iter().zip(&native) {
        let mut a = proof[masked.poly].clone();
        a.sub_assign(&masked.expected::<TestR>());
        assert_eq!(claim.a, a.eval(r));
        assert_eq!(claim.b, masked.mask::<TestR>().eval(r));
        assert_eq!(claim.k, Fp::ZERO);
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

#[test]
fn extra_openings_hold() {
    let (app, pcd, instance) = setup();
    let proof = pcd.proof();
    let challenges = replay(&instance);
    let mut rng = StdRng::seed_from_u64(3);
    let (w, nested_w) = (Fp::random(&mut rng), Fq::random(&mut rng));

    let base = native_components().count() + 2;
    let (polys, claims) = instance.native_openings::<TestR, ReferenceBackend>(
        &challenges,
        &app.native_registry,
        w,
        base,
    );
    assert_eq!(polys[0], proof.native_registry_xy_commitment());
    assert_eq!(polys[1], proof.native_p_commitment());
    let value = |claim: &crate::compress::revdot::OpeningClaim<Fp>| match claim.poly {
        p if p == base => proof.native_registry_xy_poly().eval(claim.point),
        p if p == base + 1 => proof.native_p_poly().eval(claim.point),
        p => native_components()
            .nth(p)
            .map(|c| proof[c].eval(claim.point))
            .unwrap(),
    };
    for claim in &claims {
        assert_eq!(
            claim.value,
            value(claim),
            "native opening at {:?}",
            claim.point
        );
    }
    assert_eq!(claims[1].value, proof.v());

    let base = nested_components().count() + 2;
    let (polys, claims) = instance
        .nested_openings::<TestR, ReferenceBackend>(
            &challenges,
            &app.nested_registry,
            nested_w,
            base,
        )
        .unwrap();
    assert_eq!(polys[0], proof.nested_registry_xy_commitment());
    assert_eq!(polys[1], proof.nested_p_commitment());
    let value = |claim: &crate::compress::revdot::OpeningClaim<Fq>| match claim.poly {
        p if p == base => proof.nested_registry_xy_poly().eval(claim.point),
        p if p == base + 1 => proof.nested_p_poly().eval(claim.point),
        p => nested_components()
            .nth(p)
            .map(|c| proof[c].eval(claim.point))
            .unwrap(),
    };
    for claim in &claims {
        assert_eq!(
            claim.value,
            value(claim),
            "nested opening at {:?}",
            claim.point
        );
    }
    assert_eq!(claims[1].value, proof.nested_v().unwrap());
    let _: Vec<Witness<Fp>> = Vec::new();
}
