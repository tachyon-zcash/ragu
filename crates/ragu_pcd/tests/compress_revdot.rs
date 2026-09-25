//! The revdot reduction on the bootstrap proof, both curves: an honest
//! reduction verifies and yields opening claims the prover's witness
//! satisfies, and a tampered opening or commitment is rejected.

use alloc::vec::Vec;

use ragu_arithmetic::{
    CurveAffine, Cycle, eval,
    ff::{Field, PrimeField},
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::{ProductionRank, sparse};
use ragu_pasta::{EqAffine, Fp, Fq, Pasta};

use super::{
    Openings, Reduction, Witness, native_components, nested_components, reduce_native,
    reduce_nested, verify_native, verify_nested,
};
use crate::{
    Application, ApplicationBuilder, Pcd, Proof,
    internal::{
        ky::{self, NativeKy, NestedKy},
        nested,
    },
    ipa::CycleTranscript,
};

type TestR = ProductionRank;
const HEADER_SIZE: usize = 4;
const TAG: &[u8] = b"ragu-test-revdot";

fn create_test_app() -> Application<'static, Pasta, TestR, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .finalize(Pasta::baked())
        .expect("failed to create test application")
}

fn transcript() -> CycleTranscript<'static, Pasta> {
    CycleTranscript::new(Pasta::baked(), TAG).unwrap()
}

/// The openings of an honest reduction hold against the prover's witness:
/// the components' openings are the polynomials' values, $p$ and $q$ open
/// as claimed, and $p(0)$ is the combined target.
fn check_openings<F, C>(
    openings: &Openings<C>,
    reduction: &Reduction<C>,
    witness: &Witness<F>,
    polys: &[&sparse::Polynomial<F, TestR>],
    z: F,
) where
    F: PrimeField,
    C: CurveAffine<ScalarExt = F>,
{
    let claims = &openings.claims;
    assert_eq!(openings.commitments.len(), polys.len() + 2);
    assert_eq!(claims.len(), 2 * polys.len() + 3);
    let r = witness.r;
    for (i, poly) in polys.iter().enumerate() {
        assert_eq!(claims[2 * i].poly, i);
        assert_eq!(claims[2 * i + 1].poly, i);
        assert_eq!(claims[2 * i].point, r);
        assert_eq!(claims[2 * i + 1].point, r * z);
        assert_eq!(claims[2 * i].value, poly.eval(r), "component {i} at r");
        assert_eq!(
            claims[2 * i + 1].value,
            poly.eval(r * z),
            "component {i} at rz"
        );
    }
    let (p, q) = (polys.len(), polys.len() + 1);
    assert_eq!(openings.commitments[p], reduction.p);
    assert_eq!(openings.commitments[q], reduction.q);
    let [at_inverse_r, q_at_r, at_zero] = &claims[2 * polys.len()..] else {
        unreachable!()
    };
    assert_eq!(at_inverse_r.poly, p);
    assert_eq!(at_inverse_r.value, eval(&witness.p, r.invert().unwrap()));
    assert_eq!(q_at_r.poly, q);
    assert_eq!(q_at_r.value, eval(&witness.q, r));
    assert_eq!(at_zero.poly, p);
    assert_eq!(at_zero.point, F::ZERO);
    assert_eq!(at_zero.value, witness.p[0], "p(0) is the combined target");
}

fn native_targets(pcd: &Pcd<Pasta, TestR, ()>, y: Fp) -> NativeKy<Fp> {
    NativeKy {
        c: Some(pcd.proof().native_c()),
        ..ky::native_ky::<Pasta, TestR, (), HEADER_SIZE>(pcd, y).unwrap()
    }
}

struct NativeRound {
    proof: Proof<Pasta, TestR>,
    y: Fp,
    z: Fp,
    reduction: Reduction<EqAffine>,
    witness: Witness<Fp>,
    targets: NativeKy<Fp>,
}

fn native_round(app: &Application<'static, Pasta, TestR, HEADER_SIZE>, seed: u64) -> NativeRound {
    let mut rng = StdRng::seed_from_u64(seed);
    let (y, z) = (Fp::random(&mut rng), Fp::random(&mut rng));
    let pcd = app.bootstrap_pcd();
    let targets = native_targets(&pcd, y);
    let proof = pcd.into_parts().0;
    let mut t = transcript();
    let (reduction, witness) = reduce_native::<Pasta, TestR, ReferenceBackend, _>(
        &proof,
        &app.native_registry,
        Pasta::host_generators(Pasta::baked()),
        y,
        z,
        &[],
        &mut t.host(),
    )
    .unwrap();
    NativeRound {
        proof,
        y,
        z,
        reduction,
        witness,
        targets,
    }
}

fn verify_native_round(
    app: &Application<'static, Pasta, TestR, HEADER_SIZE>,
    round: &NativeRound,
    reduction: &Reduction<EqAffine>,
) -> Option<Openings<EqAffine>> {
    let mut t = transcript();
    verify_native::<Pasta, TestR, _>(
        round.proof.circuit_id(),
        |component| round.proof.native_commitment(component),
        &app.native_registry,
        round.y,
        round.z,
        &round.targets,
        &[],
        reduction,
        &mut t.host(),
    )
    .unwrap()
}

#[test]
fn native_reduction_verifies() {
    let app = create_test_app();
    let round = native_round(&app, 1);
    let openings =
        verify_native_round(&app, &round, &round.reduction).expect("the honest reduction holds");
    let polys: Vec<_> = native_components().map(|c| &round.proof[c]).collect();
    check_openings(&openings, &round.reduction, &round.witness, &polys, round.z);
    let generators = Pasta::host_generators(Pasta::baked());
    assert_eq!(
        round.reduction.p,
        sparse::Polynomial::<Fp, TestR>::from_coeffs(round.witness.p.clone())
            .commit_to_affine(generators)
    );
}

#[test]
fn native_reduction_rejects_tampering() {
    let app = create_test_app();
    let round = native_round(&app, 2);

    let mut tampered = round.reduction.clone();
    tampered.openings[5].at_rz += Fp::ONE;
    assert!(verify_native_round(&app, &round, &tampered).is_none());

    let mut tampered = round.reduction.clone();
    tampered.p_at_inverse_r += Fp::ONE;
    assert!(verify_native_round(&app, &round, &tampered).is_none());

    // A different commitment moves r, so the openings no longer match.
    let mut tampered = round.reduction.clone();
    tampered.q = tampered.p;
    assert!(verify_native_round(&app, &round, &tampered).is_none());
}

#[test]
fn nested_reduction_verifies() {
    let app = create_test_app();
    let pcd = app.bootstrap_pcd();
    let proof = pcd.proof();
    let mut rng = StdRng::seed_from_u64(3);
    let (y, z) = (Fq::random(&mut rng), Fq::random(&mut rng));
    let generators = Pasta::nested_generators(Pasta::baked());

    let mut t = transcript();
    let (reduction, witness) = reduce_nested::<Pasta, TestR, ReferenceBackend, _>(
        proof,
        &app.nested_registry,
        generators,
        y,
        z,
        &[],
        &mut t.nested(),
    )
    .unwrap();

    let targets = NestedKy {
        c: proof.nested_c(),
        unified: ky::nested_ky(proof, y).unwrap(),
    };
    let commitment = |component| match component {
        nested::RxComponent::AbA => proof.nested_a_commitment(),
        nested::RxComponent::AbB => proof.nested_b_commitment(),
        nested::RxComponent::Rx(index) => proof.nested_rx_commitment(index),
    };
    let verify = |reduction: &Reduction<_>| {
        let mut t = transcript();
        verify_nested::<Pasta, TestR, _>(
            commitment,
            &app.nested_registry,
            y,
            z,
            &targets,
            &[],
            reduction,
            &mut t.nested(),
        )
        .unwrap()
    };

    let openings = verify(&reduction).expect("the honest reduction holds");
    let polys: Vec<_> = nested_components().map(|c| &proof[c]).collect();
    check_openings(&openings, &reduction, &witness, &polys, z);

    let mut tampered = reduction;
    tampered.openings[0].at_r += Fq::ONE;
    assert!(verify(&tampered).is_none());
}
