//! The revdot reduction on the bootstrap proof, both curves: an honest
//! reduction verifies and yields opening claims the prover's witness
//! satisfies over the commitments the verifier derives, and a tampered
//! message is rejected.

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::{ProductionRank, sparse};
use ragu_core::{
    Cycle, FixedGenerators,
    pasta::{Fp, Fq, Pasta},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::{curve::Affine, field::Field, polynomial::evaluate_iter};

type EqAffine = <Pasta as Cycle>::HostCurve;

use super::{
    Openings, Reduction,
    fold::{Derived, GROUP, Layout},
    prover::Witness,
    reduce_native, reduce_nested, verify_native, verify_nested,
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
        .finalize(crate::pasta::baked())
        .expect("failed to create test application")
}

fn transcript() -> CycleTranscript<'static, Pasta> {
    CycleTranscript::new(crate::pasta::baked(), TAG).unwrap()
}

/// The openings of an honest reduction hold against the prover's witness:
/// the commitments are the derived polynomials', which the verifier
/// derived independently, each opening is the polynomial's value at its
/// point, $p$ and $q$ open as claimed, and $p(0)$ is the combined target.
fn check_openings<F, C>(
    openings: &Openings<C>,
    reduction: &Reduction<C>,
    witness: &Witness<C, TestR>,
    generators: &impl FixedGenerators<C>,
    z: F,
) where
    F: Field,
    C: Affine<Scalar = F>,
{
    let claims = &openings.claims;
    let derived = Derived::ALL.len();
    assert_eq!(witness.derived.len(), derived);
    assert_eq!(openings.commitments.len(), derived + 2);
    assert_eq!(claims.len(), derived + 3);
    let r = witness.r;
    for (i, (which, poly)) in Derived::ALL.iter().zip(&witness.derived).enumerate() {
        assert_eq!(
            openings.commitments[i],
            poly.commit_to_affine(generators),
            "{which:?} derives as committed"
        );
        assert_eq!(claims[i].poly, i);
        assert_eq!(claims[i].point, which.point(r, z));
        assert_eq!(
            claims[i].value,
            poly.eval(claims[i].point),
            "{which:?} at its point"
        );
    }
    assert_eq!(
        openings.commitments[Derived::Inner as usize],
        reduction.fold.inner
    );
    assert_eq!(
        openings.commitments[Derived::Outer as usize],
        reduction.fold.outer
    );
    let (p, q) = (derived, derived + 1);
    assert_eq!(openings.commitments[p], reduction.p);
    assert_eq!(openings.commitments[q], reduction.q);
    let [at_inverse_r, q_at_r, at_zero] = &claims[derived..] else {
        unreachable!()
    };
    assert_eq!(at_inverse_r.poly, p);
    assert_eq!(
        at_inverse_r.value,
        evaluate_iter(&witness.p, r.invert().unwrap())
    );
    assert_eq!(q_at_r.poly, q);
    assert_eq!(q_at_r.value, evaluate_iter(&witness.q, r));
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
    witness: Witness<EqAffine, TestR>,
    targets: NativeKy<Fp>,
}

fn native_round(app: &Application<'static, Pasta, TestR, HEADER_SIZE>, seed: u64) -> NativeRound {
    let mut rng = StdRng::seed_from_u64(seed);
    let (y, z) = (
        Fp::random(|bytes| rng.fill_bytes(bytes)),
        Fp::random(|bytes| rng.fill_bytes(bytes)),
    );
    let pcd = app.bootstrap_pcd();
    let targets = native_targets(&pcd, y);
    let proof = pcd.into_parts().0;
    let mut t = transcript();
    let (reduction, witness) = reduce_native::<Pasta, TestR, ReferenceBackend>(
        &proof,
        &app.native_registry,
        Pasta::host_generators(crate::pasta::baked()),
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
    verify_native::<Pasta, TestR, ReferenceBackend>(
        round.proof.circuit_ids(),
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
    let generators = Pasta::host_generators(crate::pasta::baked());
    check_openings(
        &openings,
        &round.reduction,
        &round.witness,
        generators,
        round.z,
    );
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

    // A wrong weighted error sum moves the folded target.
    let mut tampered = round.reduction.clone();
    tampered.fold.inner_epsilon += Fp::ONE;
    assert!(verify_native_round(&app, &round, &tampered).is_none());

    // A different error commitment moves the weights, so the folded
    // openings no longer match.
    let mut tampered = round.reduction.clone();
    tampered.fold.outer = tampered.fold.inner;
    assert!(verify_native_round(&app, &round, &tampered).is_none());

    let mut tampered = round.reduction.clone();
    tampered.openings[Derived::Dilated as usize] += Fp::ONE;
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
fn layout_groups_the_claims() {
    let layout = Layout::new(2 * GROUP + 3);
    assert_eq!(layout.groups(), 3);
    assert_eq!(layout.members(0), 0..GROUP);
    assert_eq!(layout.members(2), 2 * GROUP..2 * GROUP + 3);
    assert_eq!(layout.inner().count(), 2 * GROUP * (GROUP - 1) + 3 * 2);
    assert_eq!(layout.outer().count(), 6);
    assert_eq!(layout.inner().next(), Some((0, 0, 1)));
    assert_eq!(layout.inner().nth(GROUP - 1), Some((0, 1, 0)));
    assert_eq!(layout.outer().last(), Some((2, 1)));
}

#[test]
fn nested_reduction_verifies() {
    let app = create_test_app();
    let pcd = app.bootstrap_pcd();
    let proof = pcd.proof();
    let mut rng = StdRng::seed_from_u64(3);
    let (y, z) = (
        Fq::random(|bytes| rng.fill_bytes(bytes)),
        Fq::random(|bytes| rng.fill_bytes(bytes)),
    );
    let generators = Pasta::nested_generators(crate::pasta::baked());

    let mut t = transcript();
    let (reduction, witness) = reduce_nested::<Pasta, TestR, ReferenceBackend>(
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
        verify_nested::<Pasta, TestR, ReferenceBackend>(
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
    check_openings(&openings, &reduction, &witness, generators, z);

    let mut tampered = reduction;
    tampered.openings[Derived::A as usize] += Fq::ONE;
    assert!(verify(&tampered).is_none());
}

/// The reduction reads each circuit's restriction as the registry point
/// $m(\omega^i, r, y)$. It must equal the restriction $s_i(X, y)$ the
/// decider's claim builder materializes, evaluated at $r$, for every circuit
/// the claims name on either registry: the internal circuits and the stage
/// masks, and natively the application circuit as well.
#[test]
fn point_restriction_matches_the_materialized_one() {
    use ragu_backend::Backend;
    use ragu_circuits::{
        polynomials::Rank,
        registry::{CircuitIndex, Registry},
    };

    use crate::internal::native;

    fn check<F: Field, R: Rank>(
        registry: &Registry<'_, F, R>,
        circuits: impl IntoIterator<Item = CircuitIndex>,
        rng: &mut StdRng,
    ) {
        let (r, y) = (
            F::random(|bytes| rng.fill_bytes(bytes)),
            F::random(|bytes| rng.fill_bytes(bytes)),
        );
        for circuit in circuits {
            let materialized = ReferenceBackend::sparse_eval(
                &ReferenceBackend::registry_circuit_y(registry, circuit, y),
                r,
            );
            let point = ReferenceBackend::registry_wxy(registry, circuit.omega_j(), r, y);
            assert_eq!(materialized, point, "circuit {}", usize::from(circuit));
        }
    }

    let app = create_test_app();
    let mut rng = StdRng::seed_from_u64(4);
    let circuit_id = app.bootstrap_pcd().proof().circuit_id();
    check(
        &app.native_registry,
        native::InternalCircuitIndex::ALL
            .iter()
            .map(|id| id.circuit_index())
            .chain([circuit_id]),
        &mut rng,
    );
    check(
        &app.nested_registry,
        nested::InternalCircuitIndex::ALL
            .iter()
            .map(|id| id.circuit_index()),
        &mut rng,
    );
}
