//! Malformed proof data must be a rejection, not a panic or an internal error.
//! Mounted beneath `proof` to mutate private commitment caches as well as rxs.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::pasta::Pasta;
use rand::{SeedableRng, rngs::StdRng};
use udon::curve::Affine as CurveAffine;

use super::Proof;
use crate::{
    Application, ApplicationBuilder,
    wire::{self, Decode, Dimensions, Encode},
};

type TestApp = Application<'static, Pasta, ProductionRank, 4>;
type TestProof = Proof<Pasta, ProductionRank>;

fn fixture() -> (TestApp, TestProof) {
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(crate::pasta::baked())
        .expect("application must build");
    let pcd = app.bootstrap_pcd();
    assert!(
        app.verify_uncompressed(&pcd, StdRng::seed_from_u64(1234))
            .expect("valid bootstrap must not error"),
        "the unmodified proof must verify"
    );
    (app, pcd.into_parts().0)
}

/// `proof` and its deserialized counterpart, whose derived fields are not
/// yet set, must both fail the checks that precede derivation.
fn assert_prepare_rejects(app: &TestApp, proof: &TestProof, field: &str) {
    let mut deserialized = proof.clone();
    deserialized.complete = false;
    for (proof, which) in [(proof, "in memory"), (&deserialized, "deserialized")] {
        assert!(
            matches!(app.prepare(proof), Err(ragu_core::Error::InvalidWitness(_))),
            "{field} ({which}): preparation must reject before derivation"
        );
    }
}

// A vector of another length has no encoding (debug builds assert while
// encoding it) and a payload of another length is rejected before a byte is
// interpreted, so malformed shapes are checked at the in-memory boundaries.
fn assert_rejected(app: &TestApp, proof: TestProof, field: &str) {
    assert!(
        !proof.well_formed::<4>(),
        "{field}: the shape check must fail"
    );
    assert_prepare_rejects(app, &proof, field);
    let result = app.verify_uncompressed(&proof.carry::<()>(()), StdRng::seed_from_u64(5678));
    assert!(
        matches!(&result, Ok(false)),
        "{field}: expected Ok(false), got {result:?}"
    );
}

#[test]
fn rejects_malformed_vector_lengths() {
    let (app, original) = fixture();
    macro_rules! reject_lengths {
        ($($field:ident),+ $(,)?) => {$({
            let len = original.$field.len();
            for malformed_len in [0, len - 1, len + 1] {
                let mut proof = original.clone();
                proof.$field.resize(malformed_len, original.$field[0].clone());
                assert_rejected(&app, proof, stringify!($field));
            }
        })+};
    }
    reject_lengths!(
        native_bind_challenges_rxs,
        native_bind_challenges_commitments,
        native_endoscaling_step_rxs,
        native_endoscaling_step_commitments,
        nested_endoscaling_step_rxs,
        nested_endoscaling_step_commitments,
    );
}

// The identity has an encoding, which the decoder rejects; in memory the
// verifier rejects it, as it allocates every point by its coordinates.
fn assert_identity_rejected(app: &TestApp, proof: TestProof, field: &str) {
    assert!(
        !proof.well_formed::<4>(),
        "{field}: retained point preflight must reject identity"
    );
    assert!(
        app.proof_format(crate::ProofContext {
            suite: [0; 32],
            application: [0; 32]
        })
        .encode(&proof)
        .is_err()
    );
    let bytes = proof.to_bytes();
    let Err(wire::Error::Invalid { reason, .. }) =
        TestProof::from_bytes(&bytes, Dimensions::of::<ProductionRank, 4>())
    else {
        panic!("{field}: expected the decoder to reject the identity")
    };
    assert_eq!(reason, "identity point", "{field}");
    assert_prepare_rejects(app, &proof, field);
    let result = app.verify_uncompressed(&proof.carry::<()>(()), StdRng::seed_from_u64(5678));
    assert!(
        matches!(&result, Ok(false)),
        "{field}: expected Ok(false), got {result:?}"
    );
}

macro_rules! reject_identities {
    ($app:expr, $original:expr, $($field:ident $(.$member:tt)?),+ $(,)?) => {$({
        let mut proof = $original.clone();
        proof.$field$(.$member)? = CurveAffine::identity();
        assert_identity_rejected(&$app, proof, stringify!($field$(.$member)?));
    })+};
}

#[test]
fn rejects_identity_bridge_commitments() {
    let (app, original) = fixture();
    reject_identities!(
        app,
        original,
        bridge_preamble_commitment,
        bridge_s_prime_commitment,
        bridge_inner_error_commitment,
        bridge_outer_error_commitment,
        bridge_ab_commitment.0,
        bridge_query_commitment,
        bridge_f_commitment,
        bridge_eval_commitment,
    );
}

#[test]
fn rejects_identity_instance_commitments() {
    let (app, original) = fixture();
    reject_identities!(
        app,
        original,
        nested_challenges_partial,
        nested_p_commitment.0,
        nested_a_commitment.0,
        nested_b_commitment.0,
        nested_registry_xy_commitment.0,
        native_preamble_commitment.0,
        native_inner_error_commitment.0,
        native_outer_error_commitment.0,
        native_query_commitment.0,
        native_eval_commitment.0,
        native_a_commitment.0,
        native_b_commitment.0,
        native_registry_xy_commitment.0,
        native_p_commitment.0,
        native_points_binding_commitment.0,
        native_points_children_commitment.0,
        native_points_registry_wx_commitment.0,
        native_points_ab_commitment.0,
        native_points_f_commitment.0,
    );
}

#[test]
fn rejects_malformed_child_header_lengths() {
    let (app, original) = fixture();
    for left in [true, false] {
        for length in [0, 3, 5] {
            let mut proof = original.clone();
            let header = if left {
                &mut proof.left_header
            } else {
                &mut proof.right_header
            };
            header.resize(length, header[0]);
            assert_rejected(
                &app,
                proof,
                if left { "left_header" } else { "right_header" },
            );
        }
    }
}

#[test]
fn prepare_rejects_out_of_domain_circuit_before_derivation_or_compression() {
    let (app, mut proof) = fixture();
    proof.circuit_id = ragu_circuits::registry::CircuitIndex::from_u32(u32::MAX);
    assert_prepare_rejects(&app, &proof, "circuit id");
    let pcd = proof.carry::<()>(());
    assert!(matches!(
        app.compress(&pcd, &mut StdRng::seed_from_u64(1)),
        Err(ragu_core::Error::InvalidWitness(_))
    ));
    assert!(matches!(
        app.verify_uncompressed(&pcd, StdRng::seed_from_u64(1)),
        Ok(false)
    ));
}

#[test]
fn prepare_rejects_unliftable_challenges_of_an_in_memory_proof() {
    use udon::field::Field;
    let (app, mut proof) = fixture();
    proof.w = -ragu_core::pasta::Fp::ONE;
    let pcd = proof.carry::<()>(());
    assert!(matches!(
        app.compress(&pcd, &mut StdRng::seed_from_u64(1)),
        Err(ragu_core::Error::InvalidWitness(_))
    ));
    assert!(matches!(
        app.verify_uncompressed(&pcd, StdRng::seed_from_u64(1)),
        Ok(false)
    ));
}
