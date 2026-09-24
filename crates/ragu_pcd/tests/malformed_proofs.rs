//! Malformed proof data must be a rejection, not a panic or an internal error.
//! Mounted beneath `proof` to mutate private commitment caches as well as rxs.

use ragu_arithmetic::{
    group::CurveAffine,
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::Pasta;

use super::Proof;
use crate::{Application, ApplicationBuilder};

type TestApp = Application<'static, Pasta, ProductionRank, 4>;
type TestProof = Proof<Pasta, ProductionRank>;

fn fixture() -> (TestApp, TestProof) {
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(Pasta::baked())
        .expect("application must build");
    let pcd = app.bootstrap_pcd();
    assert!(
        app.verify(&pcd, StdRng::seed_from_u64(1234))
            .expect("valid bootstrap must not error"),
        "the unmodified proof must verify"
    );
    (app, pcd.into_parts().0)
}

fn assert_rejected(app: &TestApp, proof: TestProof, field: &str) {
    let result = app.verify(&proof.carry::<()>(()), StdRng::seed_from_u64(5678));
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

macro_rules! reject_identities {
    ($app:expr, $original:expr, $($field:ident $(.$member:tt)?),+ $(,)?) => {$({
        let mut proof = $original.clone();
        proof.$field$(.$member)? = CurveAffine::identity();
        assert_rejected(&$app, proof, stringify!($field$(.$member)?));
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
