//! A proof's encoding must preserve every field and reject malformed protocol
//! layouts.

use alloc::vec::Vec;

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::pasta::Pasta;
use rand::{SeedableRng, rngs::StdRng};

use super::Proof;
use crate::{
    ApplicationBuilder,
    wire::{Dimensions, Encode, Error},
};

type TestProof = Proof<Pasta, ProductionRank>;

#[test]
fn decoded_proof_equals_the_original_and_rejects_wrong_vector_lengths() {
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(crate::pasta::baked())
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let pcd = app.bootstrap_pcd();
    assert!(app.verify_uncompressed(&pcd, &mut rng).unwrap());
    let (proof, ()) = pcd.into_parts();
    let bytes = proof.to_bytes().unwrap();
    let decoded = TestProof::from_bytes(&bytes).unwrap();
    // Decoding restores every field, and the proof re-encodes to itself.
    assert_eq!(proof.test_mismatch(&decoded), None);
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
    assert!(
        app.verify_uncompressed(&decoded.carry::<()>(()), &mut rng)
            .unwrap()
    );

    // Each vector has a protocol-fixed length, so a vector of another length
    // changes the total and is rejected before any byte is interpreted.
    // Encoding refuses other counts; use the raw byte layout.
    let dims = Dimensions::of::<ProductionRank, 4>();
    macro_rules! reject_lengths {
        ($($field:ident),* $(,)?) => {$(
            let element = {
                let mut bytes = Vec::new();
                proof.$field[0].encode(&mut bytes, dims).unwrap();
                bytes
            };
            for extra in [false, true] {
                let mut malformed = bytes.clone();
                if extra {
                    malformed.extend_from_slice(&element);
                } else {
                    malformed.truncate(malformed.len() - element.len());
                }
                assert!(
                    matches!(TestProof::from_bytes(&malformed),
                        Err(Error::Length { expected, actual })
                            if expected == bytes.len() && actual == malformed.len()),
                    "{} (extra: {extra})", stringify!($field),
                );
            }
        )*};
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

#[cfg(feature = "serde")]
#[test]
fn a_proof_of_another_shape_has_no_serialization() {
    use alloc::string::ToString;

    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(crate::pasta::baked())
        .unwrap();
    let mut proof = app.bootstrap_pcd().into_parts().0;
    // The headers no longer share a length, so no envelope describes them.
    let element = proof.left_header[0];
    proof.left_header.push(element);
    let error = serde_json::to_string(&proof).unwrap_err();
    assert!(error.to_string().contains("no encoding"), "{error}");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "production-rank recursive proof")]
fn decoded_child_remains_usable_by_fuse() {
    use ragu_core::pasta::Fp;

    use crate::proof::recursive_propagation_tests::support::{Merge, Seed, Value, with_app};

    with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0xdec0de);
        let (child, ()) = app.seed(&mut rng, Seed::new(), Fp::from(7)).unwrap();
        let (proof, data) = child.into_parts();
        let decoded = TestProof::from_bytes(&proof.to_bytes().unwrap()).unwrap();
        let child = decoded.carry::<Value>(data);
        let compressed_child = app.compress(&child, &mut rng).unwrap();
        assert!(app.verify_compressed(&compressed_child).unwrap());
        let (parent, ()) = app
            .fuse(&mut rng, Merge::new(), Fp::from(11), child.clone(), child)
            .unwrap();
        let compressed_parent = app.compress(&parent, &mut rng).unwrap();
        assert!(app.verify_compressed(&compressed_parent).unwrap());
        assert!(app.verify_uncompressed(&parent, &mut rng).unwrap());
    });
}

/// A stored bootstrap proof, decoded and supplied to a new application, is
/// installed as given instead of being built, and proofs built on it verify.
/// A proof of another shape or of another step is refused.
#[test]
#[cfg_attr(debug_assertions, ignore = "production-rank recursive proof")]
fn a_supplied_bootstrap_proof_replaces_the_bootstrap_fuse() {
    use ragu_core::pasta::Fp;

    use crate::{
        proof::recursive_propagation_tests::support::{Seed, app_builder},
        step::internal::bootstrap::Bootstrap,
    };

    // A valid bootstrap proof other than the one finalization builds, from
    // another seed, so the installed proof can be told from a built one.
    let source = app_builder()
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap();
    let (other, ()) = source
        .fuse(
            &mut StdRng::seed_from_u64(1),
            Bootstrap::new(),
            (),
            source.dummy_pcd(),
            source.dummy_pcd(),
        )
        .unwrap();
    let stored = other.into_parts().0.to_bytes().unwrap();
    assert_ne!(stored, source.bootstrap_proof().to_bytes().unwrap());

    let app = app_builder()
        .unwrap()
        .with_bootstrap(TestProof::from_bytes(&stored).unwrap())
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap();
    assert_eq!(
        app.bootstrap_proof().to_bytes().unwrap(),
        stored,
        "finalization installs the supplied proof as given"
    );

    let mut rng = StdRng::seed_from_u64(0xb007);
    let (leaf, _) = app.seed(&mut rng, Seed::new(), Fp::from(7)).unwrap();
    assert!(app.verify_differential(&leaf, &mut rng).unwrap());

    // Refused: a proof of another shape, and a proof of another step.
    let mut short = TestProof::from_bytes(&stored).unwrap();
    short.left_header.pop();
    assert!(app_builder().unwrap().with_bootstrap(short).is_err());
    assert!(
        app_builder()
            .unwrap()
            .with_bootstrap(leaf.into_parts().0)
            .is_err()
    );
}
