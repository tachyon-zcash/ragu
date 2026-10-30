//! A proof's encoding must preserve the fields it retains, leave the derived
//! ones to the application, and reject malformed protocol layouts.

use alloc::vec::Vec;

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::pasta::Pasta;
use rand::{SeedableRng, rngs::StdRng};

use super::Proof;
use crate::{
    ApplicationBuilder,
    wire::{Decode, Dimensions, Encode, Error},
};

type TestProof = Proof<Pasta, ProductionRank>;

fn dims() -> Dimensions {
    Dimensions::of::<ProductionRank, 4>()
}

#[test]
fn decoded_proof_derives_its_omitted_fields_and_rejects_wrong_vector_lengths() {
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(crate::pasta::baked())
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let pcd = app.bootstrap_pcd();
    assert!(app.verify_uncompressed(&pcd, &mut rng).unwrap());
    let (proof, ()) = pcd.into_parts();
    let bytes = proof.to_bytes();
    let decoded = TestProof::from_bytes(&bytes, dims()).unwrap();
    // The encoding holds the retained fields alone, and re-encodes to itself.
    assert!(!decoded.complete);
    assert_eq!(decoded.to_bytes(), bytes);
    // Preparing derives every other field, equal to the original's.
    let (prepared, _) = app.prepare(&decoded).unwrap();
    assert_eq!(proof.test_mismatch(&prepared), None);
    assert!(
        app.verify_uncompressed(&decoded.carry::<()>(()), &mut rng)
            .unwrap()
    );

    // Each vector has a protocol-fixed length, so a vector of another length
    // changes the total and is rejected before any byte is interpreted.
    // Debug builds assert the length while encoding; use the raw byte layout.
    macro_rules! reject_lengths {
        ($($field:ident),* $(,)?) => {$(
            let element = {
                let mut bytes = Vec::new();
                proof.$field[0].encode(&mut bytes);
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
                    matches!(TestProof::from_bytes(&malformed, dims()),
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

#[test]
#[should_panic(expected = "read before the application derived it")]
fn a_decoded_proofs_derived_fields_cannot_be_read_before_they_are_derived() {
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(crate::pasta::baked())
        .unwrap();
    let proof = app.bootstrap_pcd().into_parts().0;
    let decoded = TestProof::from_bytes(&proof.to_bytes(), dims()).unwrap();
    let _ = decoded.x();
}

#[test]
fn decoded_verification_preserves_header_encoding_errors() {
    use ragu_core::{
        Error, Result,
        drivers::{Driver, DriverValue},
        gadgets::Bound,
    };
    use ragu_primitives::allocator::Allocator;
    use udon::field::Field;

    use crate::header::{Header, Suffix};

    struct BrokenHeader;
    impl<F: Field> Header<F> for BrokenHeader {
        const SUFFIX: Suffix = <() as Header<F>>::SUFFIX;
        type Data = ();
        type Output = ();

        fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
            _: &mut D,
            _: &mut A,
            _: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Err(Error::ConstraintBoundExceeded { limit: 42 })
        }
    }

    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(crate::pasta::baked())
        .unwrap();
    let proof = app.bootstrap_pcd().into_parts().0;
    let decoded = TestProof::from_bytes(&proof.to_bytes(), dims()).unwrap();
    assert!(matches!(
        app.verify_uncompressed(
            &decoded.carry::<BrokenHeader>(()),
            StdRng::seed_from_u64(0x5eed)
        ),
        Err(Error::ConstraintBoundExceeded { limit: 42 })
    ));
}

#[cfg(feature = "serde")]
#[test]
fn a_proof_of_another_shape_has_no_serialization() {
    use alloc::string::ToString;

    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(crate::pasta::baked())
        .unwrap();
    let mut proof = app.bootstrap_pcd().into_parts().0;
    // The headers no longer share a length, so no prelude describes them.
    let element = proof.left_header[0];
    proof.left_header.push(element);
    let error = serde_json::to_string(&proof).unwrap_err();
    assert!(error.to_string().contains("its type's shape"), "{error}");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "production-rank recursive proof")]
fn decoded_child_remains_usable_by_fuse() {
    use super::recursive_propagation_tests::support::{Merge, Seed, Value, with_app};
    use ragu_core::pasta::Fp;

    with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0xdec0de);
        let (child, ()) = app.seed(&mut rng, Seed::new(), Fp::from(7)).unwrap();
        let (proof, data) = child.into_parts();
        let decoded = TestProof::from_bytes(&proof.to_bytes(), dims()).unwrap();
        let child = decoded.carry::<Value>(data);
        let compressed_child = app.compress(&child, &mut rng).unwrap();
        assert!(app.verify_compressed(&compressed_child).unwrap());
        let (parent, ()) = app
            .fuse(&mut rng, Merge::new(), Fp::from(11), child.clone(), child)
            .unwrap();
        let compressed_parent = app.compress(&parent, &mut rng).unwrap();
        assert!(app.verify_compressed(&compressed_parent).unwrap());
    });
}
