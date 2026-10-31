//! Proofs and compressed proofs serialize as one byte string in every serde
//! format: a prelude recording the rank and header size, then the payload the
//! application's envelope carries.

use ragu_pcd::{CompressedProof, Proof, ProofContext};
use ragu_testing::pcd::nontrivial::LeafNode;
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, de::value::BorrowedBytesDeserializer};

#[allow(dead_code)]
mod nontrivial_support;
use nontrivial_support::{C, R, app, leaf};

/// The codec version byte, then the rank as a `u32` and the header size as a
/// `u64`, little-endian: 13 and 4 for these proofs.
const PRELUDE: [u8; 13] = [1, 13, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0];
/// The envelope `ProofFormat` puts ahead of the same payload.
const ENVELOPE: usize = 124;

fn context() -> ProofContext {
    ProofContext {
        suite: [0x53; 32],
        application: [0x41; 32],
    }
}

#[test]
fn a_proof_serializes_as_its_payload_behind_a_prelude() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let json = serde_json::to_string(&proof).unwrap();
    // JSON has no bytes type; the array of numbers is the byte string.
    let bytes: Vec<u8> = serde_json::from_str(&json).unwrap();
    assert_eq!(&bytes[..PRELUDE.len()], &PRELUDE);
    let envelope = app.proof_format(context()).encode(&proof).unwrap();
    assert_eq!(&bytes[PRELUDE.len()..], &envelope[ENVELOPE..]);

    // The deserialized proof re-serializes to the same string.
    let decoded: Proof<C, R> = serde_json::from_str(&json).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
    let decoded = decoded.carry::<LeafNode>(data);
    assert!(app.verify_uncompressed(&decoded, &mut rng).unwrap());
    let compressed = app.compress(&decoded, &mut rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap());

    let borrowed = BorrowedBytesDeserializer::<serde::de::value::Error>::new(&bytes);
    let decoded = Proof::<C, R>::deserialize(borrowed).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
    let mut trailing = bytes.clone();
    trailing.push(0);
    for malformed in [&bytes[..bytes.len() - 1], &trailing] {
        let json = serde_json::to_string(malformed).unwrap();
        assert!(serde_json::from_str::<Proof<C, R>>(&json).is_err());
    }
}

#[test]
fn a_compressed_proof_serializes_as_its_payload_behind_a_prelude() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let pcd = leaf(&app, &mut rng, 7);
    let data = *pcd.data();
    let compressed = app.compress(&pcd, &mut rng).unwrap().into_parts().0;
    let json = serde_json::to_string(&compressed).unwrap();
    let bytes: Vec<u8> = serde_json::from_str(&json).unwrap();
    assert_eq!(&bytes[..PRELUDE.len()], &PRELUDE);
    let envelope = app
        .proof_format(context())
        .encode_compressed(&compressed)
        .unwrap();
    assert_eq!(&bytes[PRELUDE.len()..], &envelope[ENVELOPE..]);

    let decoded: CompressedProof<C> = serde_json::from_str(&json).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
    assert!(
        app.verify_compressed(&decoded.carry::<LeafNode>(data))
            .unwrap()
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    for malformed in [&bytes[..bytes.len() - 1], &trailing] {
        let json = serde_json::to_string(malformed).unwrap();
        assert!(serde_json::from_str::<CompressedProof<C>>(&json).is_err());
    }
}

#[test]
fn a_prelude_this_type_cannot_have_is_rejected() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, _) = leaf(&app, &mut rng, 7).into_parts();
    let bytes: Vec<u8> = serde_json::from_str(&serde_json::to_string(&proof).unwrap()).unwrap();
    let rejected = |edit: fn(&mut Vec<u8>)| {
        let mut bytes = bytes.clone();
        edit(&mut bytes);
        let json = serde_json::to_string(&bytes).unwrap();
        let Err(error) = serde_json::from_str::<Proof<C, R>>(&json) else {
            panic!("an edited prelude must not decode")
        };
        error.to_string()
    };
    // A proof's rank is its type's.
    let error = rejected(|bytes| bytes[1] = 12);
    assert!(error.contains("proof rank mismatch"), "{error}");
    // A header size past the limit is refused before the payload is read.
    let error = rejected(|bytes| bytes[5..13].copy_from_slice(&(1u64 << 40).to_le_bytes()));
    assert!(error.contains("header size exceeds the limit"), "{error}");
    // Another admissible header size implies another length. A sequence is
    // refused once it runs past that length, a byte string by its length.
    let error = rejected(|bytes| bytes[5] = 3);
    assert!(error.contains("exceeds its fixed length"), "{error}");
    let mut edited = bytes.clone();
    edited[5] = 3;
    let borrowed = BorrowedBytesDeserializer::<serde::de::value::Error>::new(&edited);
    let Err(error) = Proof::<C, R>::deserialize(borrowed) else {
        panic!("a byte string of another length must not decode")
    };
    let error = error.to_string();
    assert!(error.contains("incorrect encoded length"), "{error}");
}

#[test]
fn malformed_bytes_are_a_serde_error() {
    let json = serde_json::to_string(&[7u8, 1, 2, 3]).unwrap();
    let Err(error) = serde_json::from_str::<Proof<C, R>>(&json) else {
        panic!("a bad version byte must not decode")
    };
    assert!(
        error.to_string().contains("unsupported wire version"),
        "{error}"
    );
    let json = serde_json::to_string(&[1u8, 13, 0]).unwrap();
    let Err(error) = serde_json::from_str::<CompressedProof<C>>(&json) else {
        panic!("a short prelude must not decode")
    };
    assert!(error.to_string().contains("truncated"), "{error}");
}
