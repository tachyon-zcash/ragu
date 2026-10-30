//! A minimal proof serializes as its wire bytes in every serde format.

use ragu_pcd::{
    MinimalProof,
    wire::{Decode, Encode},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, de::value::BorrowedBytesDeserializer};

#[allow(dead_code)]
mod nontrivial_support;
use nontrivial_support::{C, HEADER_SIZE, R, app, leaf};

type Minimal = MinimalProof<C, R, HEADER_SIZE>;

#[test]
fn json_carries_the_wire_bytes() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, _) = leaf(&app, &mut rng, 7).into_parts();
    let minimal = proof.minimize::<HEADER_SIZE>();
    let json = serde_json::to_string(&minimal).unwrap();
    // JSON has no bytes type; the array of numbers is the wire string.
    let expected = serde_json::to_string(&minimal.to_bytes()).unwrap();
    assert_eq!(json, expected);
    let decoded: Minimal = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.to_bytes(), minimal.to_bytes());

    let bytes = minimal.to_bytes();
    let borrowed = BorrowedBytesDeserializer::<serde::de::value::Error>::new(&bytes);
    let decoded = Minimal::deserialize(borrowed).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
    let mut trailing = bytes.clone();
    trailing.push(0);
    for malformed in [&bytes[..bytes.len() - 1], &trailing] {
        let json = serde_json::to_string(malformed).unwrap();
        assert!(serde_json::from_str::<Minimal>(&json).is_err());
    }
}

#[test]
fn wrong_shape_is_a_serde_error() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, _) = leaf(&app, &mut rng, 7).into_parts();
    // The headers have `HEADER_SIZE` elements, so this proof has no encoding
    // of the length its type promises.
    let wrong = proof.minimize::<{ HEADER_SIZE + 1 }>();
    let error = serde_json::to_string(&wrong).unwrap_err();
    assert!(error.to_string().contains("profile's shape"), "{error}");
}

#[test]
fn malformed_bytes_are_a_serde_error() {
    let json = serde_json::to_string(&[7u8, 1, 2, 3]).unwrap();
    let Err(error) = serde_json::from_str::<Minimal>(&json) else {
        panic!("a short input must not decode")
    };
    assert!(
        error.to_string().contains("incorrect encoded length"),
        "{error}"
    );
    let mut wrong_version = vec![0u8; 1 + Minimal::encoded_len()];
    wrong_version[0] = 7;
    let json = serde_json::to_string(&wrong_version).unwrap();
    let Err(error) = serde_json::from_str::<Minimal>(&json) else {
        panic!("a bad version byte must not decode")
    };
    assert!(
        error.to_string().contains("unsupported wire version"),
        "{error}"
    );
}
