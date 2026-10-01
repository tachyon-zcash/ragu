//! A minimal proof serializes as its wire bytes in every serde format.

use ragu_pcd::MinimalProof;
use ragu_primitives::wire::{Encode, Minimize};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, de::value::BorrowedBytesDeserializer};

#[allow(dead_code)]
mod nontrivial_support;
use nontrivial_support::{C, R, app, leaf};

#[test]
fn json_carries_the_wire_bytes() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, _) = leaf(&app, &mut rng, 7).into_parts();
    let minimal = proof.minimize();
    let json = serde_json::to_string(&minimal).unwrap();
    // JSON has no bytes type; the array of numbers is the wire string.
    let expected = serde_json::to_string(&minimal.to_bytes()).unwrap();
    assert_eq!(json, expected);
    let decoded: MinimalProof<C, R> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.to_bytes(), minimal.to_bytes());

    let bytes = minimal.to_bytes();
    let borrowed = BorrowedBytesDeserializer::<serde::de::value::Error>::new(&bytes);
    let decoded = MinimalProof::<C, R>::deserialize(borrowed).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
    let mut trailing = bytes.clone();
    trailing.push(0);
    for malformed in [&bytes[..bytes.len() - 1], &trailing] {
        let json = serde_json::to_string(malformed).unwrap();
        assert!(serde_json::from_str::<MinimalProof<C, R>>(&json).is_err());
    }
}

#[test]
fn malformed_bytes_are_a_serde_error() {
    let json = serde_json::to_string(&[7u8, 1, 2, 3]).unwrap();
    let Err(error) = serde_json::from_str::<MinimalProof<C, R>>(&json) else {
        panic!("a bad version byte must not decode")
    };
    assert!(
        error.to_string().contains("unsupported wire version"),
        "{error}"
    );
}
