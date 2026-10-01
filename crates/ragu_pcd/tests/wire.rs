//! Byte round trips of the minimal form of production-rank proofs.

use ragu_pcd::MinimalProof;
use ragu_primitives::wire::{Decode, Encode, Limits, Minimize};
use ragu_testing::pcd::nontrivial::{InternalNode, LeafNode};
use rand::{SeedableRng, rngs::StdRng};

mod nontrivial_support;
use nontrivial_support::{C, R, app, deep, leaf};

fn assert_round_trip(bytes: &[u8]) {
    let decoded = MinimalProof::<C, R>::from_bytes(bytes, Limits::default()).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
}

#[test]
fn seed_proof_round_trips() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, _) = leaf(&app, &mut rng, 7).into_parts();
    assert_round_trip(&proof.minimize().to_bytes());
}

// Proves seven production-rank proofs, so it runs with the scheduled heavy
// tests (`cargo test -- --ignored`) rather than on the PR gate.
#[test]
#[ignore]
fn fused_proof_round_trips() {
    let app = app();
    let (proof, data) = deep(&app).into_parts();
    let bytes = proof.minimize().to_bytes();
    assert_round_trip(&bytes);
    let decoded = MinimalProof::<C, R>::from_bytes(&bytes, Limits::default()).unwrap();
    assert!(
        app.verify_minimal::<_, InternalNode>(decoded, data, StdRng::seed_from_u64(0xdec1de))
            .unwrap()
    );
}

#[test]
fn decoded_proof_expands_and_verifies() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = proof.minimize().to_bytes();
    let decoded = MinimalProof::<C, R>::from_bytes(&bytes, Limits::default()).unwrap();
    let expanded = app.expand(decoded).unwrap();
    // Expansion preserves the retained fields. The unit tests compare the
    // derived fields too, through the semantic proof comparison helper.
    assert_eq!(expanded.minimize().to_bytes(), bytes);
    assert!(
        app.verify(&expanded.carry::<LeafNode>(data), &mut rng)
            .unwrap()
    );
}

#[test]
fn minimal_proof_verifies_and_a_tampered_one_does_not() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = proof.minimize().to_bytes();
    let decoded = MinimalProof::<C, R>::from_bytes(&bytes, Limits::default()).unwrap();
    assert!(
        app.verify_minimal::<_, LeafNode>(decoded, data, &mut rng)
            .unwrap()
    );

    // Another bridge alpha decodes fine, but the `ab` stage rebuilt from it
    // no longer matches the shipped commitment.
    let mut tampered = bytes;
    tampered[1..33].fill(0);
    tampered[1] = 2;
    let decoded = MinimalProof::<C, R>::from_bytes(&tampered, Limits::default()).unwrap();
    assert!(
        !app.verify_minimal::<_, LeafNode>(decoded, data, &mut rng)
            .unwrap()
    );
}

#[test]
fn malformed_proof_bytes_are_rejected() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, _) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = proof.minimize().to_bytes();
    // Every strict prefix is missing at least one trailing value.
    for length in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        MinimalProof::<C, R>::from_bytes(&bytes[..length], Limits::default())
            .err()
            .expect("truncated proof");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(MinimalProof::<C, R>::from_bytes(&trailing, Limits::default()).is_err());
    let mut wrong_version = bytes;
    wrong_version[0] = ragu_primitives::wire::VERSION.wrapping_add(1);
    assert!(MinimalProof::<C, R>::from_bytes(&wrong_version, Limits::default()).is_err());
}

/// Decode a complete proof captured with the pre-Udon implementation, without
/// regenerating it using the current prover or RNG implementation.
#[test]
fn pre_udon_proof_decodes_and_verifies() {
    use ragu_core::pasta::Fp;
    use ragu_primitives::wire::Scalar;

    let bytes = include_bytes!("fixtures/wire/pre_udon_proof.bin");
    let header = include_bytes!("fixtures/wire/pre_udon_header.bin");
    let data = <Fp as Decode<Scalar>>::from_bytes(header, Limits::default()).unwrap();
    let decoded = MinimalProof::<C, R>::from_bytes(bytes, Limits::default()).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
    assert!(
        app()
            .verify_minimal::<_, LeafNode>(decoded, data, StdRng::seed_from_u64(0xdec1de))
            .unwrap()
    );
}

#[test]
fn application_envelope_rejects_mismatches_before_payload_decoding() {
    use ragu_pcd::ProofContext;
    use ragu_primitives::wire::Error;
    let app = app();
    // Fixed test IDs stand in for trusted deployment-manifest digests.
    let context = ProofContext {
        suite: [0x53; 32],
        application: [0x41; 32],
    };
    let format = app.proof_format(context);
    let legacy = include_bytes!("fixtures/wire/pre_udon_proof.bin");
    let proof = MinimalProof::<C, R>::from_bytes(legacy, format.decode_limits()).unwrap();
    let bytes = format.encode(&proof).unwrap();
    assert_eq!(&bytes[..8], b"RAGUPCD\0");
    assert_eq!(
        &bytes[8..26],
        &[1, 0, 1, 0, 1, 0, 13, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(&bytes[90..], &legacy[1..]);
    let decoded = format.decode(&bytes).unwrap();
    assert_eq!(decoded.to_bytes(), legacy);
    let data = <ragu_core::pasta::Fp as Decode<ragu_primitives::wire::Scalar>>::from_bytes(
        include_bytes!("fixtures/wire/pre_udon_header.bin"),
        Limits::default(),
    )
    .unwrap();
    assert!(
        app.verify_minimal::<_, LeafNode>(decoded, data, StdRng::seed_from_u64(0xdec1de))
            .unwrap()
    );
    // Removing the entire payload and setting budgets to zero proves that
    // each header mismatch is detected before attempting proof allocation.
    for (offset, reason) in [
        (0, "invalid proof magic"),
        (8, "unsupported proof envelope version"),
        (10, "unsupported proof schema version"),
        (12, "unsupported proof protocol version"),
        (14, "proof rank mismatch"),
        (18, "proof header size mismatch"),
        (26, "proof suite mismatch"),
        (58, "proof application mismatch"),
    ] {
        let mut invalid = bytes[..90].to_vec();
        invalid[offset] = invalid[offset].wrapping_add(1);
        assert!(
            matches!(format.decode_with_limits(&invalid, Limits { elements: 0, allocation: 0 }),
            Err(Error::Invalid { reason: actual, .. }) if actual == reason)
        );
    }
    // Child counts must match the envelope before any payload allocation.
    let mut invalid = bytes.clone();
    invalid[90 + 32 + 4..90 + 32 + 12].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        format.decode_with_limits(
            &invalid,
            Limits {
                elements: 0,
                allocation: 0
            }
        ),
        Err(Error::Invalid {
            reason: "incorrect child header length",
            ..
        })
    ));
    assert!(matches!(
        format.decode_with_limits(
            &bytes,
            Limits {
                elements: 0,
                allocation: 0
            }
        ),
        Err(Error::Limit { .. })
    ));
    for end in [0, 8, 89, 90, bytes.len() - 1] {
        assert!(format.decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        format.decode(&trailing),
        Err(Error::Invalid {
            reason: "trailing bytes",
            ..
        })
    ));
    assert!(format.decode(legacy).is_err());
}

/// Reproducible local measurements; excluded from ordinary correctness tests.
#[test]
#[ignore]
fn wire_measurements() {
    use std::{hint::black_box, time::Instant};

    use ragu_pcd::ProofContext;
    let app = app();
    let format = app.proof_format(ProofContext {
        suite: [0x53; 32],
        application: [0x41; 32],
    });
    let legacy = include_bytes!("fixtures/wire/pre_udon_proof.bin");
    let minimal = MinimalProof::<C, R>::from_bytes(legacy, format.decode_limits()).unwrap();
    let expanded = app.expand(minimal).unwrap();
    let data = <ragu_core::pasta::Fp as Decode<ragu_primitives::wire::Scalar>>::from_bytes(
        include_bytes!("fixtures/wire/pre_udon_header.bin"),
        Limits::default(),
    )
    .unwrap();
    let mut samples = Vec::new();
    for _ in 0..5 {
        let owned = expanded.clone();
        let start = Instant::now();
        let cloned = black_box(expanded.minimize());
        let cloning = start.elapsed();
        let start = Instant::now();
        let moved = black_box(owned.into_minimal());
        let moving = start.elapsed();
        assert_eq!(cloned.to_bytes(), moved.to_bytes());
        let start = Instant::now();
        let bytes = black_box(format.encode(&moved).unwrap());
        let encoding = start.elapsed();
        let start = Instant::now();
        let decoded = black_box(format.decode(&bytes).unwrap());
        let decoding = start.elapsed();
        let start = Instant::now();
        assert!(
            app.verify_minimal::<_, LeafNode>(decoded, data, StdRng::seed_from_u64(0xdec1de))
                .unwrap()
        );
        let verification = start.elapsed();
        samples.push([cloning, moving, encoding, decoding, verification]);
        println!(
            "bytes={}, clone={cloning:?}, move={moving:?}, encode={encoding:?}, decode={decoding:?}, expand+verify={verification:?}",
            bytes.len()
        );
    }
    for (column, name) in ["clone", "move", "encode", "decode", "expand+verify"]
        .iter()
        .enumerate()
    {
        let mut values: Vec<_> = samples.iter().map(|s| s[column]).collect();
        values.sort();
        println!("median {name}={:?}", values[2]);
    }
}
