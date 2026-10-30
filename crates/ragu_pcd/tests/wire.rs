//! Byte round trips of the minimal form of production-rank proofs.

use ragu_pcd::{
    MinimalProof, ProofContext,
    wire::{Decode, Encode, Error},
};
use ragu_testing::pcd::nontrivial::{InternalNode, LeafNode};
use rand::{SeedableRng, rngs::StdRng};

mod nontrivial_support;
use nontrivial_support::{C, HEADER_SIZE, R, app, deep, leaf};

type Minimal = MinimalProof<C, R, HEADER_SIZE>;

fn assert_round_trip(bytes: &[u8]) {
    assert_eq!(bytes.len(), 1 + Minimal::encoded_len());
    let decoded = Minimal::from_bytes(bytes).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
}

#[test]
fn seed_proof_round_trips() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, _) = leaf(&app, &mut rng, 7).into_parts();
    assert_round_trip(&proof.minimize::<HEADER_SIZE>().to_bytes());
}

// Proves seven production-rank proofs. Run explicitly in release with
// `--include-ignored`; ordinary runs leave it ignored.
#[test]
#[ignore]
fn fused_proof_round_trips() {
    let app = app();
    let (proof, data) = deep(&app).into_parts();
    let bytes = proof.minimize::<HEADER_SIZE>().to_bytes();
    assert_round_trip(&bytes);
    let decoded = Minimal::from_bytes(&bytes).unwrap();
    assert!(
        app.verify_minimal::<_, InternalNode>(decoded, data, StdRng::seed_from_u64(0xdec1de))
            .unwrap()
    );
}

#[test]
fn decoded_proof_expands_verifies_and_compresses() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = proof.minimize::<HEADER_SIZE>().to_bytes();
    let decoded = Minimal::from_bytes(&bytes).unwrap();
    let expanded = app.expand(decoded).unwrap();
    // Expansion preserves the retained fields. The unit tests compare the
    // derived fields too, through the semantic proof comparison helper.
    assert_eq!(expanded.minimize::<HEADER_SIZE>().to_bytes(), bytes);
    let expanded = expanded.carry::<LeafNode>(data);
    assert!(app.verify_uncompressed(&expanded, &mut rng).unwrap());
    // The reconstructed fields must also be valid inputs to the IPA path.
    let compressed = app.compress(&expanded, &mut rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap());
}

#[test]
fn minimal_proof_verifies_and_a_tampered_one_does_not() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = proof.minimize::<HEADER_SIZE>().to_bytes();
    let decoded = Minimal::from_bytes(&bytes).unwrap();
    assert!(
        app.verify_minimal::<_, LeafNode>(decoded, data, &mut rng)
            .unwrap()
    );

    // Another bridge alpha decodes fine, but the `ab` stage rebuilt from it
    // no longer matches the shipped commitment.
    let mut tampered = bytes;
    tampered[1..33].fill(0);
    tampered[1] = 2;
    let decoded = Minimal::from_bytes(&tampered).unwrap();
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
    let bytes = proof.minimize::<HEADER_SIZE>().to_bytes();
    // Every other length is rejected before any byte is interpreted.
    for length in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        assert!(matches!(
            Minimal::from_bytes(&bytes[..length]),
            Err(Error::Length { actual, .. }) if actual == length
        ));
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        Minimal::from_bytes(&trailing),
        Err(Error::Length { .. })
    ));
    let mut wrong_version = bytes;
    wrong_version[0] = ragu_pcd::wire::VERSION.wrapping_add(1);
    assert!(matches!(
        Minimal::from_bytes(&wrong_version),
        Err(Error::Invalid {
            reason: "unsupported wire version",
            ..
        })
    ));
}

#[test]
fn application_envelope_rejects_mismatches_before_payload_decoding() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let proof = proof.into_minimal::<HEADER_SIZE>();
    let payload = proof.to_bytes();
    // Fixed test IDs stand in for trusted deployment-manifest digests.
    let context = ProofContext {
        suite: [0x53; 32],
        application: [0x41; 32],
    };
    let format = app.proof_format(context);
    let bytes = format.encode(&proof).unwrap();
    assert_eq!(bytes.len(), format.encoded_len());
    assert_eq!(&bytes[..8], b"RAGUPCD\0");
    assert_eq!(
        &bytes[8..28],
        &[1, 0, 1, 0, 1, 0, 1, 0, 13, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(&bytes[92..], &payload[1..]);
    let decoded = format.decode(&bytes).unwrap();
    assert_eq!(decoded.to_bytes(), payload);
    assert!(
        app.verify_minimal::<_, LeafNode>(decoded, data, StdRng::seed_from_u64(0xdec1de))
            .unwrap()
    );
    // Each header mismatch is reported by component, before the payload.
    for (offset, reason) in [
        (0, "invalid proof magic"),
        (8, "unsupported proof envelope version"),
        (10, "proof payload kind mismatch"),
        (12, "unsupported proof schema version"),
        (14, "unsupported proof protocol version"),
        (16, "proof rank mismatch"),
        (20, "proof header size mismatch"),
        (28, "proof suite mismatch"),
        (60, "proof application mismatch"),
    ] {
        let mut invalid = bytes.clone();
        invalid[offset] = invalid[offset].wrapping_add(1);
        assert!(matches!(format.decode(&invalid),
            Err(Error::Invalid { offset: actual, reason: why, .. }) if actual == offset && why == reason));
    }
    // Any other length is rejected before the envelope is read, so a short
    // input with a bad magic reports its length, not the magic.
    for end in [0, 8, 91, 92, bytes.len() - 1] {
        let mut short = bytes[..end].to_vec();
        if end > 0 {
            short[0] = 0;
        }
        assert!(matches!(
            format.decode(&short),
            Err(Error::Length { actual, .. }) if actual == end
        ));
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        format.decode(&trailing),
        Err(Error::Length { .. })
    ));
    assert!(matches!(format.decode(&payload), Err(Error::Length { .. })));
    // The application's header size is part of the type, so another
    // application's format decodes nothing of this one.
    let other = ragu_pcd::ApplicationBuilder::<C, R, 3>::new()
        .finalize(ragu_pcd::pasta::baked())
        .unwrap()
        .proof_format(context);
    assert!(matches!(other.decode(&bytes), Err(Error::Length { .. })));
}

/// Reproducible local measurements; excluded from ordinary correctness tests.
#[test]
#[ignore]
fn wire_measurements() {
    use std::{hint::black_box, time::Instant};

    let app = app();
    let format = app.proof_format(ProofContext {
        suite: [0x53; 32],
        application: [0x41; 32],
    });
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (expanded, data) = leaf(&app, &mut rng, 7).into_parts();
    let mut samples = Vec::new();
    for _ in 0..5 {
        let owned = expanded.clone();
        let start = Instant::now();
        let cloned = black_box(expanded.minimize::<HEADER_SIZE>());
        let cloning = start.elapsed();
        let start = Instant::now();
        let moved = black_box(owned.into_minimal::<HEADER_SIZE>());
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
