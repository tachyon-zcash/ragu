//! Byte round trips of production-rank proofs through the application's
//! versioned envelope.

use ragu_pcd::{ProofContext, wire::Error};
use ragu_testing::pcd::nontrivial::{InternalNode, LeafNode};
use rand::{SeedableRng, rngs::StdRng};

mod nontrivial_support;
use nontrivial_support::{C, R, app, deep, leaf};

/// The envelope ahead of every payload.
const ENVELOPE: usize = 124;

/// Fixed test IDs stand in for trusted deployment-manifest digests.
fn context() -> ProofContext {
    ProofContext {
        suite: [0x53; 32],
        application: [0x41; 32],
    }
}

#[test]
fn seed_proof_round_trips() {
    let app = app();
    let format = app.proof_format(context());
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, _) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = format.encode(&proof).unwrap();
    assert_eq!(bytes.len(), format.encoded_len());
    let decoded = format.decode(&bytes).unwrap();
    assert_eq!(format.encode(&decoded).unwrap(), bytes);
}

// Proves seven production-rank proofs. Run explicitly in release with
// `--include-ignored`; ordinary runs leave it ignored.
#[test]
#[ignore]
fn fused_proof_round_trips() {
    let app = app();
    let format = app.proof_format(context());
    let (proof, data) = deep(&app).into_parts();
    let bytes = format.encode(&proof).unwrap();
    let decoded = format.decode(&bytes).unwrap();
    assert_eq!(format.encode(&decoded).unwrap(), bytes);
    assert!(
        app.verify_uncompressed(
            &decoded.carry::<InternalNode>(data),
            StdRng::seed_from_u64(0xdec1de)
        )
        .unwrap()
    );
}

#[test]
fn decoded_proof_verifies_and_compresses() {
    let app = app();
    let format = app.proof_format(context());
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let decoded = format
        .decode(&format.encode(&proof).unwrap())
        .unwrap()
        .carry::<LeafNode>(data);
    assert!(app.verify_uncompressed(&decoded, &mut rng).unwrap());
    let compressed = app.compress(&decoded, &mut rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap());
}

#[test]
fn decoded_proof_verifies_and_a_tampered_one_does_not() {
    let app = app();
    let format = app.proof_format(context());
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = format.encode(&proof).unwrap();
    let decoded = format.decode(&bytes).unwrap();
    assert!(
        app.verify_uncompressed(&decoded.carry::<LeafNode>(data), &mut rng)
            .unwrap()
    );

    // Another bridge alpha, the payload's first scalar, decodes fine, but the
    // `ab` stage the verifier derives from it no longer matches the shipped one.
    let mut tampered = bytes;
    tampered[ENVELOPE..ENVELOPE + 32].fill(0);
    tampered[ENVELOPE] = 2;
    let decoded = format.decode(&tampered).unwrap();
    assert!(
        !app.verify_uncompressed(&decoded.carry::<LeafNode>(data), &mut rng)
            .unwrap()
    );
}

#[test]
fn application_envelope_rejects_mismatches_before_payload_decoding() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let format = app.proof_format(context());
    let bytes = format.encode(&proof).unwrap();
    assert_eq!(bytes.len(), format.encoded_len());
    assert_eq!(&bytes[..8], b"RAGUPCD\0");
    assert_eq!(
        &bytes[8..28],
        &[2, 0, 1, 0, 1, 0, 1, 0, 13, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    );
    let decoded = format.decode(&bytes).unwrap();
    assert_eq!(format.encode(&decoded).unwrap(), bytes);
    assert!(
        app.verify_uncompressed(
            &decoded.carry::<LeafNode>(data),
            StdRng::seed_from_u64(0xdec1de)
        )
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
        (28, "proof profile mismatch"),
        (60, "proof suite mismatch"),
        (92, "proof application mismatch"),
    ] {
        let mut invalid = bytes.clone();
        invalid[offset] = invalid[offset].wrapping_add(1);
        assert!(matches!(format.decode(&invalid),
            Err(Error::Invalid { offset: actual, reason: why, .. }) if actual == offset && why == reason));
    }
    // Any other length is rejected before the envelope is read, so a short
    // input with a bad magic reports its length, not the magic.
    for end in [0, 8, 123, 124, bytes.len() - 1] {
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
    // The payload without its envelope is another length.
    assert!(matches!(
        format.decode(&bytes[ENVELOPE..]),
        Err(Error::Length { .. })
    ));
    // The application's header size is part of the type, so another
    // application's format decodes nothing of this one.
    let other = ragu_pcd::ApplicationBuilder::<C, R, 3>::new()
        .finalize(ragu_pcd::pasta::baked())
        .unwrap()
        .proof_format(context());
    assert!(matches!(other.decode(&bytes), Err(Error::Length { .. })));
}

/// Reproducible local measurements; excluded from ordinary correctness tests.
#[test]
#[ignore]
fn wire_measurements() {
    use std::{hint::black_box, time::Instant};

    let app = app();
    let format = app.proof_format(context());
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let mut samples = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let bytes = black_box(format.encode(&proof).unwrap());
        let encoding = start.elapsed();
        let start = Instant::now();
        let decoded = black_box(format.decode(&bytes).unwrap());
        let decoding = start.elapsed();
        let start = Instant::now();
        assert!(
            app.verify_uncompressed(
                &decoded.carry::<LeafNode>(data),
                StdRng::seed_from_u64(0xdec1de)
            )
            .unwrap()
        );
        let verification = start.elapsed();
        samples.push([encoding, decoding, verification]);
        println!(
            "bytes={}, encode={encoding:?}, decode={decoding:?}, verify={verification:?}",
            bytes.len()
        );
    }
    for (column, name) in ["encode", "decode", "verify"].iter().enumerate() {
        let mut values: Vec<_> = samples.iter().map(|s| s[column]).collect();
        values.sort();
        println!("median {name}={:?}", values[2]);
    }
}
