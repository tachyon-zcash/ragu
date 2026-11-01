//! Byte round trips of production-rank proofs through the versioned envelope.

use ragu_pcd::wire::Error;
use ragu_testing::pcd::nontrivial::LeafNode;
use rand::{SeedableRng, rngs::StdRng};

use super::{ENVELOPE, TestCompressed, TestProof};
use crate::nontrivial_support::{C, R, app, leaf};

#[test]
fn seed_proof_round_trips() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, _) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = proof.to_bytes().unwrap();
    assert_eq!(bytes.len(), TestProof::encoded_len::<4>());
    let decoded = TestProof::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
}

#[test]
fn decoded_proof_verifies_and_compresses() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = proof.to_bytes().unwrap();
    // The application used below infers the cycle and rank.
    let decoded = ragu_pcd::Proof::from_bytes(&bytes)
        .unwrap()
        .carry::<LeafNode>(data);
    assert!(app.verify_uncompressed(&decoded, &mut rng).unwrap());
    let compressed = app.compress(&decoded, &mut rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap());
}

#[test]
fn decoded_proof_verifies_and_a_tampered_one_does_not() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = proof.to_bytes().unwrap();
    let decoded = TestProof::from_bytes(&bytes).unwrap();
    assert!(
        app.verify_uncompressed(&decoded.carry::<LeafNode>(data), &mut rng)
            .unwrap()
    );

    // Another bridge alpha, the payload's first scalar, decodes fine, but the
    // `ab` stage the verifier derives from it no longer matches the shipped one.
    let mut tampered = bytes;
    tampered[ENVELOPE..ENVELOPE + 32].fill(0);
    tampered[ENVELOPE] = 2;
    let decoded = TestProof::from_bytes(&tampered).unwrap();
    assert!(
        !app.verify_uncompressed(&decoded.carry::<LeafNode>(data), &mut rng)
            .unwrap()
    );
}

#[test]
fn envelope_rejects_mismatches_before_payload_decoding() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    let bytes = proof.to_bytes().unwrap();
    assert_eq!(bytes.len(), TestProof::encoded_len::<4>());
    assert_eq!(&bytes[..8], b"RAGUPCD\0");
    assert_eq!(
        &bytes[8..28],
        &[3, 0, 1, 0, 1, 0, 1, 0, 13, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    );
    let decoded = TestProof::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
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
    ] {
        let mut invalid = bytes.clone();
        invalid[offset] = invalid[offset].wrapping_add(1);
        assert!(matches!(TestProof::from_bytes(&invalid),
            Err(Error::Invalid { offset: actual, reason: why, .. }) if actual == offset && why == reason));
    }
    // A short envelope is rejected before reading dimensions. Once the
    // envelope is available, its dimensions fix the exact payload length.
    for end in [0, 8, ENVELOPE - 1] {
        assert!(matches!(
            TestProof::from_bytes(&bytes[..end]),
            Err(Error::Truncated { .. })
        ));
    }
    for end in [ENVELOPE, bytes.len() - 1] {
        assert!(matches!(TestProof::from_bytes(&bytes[..end]),
            Err(Error::Length { actual, .. }) if actual == end));
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        TestProof::from_bytes(&trailing),
        Err(Error::Length { .. })
    ));
    // A payload alone has no version envelope.
    assert!(TestProof::from_bytes(&bytes[ENVELOPE..]).is_err());
}

#[test]
fn verification_uses_the_receiving_application() {
    use ragu_core::Cycle;
    use ragu_pcd::{ApplicationBuilder, RegistryTags};
    use ragu_testing::pcd::nontrivial::WitnessLeaf;

    let params = ragu_pcd::pasta::baked();
    let build = |beacon| {
        let manifest = [0x24; 20];
        ApplicationBuilder::<C, R, 4>::new()
            .with_registry_tags(
                RegistryTags::from_beacon(&[beacon; 32], &manifest),
                &manifest,
            )
            .unwrap()
            .register(WitnessLeaf::<C> {
                poseidon_params: C::circuit_poseidon(params),
            })
            .unwrap()
            .finalize(params)
            .unwrap()
    };
    let sender = build(0x42);
    let receiver = build(0x43);
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let proof = leaf(&sender, &mut rng, 7);
    let data = *proof.data();
    let bytes = proof.proof().to_bytes().unwrap();
    let compressed = sender.compress(&proof, &mut rng).unwrap();
    assert!(sender.verify_compressed(&compressed).unwrap());
    let compressed_bytes = compressed.proof().to_bytes().unwrap();

    // Both setups have the same layout. Decoding succeeds and re-encodes
    // identically, while verification checks the selected registry setup.
    let decoded = TestProof::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
    let decoded = decoded.carry::<LeafNode>(data);
    assert!(sender.verify_uncompressed(&decoded, &mut rng).unwrap());
    assert!(!receiver.verify_uncompressed(&decoded, &mut rng).unwrap());

    let decoded = TestCompressed::from_bytes(&compressed_bytes).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), compressed_bytes);
    let decoded = decoded.carry::<LeafNode>(data);
    assert!(sender.verify_compressed(&decoded).unwrap());
    assert!(!receiver.verify_compressed(&decoded).unwrap());
}
