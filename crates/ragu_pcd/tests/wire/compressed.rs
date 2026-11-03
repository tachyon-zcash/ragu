//! The production compressed-proof transport path and hostile byte boundaries.
use ragu_testing::pcd::nontrivial::LeafNode;
use rand::{SeedableRng, rngs::StdRng};

use super::{ENVELOPE, TestCompressed, TestProof};
use crate::nontrivial_support::{app, leaf};

#[test]
fn compressed_transport_roundtrip_and_rejection() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x51a1);
    let proof = leaf(&app, &mut rng, 42);
    let data = *proof.data();
    let compressed = app.compress(&proof, &mut rng).unwrap();
    let bytes = compressed.proof().to_bytes().unwrap();
    assert_eq!(
        bytes.len(),
        TestCompressed::encoded_len::<crate::nontrivial_support::R, 4>()
    );
    let decoded = TestCompressed::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
    assert!(
        app.verify_compressed(&decoded.carry::<LeafNode>(data))
            .unwrap()
    );
    assert!(TestProof::from_bytes(&bytes).is_err());
    let uncompressed = proof.proof().to_bytes().unwrap();
    assert!(TestCompressed::from_bytes(&uncompressed).is_err());
    for n in [0, 1, ENVELOPE - 1, ENVELOPE, bytes.len() - 1] {
        assert!(TestCompressed::from_bytes(&bytes[..n]).is_err());
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(TestCompressed::from_bytes(&bad).is_err());
    // Each envelope component is independently checked at the correct length.
    for offset in [0, 8, 10, 12, 14, 16, 20] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        assert!(
            TestCompressed::from_bytes(&bad).is_err(),
            "envelope offset {offset}"
        );
    }
    // First native point: circuit id and the two fixed four-element headers precede it.
    let point = ENVELOPE + 4 + 2 * 4 * 32;
    for value in [0, 0xff] {
        let mut bad = bytes.clone();
        bad[point..point + 32].fill(value);
        assert!(TestCompressed::from_bytes(&bad).is_err());
    }
    let mut bad = bytes.clone();
    let header = ENVELOPE + 4;
    bad[header..header + 32].fill(0xff);
    assert!(
        TestCompressed::from_bytes(&bad).is_err(),
        "noncanonical header scalar"
    );

    // A different bounded header size can describe a canonical encoding.
    // Application consumers enforce the configured shape after decoding.
    let mut other_header = uncompressed.clone();
    other_header[20..28].copy_from_slice(&0u64.to_le_bytes());
    other_header.drain(ENVELOPE + 36..ENVELOPE + 36 + 2 * 4 * 32);
    let decoded = TestProof::from_bytes(&other_header)
        .unwrap()
        .carry::<LeafNode>(data);
    assert!(app.compress(&decoded, &mut rng).is_err());

    let mut other_header = bytes.clone();
    other_header[20..28].copy_from_slice(&0u64.to_le_bytes());
    other_header.drain(ENVELOPE + 4..ENVELOPE + 4 + 2 * 4 * 32);
    let decoded = TestCompressed::from_bytes(&other_header)
        .unwrap()
        .carry::<LeafNode>(data);
    assert!(!app.verify_compressed(&decoded).unwrap());

    // A canonical but false final IPA coefficient is representation-valid,
    // and must fail production verification rather than decoding.
    let mut bad = bytes;
    let end = bad.len();
    bad[end - 32..].fill(0);
    let decoded = TestCompressed::from_bytes(&bad)
        .unwrap()
        .carry::<LeafNode>(data);
    assert!(!app.verify_compressed(&decoded).unwrap());
}
