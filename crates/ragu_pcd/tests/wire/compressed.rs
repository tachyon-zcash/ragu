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
        TestCompressed::encoded_len::<crate::nontrivial_support::R>()
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
    // First native point: only the circuit id precedes it.
    let point = ENVELOPE + 4;
    for value in [0, 0xff] {
        let mut bad = bytes.clone();
        bad[point..point + 32].fill(value);
        assert!(TestCompressed::from_bytes(&bad).is_err());
    }

    // Neither payload carries a header, so a nonzero header size has no
    // canonical encoding, even with a payload of the length it would imply.
    for encoding in [&uncompressed, &bytes] {
        let mut other_header = encoding.clone();
        other_header[20..28].copy_from_slice(&4u64.to_le_bytes());
        other_header.extend(core::iter::repeat_n(0u8, 2 * 4 * 32));
        assert!(TestProof::from_bytes(&other_header).is_err());
        assert!(TestCompressed::from_bytes(&other_header).is_err());
    }

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
