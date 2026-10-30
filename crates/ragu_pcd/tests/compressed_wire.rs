//! The production compressed-proof transport path and hostile byte boundaries.
use ragu_pcd::ProofContext;
use ragu_testing::pcd::nontrivial::LeafNode;
use rand::{SeedableRng, rngs::StdRng};
#[allow(dead_code)]
mod nontrivial_support;
use nontrivial_support::{app, leaf};

#[test]
fn compressed_transport_roundtrip_and_rejection() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x51a1);
    let proof = leaf(&app, &mut rng, 42);
    let data = *proof.data();
    let compressed = app.compress(&proof, &mut rng).unwrap();
    let context = ProofContext {
        suite: [31; 32],
        application: [47; 32],
    };
    let format = app.proof_format(context);
    let bytes = format.encode_compressed(compressed.proof()).unwrap();
    assert_eq!(bytes.len(), format.compressed_encoded_len());
    let decoded = format.decode_compressed(&bytes).unwrap();
    assert_eq!(format.encode_compressed(&decoded).unwrap(), bytes);
    assert!(
        app.verify_compressed(&decoded.carry::<LeafNode>(data))
            .unwrap()
    );
    assert!(format.decode(&bytes).is_err());
    let minimal = format.encode(&proof.proof().minimize::<4>()).unwrap();
    assert!(format.decode_compressed(&minimal).is_err());
    for n in [0, 1, 91, bytes.len() - 1] {
        assert!(format.decode_compressed(&bytes[..n]).is_err());
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(format.decode_compressed(&bad).is_err());
    // Each envelope component is independently checked at the correct length.
    for offset in [0, 8, 10, 12, 14, 16, 20, 28, 60] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        assert!(
            format.decode_compressed(&bad).is_err(),
            "envelope offset {offset}"
        );
    }
    // First native point: circuit id and the two fixed four-element headers precede it.
    let point = 92 + 4 + 2 * 4 * 32;
    for value in [0, 0xff] {
        let mut bad = bytes.clone();
        bad[point..point + 32].fill(value);
        assert!(format.decode_compressed(&bad).is_err());
    }
    let mut bad = bytes.clone();
    bad[96..128].fill(0xff);
    assert!(
        format.decode_compressed(&bad).is_err(),
        "noncanonical header scalar"
    );
    // A canonical but false final IPA coefficient is representation-valid,
    // and must fail production verification rather than decoding.
    let mut bad = bytes;
    let end = bad.len();
    bad[end - 32..].fill(0);
    let decoded = format
        .decode_compressed(&bad)
        .unwrap()
        .carry::<LeafNode>(data);
    assert!(!app.verify_compressed(&decoded).unwrap());
}
