use crate::{
    header::Suffix,
    proof::{PROOF_SIZE_COMPRESSED, Pcd, Proof},
    step::Index,
};

const TEST_SUFFIX: Suffix = Suffix::new(0);
const TEST_INDEX: Index = Index::new(0);

#[test]
fn round_trip() {
    let proof = Proof::new(TEST_SUFFIX, TEST_INDEX, b"header", b"witness");
    let bytes: [u8; PROOF_SIZE_COMPRESSED] = proof.clone().into();
    let recovered = Proof::try_from(&bytes).expect("round trip should succeed");
    assert_eq!(proof.serialize(), recovered.serialize());
}

#[test]
fn tampered_fails() {
    let proof = Proof::new(TEST_SUFFIX, TEST_INDEX, b"header", b"witness");
    let mut bytes: [u8; PROOF_SIZE_COMPRESSED] = proof.into();
    bytes[0] ^= 0xFFu8;
    assert!(
        Proof::try_from(&bytes).is_err(),
        "tampered proof should fail"
    );
}

#[test]
fn carry_creates_pcd() {
    let proof = Proof::new(TEST_SUFFIX, TEST_INDEX, b"header", b"witness");
    let expected = proof.clone();
    let pcd: Pcd<()> = proof.carry(());
    assert_eq!(pcd.proof.serialize(), expected.serialize());
}

#[test]
fn rerandomize() {
    let proof = Proof::new(TEST_SUFFIX, TEST_INDEX, b"header", b"witness");
    assert_eq!(proof.rerand_tag, [0u8; 32]);

    let once = proof.rerandomize();

    assert_eq!(proof.header_hash, once.header_hash);
    assert_eq!(proof.witness_hash, once.witness_hash);
    assert_eq!(proof.binding, once.binding);
    assert_ne!(proof.serialize(), once.serialize());

    let twice = once.rerandomize();
    assert_eq!(proof.header_hash, twice.header_hash);
    assert_eq!(proof.witness_hash, twice.witness_hash);
    assert_eq!(proof.binding, twice.binding);
    assert_ne!(once.serialize(), twice.serialize());

    assert_ne!(proof.rerand_tag, once.rerand_tag);
    assert_ne!(proof.rerand_tag, twice.rerand_tag);
    assert_ne!(once.rerand_tag, twice.rerand_tag);
}
