use ragu_circuits::polynomials::{ProductionRank as TestRank, Rank};
use ragu_core::pasta::{Fp, Pasta};
use rand::{SeedableRng as _, rngs::StdRng};
use udon::curve::Affine;

use super::application::{Seed, ValueHeader, test_builder_for, test_params};
use crate::{Application, Pcd, Proof, WireHeader, wire::Error};

type MockProof = Proof<Pasta, TestRank>;
type MockPcd<H> = Pcd<Pasta, TestRank, H>;
type MockApplication = Application<'static, Pasta, TestRank, 4>;

impl WireHeader<Fp> for ValueHeader {
    fn decode(elements: &[Fp]) -> Option<Self::Data> {
        match elements {
            [value] => Some(*value),
            _ => None,
        }
    }
}

fn application() -> MockApplication {
    test_builder_for::<TestRank>()
        .register(Seed::<0>)
        .expect("register")
        .finalize(test_params())
        .expect("finalize")
}

fn seeded_pcd() -> MockPcd<ValueHeader> {
    let mut rng = StdRng::seed_from_u64(7);
    application()
        .seed(&mut rng, Seed::<0>, Fp::from(42))
        .expect("seed")
        .0
}

fn bootstrap_proof() -> MockProof {
    application().bootstrap_proof().clone()
}

#[test]
fn proof_round_trip_preserves_reusable_data() {
    for proof in [bootstrap_proof(), seeded_pcd().proof().clone()] {
        let bytes = proof.to_bytes().expect("encode");
        assert_eq!(bytes.len(), MockProof::encoded_len::<4>());
        let decoded = MockProof::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded.to_bytes().expect("re-encode"), bytes);
    }
}

#[test]
fn pcd_round_trip() {
    let pcd = seeded_pcd();
    let bytes = pcd.to_bytes().expect("encode");
    let decoded = MockPcd::<ValueHeader>::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded.data(), pcd.data());
    assert_eq!(
        decoded.proof().to_bytes().expect("encode"),
        pcd.proof().to_bytes().expect("encode")
    );
    assert!(
        application()
            .verify_uncompressed(&decoded, StdRng::seed_from_u64(8))
            .expect("verify")
    );

    let unit = bootstrap_proof().carry::<()>(());
    let bytes = unit.to_bytes().expect("encode");
    let decoded = MockPcd::<()>::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded.data(), &());
}

#[test]
fn envelope_and_payload_layout() {
    let proof = bootstrap_proof();
    let bytes = proof.to_bytes().expect("encode");
    assert_eq!(&bytes[..8], b"RAGUPCD\0");
    assert_eq!(
        u16::from_le_bytes(bytes[8..10].try_into().expect("version")),
        3
    );
    assert_eq!(
        u16::from_le_bytes(bytes[10..12].try_into().expect("kind")),
        1
    );
    assert_eq!(
        u16::from_le_bytes(bytes[12..14].try_into().expect("schema")),
        2
    );
    assert_eq!(
        u16::from_le_bytes(bytes[14..16].try_into().expect("protocol")),
        1
    );
    assert_eq!(
        u32::from_le_bytes(bytes[16..20].try_into().expect("rank")),
        TestRank::RANK
    );
    assert_eq!(
        u64::from_le_bytes(bytes[20..28].try_into().expect("size")),
        4
    );
    assert_eq!(bytes.len(), MockProof::encoded_len::<4>());

    let pcd = seeded_pcd();
    let framed = pcd.to_bytes().expect("encode PCD");
    assert_eq!(&framed[..8], b"RAGUPCD\0");
    assert_eq!(
        u16::from_le_bytes(framed[10..12].try_into().expect("kind")),
        4
    );
    assert_eq!(
        u64::from_le_bytes(framed[20..28].try_into().expect("count")),
        1
    );
    let inner = pcd.proof().to_bytes().expect("encode proof");
    assert_eq!(&framed[28..28 + inner.len()], inner.as_slice());
}

#[test]
fn rejects_every_envelope_component_mutation() {
    let bytes = bootstrap_proof().to_bytes().expect("encode");
    for offset in [0, 8, 10, 12, 14, 16] {
        let mut mutated = bytes.clone();
        mutated[offset] ^= 1;
        assert!(
            matches!(MockProof::from_bytes(&mutated), Err(Error::Invalid { offset: at, .. }) if at == offset),
            "offset {offset} must fail"
        );
    }
    let mut mutated = bytes;
    mutated[20] ^= 1;
    assert!(MockProof::from_bytes(&mutated).is_err());
}

#[test]
fn other_payload_kinds_fail_closed() {
    for tag in [2u16, 3, 4, 5] {
        let mut bytes = bootstrap_proof().to_bytes().expect("encode");
        bytes[10..12].copy_from_slice(&tag.to_le_bytes());
        assert!(matches!(
            MockProof::from_bytes(&bytes),
            Err(Error::Invalid {
                reason: "proof payload kind mismatch",
                ..
            })
        ));
    }
}

#[test]
fn rejects_invalid_proof_payload() {
    let mut bytes = bootstrap_proof().to_bytes().expect("encode");
    // Proof prefix: index, header hash, two commitments, witness hash, binding.
    let binding = 28 + 8 + 32 + 2 * 32 + 32;
    bytes[binding] ^= 1;
    assert!(matches!(
        MockProof::from_bytes(&bytes),
        Err(Error::Invalid {
            reason: "mock proof binding mismatch",
            ..
        })
    ));

    let mut bytes = bootstrap_proof().to_bytes().expect("encode");
    let point_start = 28 + 8 + 32;
    let identity = <Pasta as ragu_core::Cycle>::HostCurve::identity().to_bytes();
    bytes[point_start..point_start + identity.as_ref().len()].copy_from_slice(identity.as_ref());
    assert!(MockProof::from_bytes(&bytes).is_err());

    let mut bytes = bootstrap_proof().to_bytes().expect("encode");
    let coefficients = crate::CompressedProof::<Pasta>::encoded_len::<TestRank, 4>();
    bytes[coefficients..coefficients + 32].fill(0xff);
    assert!(MockProof::from_bytes(&bytes).is_err());
}

#[test]
fn rejects_truncation_and_trailing_bytes() {
    let bytes = bootstrap_proof().to_bytes().expect("encode");
    assert!(matches!(
        MockProof::from_bytes(&bytes[..bytes.len() - 1]),
        Err(Error::Length { .. })
    ));
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(
        MockProof::from_bytes(&longer),
        Err(Error::Length { .. })
    ));

    let bytes = seeded_pcd().to_bytes().expect("encode");
    assert!(matches!(
        MockPcd::<ValueHeader>::from_bytes(&bytes[..bytes.len() - 1]),
        Err(Error::Length { .. })
    ));
    let mut longer = bytes;
    longer.push(0);
    assert!(matches!(
        MockPcd::<ValueHeader>::from_bytes(&longer),
        Err(Error::Length { .. })
    ));
}

#[test]
fn rejects_suffix_and_count_mismatches() {
    let bytes = seeded_pcd().to_bytes().expect("encode");
    let mut wrong_rank = bytes.clone();
    wrong_rank[16] ^= 1;
    assert!(matches!(
        MockPcd::<ValueHeader>::from_bytes(&wrong_rank),
        Err(Error::Invalid { offset: 16, .. })
    ));

    let mut oversized = bytes.clone();
    oversized[20..28].copy_from_slice(&4097u64.to_le_bytes());
    assert!(matches!(
        MockPcd::<ValueHeader>::from_bytes(&oversized),
        Err(Error::Invalid { offset: 20, .. })
    ));

    let mut invalid_proof = bytes.clone();
    invalid_proof[28 + 10] ^= 1;
    assert!(MockPcd::<ValueHeader>::from_bytes(&invalid_proof).is_err());

    assert!(matches!(
        MockPcd::<()>::from_bytes(&bytes),
        Err(Error::Invalid {
            reason: "mock PCD header suffix mismatch",
            ..
        })
    ));

    let mut bytes = bytes;
    let count = 28 + MockProof::encoded_len::<4>() + 8;
    bytes[count] ^= 1;
    assert!(matches!(
        MockPcd::<ValueHeader>::from_bytes(&bytes),
        Err(Error::Invalid {
            reason: "header element count does not match the envelope",
            ..
        })
    ));
}

#[test]
fn rejects_noncanonical_header_element() {
    let mut bytes = seeded_pcd().to_bytes().expect("encode");
    let first = 28 + MockProof::encoded_len::<4>() + 16;
    bytes[first..first + 32].fill(0xff);
    assert!(matches!(
        MockPcd::<ValueHeader>::from_bytes(&bytes),
        Err(Error::Invalid {
            reason: "non-canonical field element",
            ..
        })
    ));
}

#[test]
fn decoded_pcd_still_requires_application_verification() {
    let app = application();
    let mut bytes = seeded_pcd().to_bytes().expect("encode");
    let first = 28 + MockProof::encoded_len::<4>() + 16;
    bytes[first] ^= 1;
    let decoded = MockPcd::<ValueHeader>::from_bytes(&bytes).expect("valid representation");
    assert!(
        !app.verify_uncompressed(&decoded, StdRng::seed_from_u64(8))
            .expect("verify")
    );
}

#[cfg(feature = "serde")]
mod serde_tests {
    use alloc::string::ToString as _;

    use serde::de::{DeserializeSeed, value::SeqDeserializer};

    use super::*;

    #[test]
    fn serde_round_trip() {
        let proof = bootstrap_proof();
        let json = serde_json::to_string(&proof).expect("serialize");
        let decoded: MockProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            decoded.to_bytes().expect("encode"),
            proof.to_bytes().expect("encode")
        );

        let pcd = seeded_pcd();
        let json = serde_json::to_string(&pcd).expect("serialize");
        let decoded: MockPcd<ValueHeader> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.data(), pcd.data());
    }

    #[test]
    fn serde_rejects_corruption() {
        let mut bytes = bootstrap_proof().to_bytes().expect("encode");
        bytes[0] ^= 1;
        let json = serde_json::to_string(&bytes).expect("serialize bytes");
        let error = serde_json::from_str::<MockProof>(&json)
            .err()
            .expect("corrupted bytes must fail");
        assert!(error.to_string().contains("invalid proof magic"), "{error}");
    }

    struct EmptyWithHugeHint;

    impl<'de> serde::de::SeqAccess<'de> for EmptyWithHugeHint {
        type Error = serde::de::value::Error;

        fn next_element_seed<T: DeserializeSeed<'de>>(
            &mut self,
            _: T,
        ) -> core::result::Result<Option<T::Value>, Self::Error> {
            Ok(None)
        }

        fn size_hint(&self) -> Option<usize> {
            Some(usize::MAX)
        }
    }

    #[test]
    fn sequence_size_hint_does_not_control_allocation() {
        use serde::de::Visitor;
        struct ProofVisitor;
        impl<'de> Visitor<'de> for ProofVisitor {
            type Value = MockProof;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a mock proof")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                seq: A,
            ) -> core::result::Result<Self::Value, A::Error> {
                use serde::Deserialize as _;
                MockProof::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
            }
        }
        let error = ProofVisitor
            .visit_seq(EmptyWithHugeHint)
            .err()
            .expect("empty input must fail");
        assert!(error.to_string().contains("truncated"), "{error}");
    }

    #[test]
    fn sequence_buffer_stops_at_the_envelope_length() {
        use serde::{Deserialize as _, de::value::Error as DeError};
        let input = bootstrap_proof()
            .to_bytes()
            .expect("encode")
            .into_iter()
            .chain(core::iter::repeat(0u8));
        let error = MockProof::deserialize(SeqDeserializer::<_, DeError>::new(input))
            .err()
            .expect("overlong input must fail");
        assert!(
            error.to_string().contains("exceeds its fixed length"),
            "{error}"
        );
    }
}
