use alloc::{string::ToString as _, vec, vec::Vec};

use ragu_core::{
    Result,
    pasta::{Ep, EpAffine, Eq, EqAffine, Fp, Fq},
};
use rand::{SeedableRng as _, rngs::StdRng};
use udon::curve::Affine;

use crate::{
    Application, ApplicationBuilder, Header, Index, Pcd, Proof, Step, StepCtx, Suffix, WireHeader,
    wire::Error,
};

/// Header carrying one of every element kind, as a rich application header.
struct MixedHeader;

#[derive(Clone, Debug, PartialEq, Eq)]
struct MixedData {
    fp: Fp,
    fq: Fq,
    ep: Ep,
    eq: Eq,
}

impl Header for MixedHeader {
    type Data = MixedData;

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        (vec![data.fp], vec![data.fq], vec![data.ep], vec![data.eq])
    }
}

impl WireHeader for MixedHeader {
    fn decode(fps: &[Fp], fqs: &[Fq], eps: &[Ep], eqs: &[Eq]) -> Option<Self::Data> {
        if let ([fp], [fq], [ep], [eq]) = (fps, fqs, eps, eqs) {
            Some(MixedData {
                fp: *fp,
                fq: *fq,
                ep: *ep,
                eq: *eq,
            })
        } else {
            None
        }
    }
}

/// A header with the same shape but a different suffix.
struct OtherHeader;

impl Header for OtherHeader {
    type Data = MixedData;

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        MixedHeader::encode(data)
    }
}

impl WireHeader for OtherHeader {
    fn decode(fps: &[Fp], fqs: &[Fq], eps: &[Ep], eqs: &[Eq]) -> Option<Self::Data> {
        MixedHeader::decode(fps, fqs, eps, eqs)
    }
}

/// Seed step producing a [`MixedHeader`].
struct MixedSeedStep;

impl Step for MixedSeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = MixedHeader;
    type Right = ();
    type Witness<'source> = MixedData;

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((witness, ()))
    }
}

fn mixed_app() -> Application {
    ApplicationBuilder::new()
        .register(MixedSeedStep)
        .expect("register")
        .finalize()
        .expect("finalize")
}

fn mixed_data() -> MixedData {
    MixedData {
        fp: Fp::from(42),
        fq: Fq::from(7),
        ep: EpAffine::generator().to_projective(),
        eq: EqAffine::generator().to_projective(),
    }
}

fn mixed_pcd() -> Pcd<MixedHeader> {
    mixed_app()
        .seed(&mut StdRng::from_seed([7; 32]), MixedSeedStep, mixed_data())
        .expect("seed")
        .0
}

#[test]
fn proof_round_trip() {
    for proof in [Proof::bootstrap(), mixed_pcd().proof().clone()] {
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), Proof::encoded_len());
        let decoded = Proof::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded.to_bytes(), bytes);
    }
}

#[test]
fn pcd_round_trip() {
    let pcd = mixed_pcd();
    let bytes = pcd.to_bytes().expect("encode");
    let decoded = Pcd::<MixedHeader>::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded.data(), &mixed_data());
    assert_eq!(decoded.proof().to_bytes(), pcd.proof().to_bytes());

    let unit = Proof::bootstrap().carry::<()>(());
    let bytes = unit.to_bytes().expect("encode");
    let decoded = Pcd::<()>::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded.data(), &());
}

/// The trivial proof's full encoding, recomputed independently of the crate.
/// A change here is a format change: bump the schema or envelope version.
#[test]
fn golden_trivial_proof() {
    let expected: &[u8] = &[
        0x52, 0x41, 0x47, 0x55, 0x50, 0x43, 0x44, 0x00, // magic
        0x03, 0x00, // envelope version
        0x03, 0x00, // payload kind: mock proof
        0x01, 0x00, // schema version
        0x01, 0x00, // protocol version
        0x00, 0x00, 0x00, 0x00, // rank
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header elements
    ];
    let bytes = Proof::bootstrap().to_bytes();
    assert_eq!(&bytes[..28], expected);
    assert_eq!(
        bytes[28..].to_vec(),
        vec![
            // step index 1 (internal)
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
        .into_iter()
        .chain(
            [
                // header hash
                0xcd, 0x6d, 0x63, 0xa9, 0x3b, 0x98, 0x61, 0x2d, 0x26, 0x50, 0xef, 0xde, 0x8f, 0xf4,
                0x99, 0x1d, 0xe7, 0xd2, 0xe4, 0xe3, 0x4d, 0xc4, 0xa2, 0xa3, 0x66, 0xe2, 0x55, 0xa0,
                0x58, 0xd4, 0xc7, 0x1c,
            ]
            .into_iter()
            // witness hash
            .chain([
                0xbc, 0x51, 0x90, 0x92, 0xac, 0xba, 0x34, 0x4c, 0xf3, 0x9e, 0x3b, 0x15, 0xe7, 0x4a,
                0x88, 0xa9, 0xe4, 0x5f, 0xc4, 0xa3, 0x09, 0xbb, 0xc5, 0x90, 0x07, 0x99, 0xcf, 0xbe,
                0x69, 0x2d, 0x6e, 0x14,
            ])
            // binding
            .chain([
                0x25, 0x46, 0xec, 0xae, 0xe1, 0xe6, 0x1f, 0x8d, 0x86, 0x83, 0x67, 0x45, 0x9c, 0x3d,
                0x0e, 0x66, 0xc3, 0x82, 0xd2, 0x92, 0xdd, 0xa9, 0x58, 0x06, 0x70, 0xda, 0xb4, 0x62,
                0x5e, 0x0b, 0x36, 0x67,
            ])
            // rerandomization tag
            .chain([0u8; 32]),
        )
        .collect::<Vec<u8>>()
    );
}

#[test]
fn rejects_every_envelope_component_mutation() {
    let bytes = Proof::bootstrap().to_bytes();
    for (offset, reason) in [
        (0, "invalid proof magic"),
        (8, "unsupported proof envelope version"),
        (10, "proof payload kind mismatch"),
        (12, "unsupported proof schema version"),
        (14, "unsupported proof protocol version"),
        (16, "mock proofs carry no rank"),
        (20, "mock header element count exceeds the limit"),
    ] {
        let mut mutated = bytes.clone();
        mutated[offset] ^= 1;
        assert!(
            matches!(Proof::from_bytes(&mutated), Err(Error::Invalid { offset: at, reason: why, .. }) if at == offset && why == reason),
            "offset {offset} must fail with {reason}"
        );
    }
}

#[test]
fn rejects_truncation_and_trailing_bytes() {
    let bytes = mixed_pcd().to_bytes().expect("encode");
    assert!(matches!(
        Proof::from_bytes(&Proof::bootstrap().to_bytes()[..Proof::encoded_len() - 1]),
        Err(Error::Truncated { .. }) | Err(Error::Length { .. })
    ));
    assert!(matches!(
        Pcd::<MixedHeader>::from_bytes(&bytes[..bytes.len() - 1]),
        Err(Error::Length { .. })
    ));
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(
        Pcd::<MixedHeader>::from_bytes(&longer),
        Err(Error::Length { .. })
    ));
}

#[test]
fn rejects_binding_mismatch() {
    let mut bytes = Proof::bootstrap().to_bytes();
    // The binding hash follows the step index and two hashes.
    bytes[28 + 8 + 64] ^= 1;
    assert!(matches!(
        Proof::from_bytes(&bytes),
        Err(Error::Invalid {
            reason: "mock proof binding mismatch",
            ..
        })
    ));
}

#[test]
fn rejects_suffix_mismatch() {
    let bytes = mixed_pcd().to_bytes().expect("encode");
    assert!(matches!(
        Pcd::<OtherHeader>::from_bytes(&bytes),
        Err(Error::Invalid {
            reason: "mock PCD header suffix mismatch",
            ..
        })
    ));
}

#[test]
fn rejects_counts_disagreeing_with_the_envelope() {
    let mut bytes = mixed_pcd().to_bytes().expect("encode");
    // First count follows the proof payload and suffix.
    bytes[28 + 136 + 8] ^= 1;
    assert!(matches!(
        Pcd::<MixedHeader>::from_bytes(&bytes),
        Err(Error::Invalid {
            reason: "header element counts do not match the envelope",
            ..
        })
    ));
}

#[test]
fn rejects_noncanonical_field_element() {
    let mut bytes = mixed_pcd().to_bytes().expect("encode");
    // First Fp follows the head: envelope, proof, suffix, counts.
    let first = 28 + 136 + 8 + 32;
    for byte in &mut bytes[first..first + 32] {
        *byte = 0xff;
    }
    assert!(matches!(
        Pcd::<MixedHeader>::from_bytes(&bytes),
        Err(Error::Invalid {
            reason: "non-canonical field element",
            ..
        })
    ));
}

#[test]
fn rejects_identity_point() {
    let mut bytes = mixed_pcd().to_bytes().expect("encode");
    // First point: after one Fp and one Fq.
    let first_point = 28 + 136 + 8 + 32 + 64;
    let identity = EpAffine::identity().to_bytes();
    bytes[first_point..first_point + 32].copy_from_slice(identity.as_ref());
    assert!(matches!(
        Pcd::<MixedHeader>::from_bytes(&bytes),
        Err(Error::Invalid { .. })
    ));
}

#[test]
fn rejects_data_that_does_not_reencode_to_the_proof() {
    // A well-formed payload whose data was replaced by another value with the
    // same shape: the header hash no longer matches.
    let mut bytes = mixed_pcd().to_bytes().expect("encode");
    let first = 28 + 136 + 8 + 32;
    // Fp::from(42) -> Fp::from(43)
    bytes[first] = 43;
    assert!(matches!(
        Pcd::<MixedHeader>::from_bytes(&bytes),
        Err(Error::Invalid {
            reason: "mock PCD header data does not match its proof",
            ..
        })
    ));
}

#[test]
fn real_format_payload_kinds_fail_closed() {
    for tag in [1u16, 2, 5] {
        let mut bytes = Proof::bootstrap().to_bytes();
        bytes[10..12].copy_from_slice(&tag.to_le_bytes());
        assert!(matches!(
            Proof::from_bytes(&bytes),
            Err(Error::Invalid {
                reason: "proof payload kind mismatch",
                ..
            })
        ));
    }
}

#[cfg(feature = "serde")]
mod serde_tests {
    use serde::de::{DeserializeSeed, value::SeqDeserializer};

    use super::*;

    #[test]
    fn serde_round_trip() {
        let proof = Proof::bootstrap();
        let json = serde_json::to_string(&proof).expect("serialize");
        let decoded: Proof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.to_bytes(), proof.to_bytes());

        let pcd = mixed_pcd();
        let json = serde_json::to_string(&pcd).expect("serialize");
        let decoded: Pcd<MixedHeader> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.data(), &mixed_data());
    }

    #[test]
    fn serde_rejects_corruption() {
        let mut bytes = Proof::bootstrap().to_bytes();
        bytes[0] ^= 1;
        let json = serde_json::to_string(&bytes).expect("serialize bytes");
        let error = serde_json::from_str::<Proof>(&json)
            .err()
            .expect("corrupted bytes must fail to decode");
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
        struct P;
        impl<'de> Visitor<'de> for P {
            type Value = Proof;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a mock proof")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                seq: A,
            ) -> core::result::Result<Self::Value, A::Error> {
                use serde::Deserialize as _;
                Proof::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
            }
        }
        let error = P
            .visit_seq(EmptyWithHugeHint)
            .err()
            .expect("empty input must fail to decode");
        assert!(error.to_string().contains("truncated"), "{error}");
    }

    #[test]
    fn sequence_buffer_stops_at_the_envelope_length() {
        use serde::{Deserialize as _, de::value::Error as DeError};
        // One byte beyond a mock proof's fixed length is refused.
        let input = Proof::bootstrap()
            .to_bytes()
            .into_iter()
            .chain(core::iter::repeat(0u8));
        let error = Proof::deserialize(SeqDeserializer::<_, DeError>::new(input))
            .err()
            .expect("overlong input must fail to decode");
        assert!(
            error.to_string().contains("exceeds its fixed length"),
            "{error}"
        );
    }
}
