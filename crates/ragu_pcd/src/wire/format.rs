//! Versioned envelope over fixed-length proofs and compressed proofs.

use alloc::vec::Vec;

use ragu_circuits::polynomials::Rank;

use crate::{
    CompressedProof, Proof,
    profile::ProfiledCycle,
    wire::{Decode, Dimensions, Encode, Error, MAX_RANK, Reader},
};

const MAGIC: &[u8; 8] = b"RAGUPCD\0";
const ENVELOPE_VERSION: u16 = 3;
/// Each proof representation has its own payload kind and schema version.
#[derive(Clone, Copy)]
pub(crate) enum PayloadKind {
    Proof,
    Compressed,
}

impl PayloadKind {
    fn tag(self) -> u16 {
        match self {
            Self::Proof => 1,
            Self::Compressed => 2,
        }
    }

    fn schema_version(self) -> u16 {
        match self {
            Self::Proof => PROOF_SCHEMA_VERSION,
            Self::Compressed => COMPRESSED_SCHEMA_VERSION,
        }
    }
}
const PROOF_SCHEMA_VERSION: u16 = 2;
const COMPRESSED_SCHEMA_VERSION: u16 = 2;
// Matches the verification semantics identified by RAGU_TAG and IPA_TAG.
const PROTOCOL_VERSION: u16 = 1;
pub(crate) const ENVELOPE_SIZE: usize = 28;

impl<C: ProfiledCycle, R: Rank> Proof<C, R> {
    /// Encodes this proof with its version envelope. The rank comes from `R`.
    ///
    /// This checks representation, not proof validity. The caller selects
    /// the expected application through its deployment or consensus rules.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unencodable`] if dimensions exceed the limits in
    /// [`wire`](crate::wire), vectors have inconsistent lengths or any point
    /// is the identity.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<'static>> {
        encode(self, PayloadKind::Proof, Dimensions::of::<R>())
    }

    /// The exact encoded length, including the envelope. Bound transport
    /// input to this size before buffering it.
    pub fn encoded_len() -> usize {
        ENVELOPE_SIZE + <Self as Decode>::encoded_len(Dimensions::of::<R>())
    }

    /// Decodes one proof, checking the envelope, bounded dimensions and exact
    /// payload length before reading its fields. The declared rank must
    /// match `R`.
    ///
    /// Attach the accompanying output data with [`carry`](Self::carry),
    /// compress with [`Application::compress`](crate::Application::compress)
    /// and verify with
    /// [`Application::verify_compressed`](crate::Application::verify_compressed)
    /// before accepting the proof or using it as a child.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<'_>> {
        decode(bytes, PayloadKind::Proof, Some(R::RANK))
    }

    /// The exact length of the encoding whose envelope `bytes` begins with,
    /// checked as [`from_bytes`](Self::from_bytes) checks it.
    #[cfg(feature = "serde")]
    pub(crate) fn framed_len(bytes: &[u8]) -> Result<usize, Error<'_>> {
        framed_len::<Self>(bytes, PayloadKind::Proof, Some(R::RANK))
    }
}

impl<C: ProfiledCycle> CompressedProof<C> {
    /// Encodes this compressed proof with its version envelope. The rank
    /// comes from its IPA round count. This checks representation, not
    /// proof validity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unencodable`] if dimensions exceed the limits in
    /// [`wire`](crate::wire), vectors have inconsistent lengths or any point
    /// is the identity.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<'static>> {
        let dims = Dimensions {
            rank: self
                .native
                .opening
                .rounds
                .len()
                .try_into()
                .map_err(|_| Error::Unencodable)?,
        };
        encode(self, PayloadKind::Compressed, dims)
    }

    /// The exact encoded length for the expected rank, including the
    /// envelope. Bound transport input to this size before buffering it.
    /// Decoding admits any bounded rank, and
    /// [`verify_compressed`](crate::Application::verify_compressed) rejects
    /// every shape but the application's.
    pub fn encoded_len<R: Rank>() -> usize {
        ENVELOPE_SIZE + <Self as Decode>::encoded_len(Dimensions::of::<R>())
    }

    /// Decodes one compressed proof, checking the envelope, bounded dimensions
    /// and exact payload length before reading its fields. The rank comes from
    /// the envelope; verification checks the application's shape.
    /// The caller selects the expected application and parameters through
    /// its deployment or consensus rules.
    ///
    /// Attach the accompanying output data with [`carry`](Self::carry) and
    /// use [`Application::verify_compressed`](crate::Application::verify_compressed)
    /// before accepting the proof.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<'_>> {
        decode(bytes, PayloadKind::Compressed, None)
    }

    /// The exact length of the encoding whose envelope `bytes` begins with,
    /// checked as [`from_bytes`](Self::from_bytes) checks it.
    #[cfg(feature = "serde")]
    pub(crate) fn framed_len(bytes: &[u8]) -> Result<usize, Error<'_>> {
        framed_len::<Self>(bytes, PayloadKind::Compressed, None)
    }
}

pub(crate) fn write_envelope(payload: PayloadKind, dims: Dimensions, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(MAGIC);
    for word in [
        ENVELOPE_VERSION,
        payload.tag(),
        payload.schema_version(),
        PROTOCOL_VERSION,
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(&dims.rank.to_le_bytes());
    // The header size: no payload of these schemas carries a header.
    bytes.extend_from_slice(&0u64.to_le_bytes());
}

fn encode<T: Encode + Decode>(
    proof: &T,
    payload: PayloadKind,
    dims: Dimensions,
) -> Result<Vec<u8>, Error<'static>> {
    if dims.rank > MAX_RANK {
        return Err(Error::Unencodable);
    }
    let mut bytes = Vec::with_capacity(ENVELOPE_SIZE + T::encoded_len(dims));
    write_envelope(payload, dims, &mut bytes);
    proof.encode(&mut bytes, dims)?;
    Ok(bytes)
}

fn decode<T: Decode>(
    bytes: &[u8],
    payload: PayloadKind,
    rank: Option<u32>,
) -> Result<T, Error<'_>> {
    let (mut reader, dims) = open(bytes, payload, rank)?;
    let expected = ENVELOPE_SIZE + T::encoded_len(dims);
    if bytes.len() != expected {
        return Err(Error::Length {
            expected,
            actual: bytes.len(),
        });
    }
    T::decode(&mut reader, dims)
}

/// The exact length of the encoding whose envelope `bytes` begins with, once
/// the envelope and its dimensions pass the checks `decode` applies.
#[cfg(feature = "serde")]
fn framed_len<T: Decode>(
    bytes: &[u8],
    payload: PayloadKind,
    rank: Option<u32>,
) -> Result<usize, Error<'_>> {
    let (_, dims) = open(bytes, payload, rank)?;
    Ok(ENVELOPE_SIZE + T::encoded_len(dims))
}

/// Checks the envelope and bounds its dimensions before allocating any payload.
fn open<'a>(
    bytes: &'a [u8],
    payload: PayloadKind,
    expected_rank: Option<u32>,
) -> Result<(Reader<'a>, Dimensions), Error<'a>> {
    let mut reader = Reader::new(bytes);
    let envelope = reader.take(ENVELOPE_SIZE)?;
    let mut known = Vec::with_capacity(ENVELOPE_SIZE);
    write_envelope(payload, Dimensions::default(), &mut known);
    // Report the exact rejected component. Every check precedes payload decoding.
    for (start, end, reason) in [
        (0, 8, "invalid proof magic"),
        (8, 10, "unsupported proof envelope version"),
        (10, 12, "proof payload kind mismatch"),
        (12, 14, "unsupported proof schema version"),
        (14, 16, "unsupported proof protocol version"),
    ] {
        if envelope[start..end] != known[start..end] {
            return Err(Error::Invalid {
                offset: start,
                bytes: &envelope[start..end],
                reason,
            });
        }
    }
    let rank_bytes = &envelope[16..20];
    let rank = u32::from_le_bytes(rank_bytes.try_into().expect("4-byte rank"));
    let reason = match expected_rank {
        Some(expected) if rank != expected => Some("proof rank mismatch"),
        Some(_) if rank > MAX_RANK => Some("proof rank exceeds the limit"),
        None if rank > MAX_RANK => Some("compressed proof rank exceeds the limit"),
        _ => None,
    };
    if let Some(reason) = reason {
        return Err(Error::Invalid {
            offset: 16,
            bytes: rank_bytes,
            reason,
        });
    }
    // No payload of these schemas carries a header, so any other header
    // size would be a second encoding of the same payload.
    let header_bytes = &envelope[20..28];
    if header_bytes != &known[20..28] {
        return Err(Error::Invalid {
            offset: 20,
            bytes: header_bytes,
            reason: "proof header size must be zero",
        });
    }
    Ok((reader, Dimensions { rank }))
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::{ProductionRank, TestRank};
    use ragu_core::pasta::Pasta;

    use super::*;
    use crate::profile::{Shape, Standard};

    // Schema v2 is the standard profile's shape under `ragu-pcd-v1`, with
    // each step folding its own application claim. A change to either moves
    // the layout or the verifier semantics and needs a new schema or protocol
    // version, not a silent re-pin.
    #[test]
    fn schema_v2_pins_protocol_and_shape() {
        assert_eq!(crate::RAGU_TAG, b"ragu-pcd-v1");
        assert_eq!(crate::ipa::IPA_TAG, b"ragu-ipa-v1");
        assert_eq!(ragu_primitives::ENDOSCALAR_BITS, 143);
        assert_eq!(
            Shape::of::<Standard>(),
            Shape {
                native_rx: 44,
                nested_points: 104,
                nested_steps: 26,
                nested_rx: 39,
                native_points: 93,
                native_steps: 23,
            }
        );
    }

    #[test]
    fn encoded_length_is_a_function_of_profile_and_rank() {
        // Every polynomial of the shape, with `2^rank` coefficients each; a
        // commitment per polynomial plus the nested challenges partial; the
        // bridge alpha and nine challenges; one circuit index. The envelope
        // adds 28 bytes.
        fn payload<R: Rank>() -> usize {
            let polynomials = Shape::of::<Standard>().polynomials();
            polynomials * R::num_coeffs() * 32 + (polynomials + 1) * 32 + 10 * 32 + 4
        }
        assert_eq!(
            <Proof<Pasta, ProductionRank> as Decode>::encoded_len(
                Dimensions::of::<ProductionRank>()
            ),
            payload::<ProductionRank>()
        );
        assert_eq!(
            <Proof<Pasta, TestRank> as Decode>::encoded_len(Dimensions::of::<TestRank>()),
            payload::<TestRank>()
        );
        assert_eq!(
            Proof::<Pasta, ProductionRank>::encoded_len(),
            28 + payload::<ProductionRank>()
        );
        // 92 instance points; 17 instance scalars; per side 6+2R points,
        // 21 scalars; plus the circuit index and common envelope.
        assert_eq!(
            CompressedProof::<Pasta>::encoded_len::<ProductionRank>(),
            28 + 4 + (92 + 17 + 2 * (6 + 2 * 13 + 21)) * 32
        );
    }

    #[test]
    fn rejects_other_envelope_versions() {
        let dims = Dimensions::of::<TestRank>();
        for (kind, length) in [
            (PayloadKind::Proof, Proof::<Pasta, TestRank>::encoded_len()),
            (
                PayloadKind::Compressed,
                CompressedProof::<Pasta>::encoded_len::<TestRank>(),
            ),
        ] {
            let mut bytes = Vec::with_capacity(length);
            write_envelope(kind, dims, &mut bytes);
            bytes.resize(length, 0);
            // Old layouts and future versions cannot be reinterpreted, even
            // when their input has the receiving type's expected length.
            for version in [1u16, 2, 4] {
                bytes[8..10].copy_from_slice(&version.to_le_bytes());
                assert!(matches!(
                    open(&bytes, kind, Some(TestRank::RANK)),
                    Err(Error::Invalid {
                        offset: 8,
                        reason: "unsupported proof envelope version",
                        ..
                    })
                ));
            }
        }
    }

    #[test]
    fn dimensions_are_bounded_before_payload_decoding() {
        for (kind, expected_rank) in [
            (PayloadKind::Proof, Some(TestRank::RANK)),
            (PayloadKind::Compressed, None),
        ] {
            // No payload carries a header, so only a zero header size is
            // admitted: any other would be a second encoding.
            for header_size in [1, 4, u64::MAX] {
                let mut bytes = Vec::new();
                write_envelope(kind, Dimensions::of::<TestRank>(), &mut bytes);
                bytes[20..28].copy_from_slice(&header_size.to_le_bytes());
                assert!(matches!(
                    open(&bytes, kind, expected_rank),
                    Err(Error::Invalid {
                        offset: 20,
                        reason: "proof header size must be zero",
                        ..
                    })
                ));
            }
        }
        let mut bytes = Vec::new();
        write_envelope(
            PayloadKind::Compressed,
            Dimensions::of::<TestRank>(),
            &mut bytes,
        );
        bytes[16..20].copy_from_slice(&(MAX_RANK + 1).to_le_bytes());
        assert!(matches!(
            open(&bytes, PayloadKind::Compressed, None),
            Err(Error::Invalid {
                offset: 16,
                reason: "compressed proof rank exceeds the limit",
                ..
            })
        ));
    }
}
