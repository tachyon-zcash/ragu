//! Canonical byte encoding for mock proofs and proof-carrying data.
//!
//! This mirrors `ragu_pcd::wire` (added in #875) for the mock: [`Proof`] and
//! [`Pcd`] reach bytes through `to_bytes` / `from_bytes` with the same
//! 28-byte versioned envelope, and the optional `serde` adapters carry the
//! same bytes. The mock shares the real format's magic, envelope layout and
//! envelope version, and occupies its own payload kinds (3 and 4), so a mock
//! encoding fed to a real decoder — or the reverse — fails closed on the
//! payload kind rather than being reinterpreted.
//!
//! # Envelope
//!
//! | Offset | Size | Meaning |
//! | --- | --- | --- |
//! | 0 | 8 | Magic: `RAGUPCD` and a NUL |
//! | 8 | 2 | Envelope version: 3 |
//! | 10 | 2 | Payload kind: 3 mock proof, 4 mock PCD |
//! | 12 | 2 | Schema version of that payload kind: 1 |
//! | 14 | 2 | Protocol version: 1 (the mock binding hashes) |
//! | 16 | 4 | Rank: always 0; mock proofs carry no rank |
//! | 20 | 8 | Header elements: 0 for a proof; total encoded header elements for a PCD |
//!
//! A mock proof's payload is its five fields in declaration order: the step
//! index, then the header, witness, binding and rerandomization hashes. A mock
//! PCD's payload is its proof, the header suffix, four element counts, then
//! the header's encoded elements: canonical field elements and compressed
//! non-identity points, as in the real format.
//!
//! Decoding checks the envelope, then the exact length the counts imply,
//! before decoding any element. For a PCD, decoding additionally requires the
//! suffix to match the receiving type's [`Header::SUFFIX`], the header data
//! to re-encode to the proof's header hash, and the proof's internal binding
//! to check — together these are the mock equivalent of verifying on decode.
//! As in the real format, this establishes representation, not the witness
//! semantics the mock's `fuse` enforces at proving time.
//!
//! # Versions
//!
//! The schema version fixes a payload's field order and codecs; the envelope
//! version fixes the layout above; the protocol version follows the mock's
//! hashing semantics. Changing any of them means a new version and explicit
//! dispatch in the decoder — never silent reinterpretation.

use alloc::vec::Vec;

use ragu_core::pasta::{Ep, EpAffine, Eq, EqAffine, Fp, Fq};
use udon::{
    curve::{Affine, Projective},
    field::Field,
};

use super::{
    header::{Header, Suffix},
    proof::{Pcd, Proof, compute_binding, compute_header_hash},
    step::Index,
};

#[cfg(feature = "serde")]
mod serde;

/// The envelope prepended to every encoding, in bytes.
pub(crate) const ENVELOPE_SIZE: usize = 28;

const MAGIC: &[u8; 8] = b"RAGUPCD\0";
// Matches `ragu_pcd::wire`: one layout, one version namespace.
const ENVELOPE_VERSION: u16 = 3;
// Follows the mock's hashing semantics: the header, witness, binding and
// rerandomization digests in `mock::proof`.
const PROTOCOL_VERSION: u16 = 1;
const MOCK_PROOF_SCHEMA_VERSION: u16 = 1;
const MOCK_PCD_SCHEMA_VERSION: u16 = 1;
/// Largest encoded header admitted by the byte formats, in total elements.
const MAX_HEADER_ELEMENTS: u64 = 1 << 12;
/// Step index plus four hashes.
const PROOF_PAYLOAD_LEN: usize = 8 + 4 * 32;
/// Proof, header suffix and four element counts.
const PCD_HEAD_LEN: usize = PROOF_PAYLOAD_LEN + 8 + 4 * 8;

/// Each mock representation has its own payload kind and schema version,
/// disjoint from the real format's kinds 1 and 2.
#[derive(Clone, Copy)]
enum PayloadKind {
    MockProof,
    MockPcd,
}

impl PayloadKind {
    fn tag(self) -> u16 {
        match self {
            Self::MockProof => 3,
            Self::MockPcd => 4,
        }
    }

    fn schema_version(self) -> u16 {
        match self {
            Self::MockProof => MOCK_PROOF_SCHEMA_VERSION,
            Self::MockPcd => MOCK_PCD_SCHEMA_VERSION,
        }
    }
}

/// A malformed byte encoding, or a value that has none.
///
/// Mirrors `ragu_pcd::wire::Error`. Offending byte slices borrow the input
/// rather than copying hostile data. New versions of the format may add
/// variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error<'a> {
    /// The value to encode has no encoding: a point slot holds the identity,
    /// which no slot admits. Decoding never reports this.
    Unencodable,
    /// The input is not the exact encoded length of the expected value.
    Length {
        /// The length every valid encoding has.
        expected: usize,
        /// The length received.
        actual: usize,
    },
    /// The next value extends beyond the input.
    Truncated {
        /// Start of the missing value.
        offset: usize,
        /// Number of bytes requested.
        requested: usize,
        /// Available bytes at that position.
        bytes: &'a [u8],
    },
    /// Bytes are not a canonical representation of the expected value.
    Invalid {
        /// Start of the offending value.
        offset: usize,
        /// The offending bytes.
        bytes: &'a [u8],
        /// Explanation of the rejected representation.
        reason: &'static str,
    },
}

impl core::fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unencodable => {
                f.write_str("the value has no encoding: a point slot holds the identity")
            }
            Self::Length { expected, actual } => {
                write!(
                    f,
                    "incorrect encoded length: expected {expected} bytes, got {actual}"
                )
            }
            Self::Truncated {
                offset,
                requested,
                bytes,
            } => write!(
                f,
                "truncated input at byte {offset}: need {requested} bytes, have {}",
                bytes.len()
            ),
            Self::Invalid { offset, reason, .. } => {
                write!(f, "invalid encoding at byte {offset}: {reason}")
            }
        }
    }
}
impl core::error::Error for Error<'_> {}

/// A borrowed byte cursor.
struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn remaining(&self) -> &'a [u8] {
        &self.input[self.offset..]
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error<'a>> {
        let bytes = self.remaining().get(..length).ok_or(Error::Truncated {
            offset: self.offset,
            requested: length,
            bytes: self.remaining(),
        })?;
        self.offset += length;
        Ok(bytes)
    }

    fn take_u64(&mut self) -> Result<u64, Error<'a>> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("8-byte word")))
    }

    fn take_hash(&mut self) -> Result<[u8; 32], Error<'a>> {
        let bytes = self.take(32)?;
        Ok(bytes.try_into().expect("32-byte hash"))
    }

    fn take_scalar<F: Field>(&mut self) -> Result<F, Error<'a>> {
        let offset = self.offset();
        let mut repr = F::ZERO.to_bytes();
        let bytes = self.take(repr.as_ref().len())?;
        repr.as_mut().copy_from_slice(bytes);
        // `Field::from_bytes` accepts the canonical representation alone, so
        // every element has one spelling.
        F::from_bytes(repr).ok_or(Error::Invalid {
            offset,
            bytes,
            reason: "non-canonical field element",
        })
    }

    fn take_point<A: Affine>(&mut self) -> Result<A, Error<'a>> {
        let offset = self.offset();
        let mut repr = A::identity().to_bytes();
        let bytes = self.take(repr.as_ref().len())?;
        repr.as_mut().copy_from_slice(bytes);
        // `Affine::from_bytes` accepts the canonical representation of a
        // group element alone, so every point has one spelling.
        let point = A::from_bytes(repr).ok_or(Error::Invalid {
            offset,
            bytes,
            reason: "invalid compressed point",
        })?;
        if point.is_identity() {
            return Err(Error::Invalid {
                offset,
                bytes,
                reason: "identity point",
            });
        }
        Ok(point)
    }
}

fn write_envelope(payload: PayloadKind, header_elements: u64, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(MAGIC);
    for word in [
        ENVELOPE_VERSION,
        payload.tag(),
        payload.schema_version(),
        PROTOCOL_VERSION,
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    // Mock proofs carry no rank.
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&header_elements.to_le_bytes());
}

/// Checks the envelope and bounds its dimensions before any payload is read.
fn open<'a>(bytes: &'a [u8], payload: PayloadKind) -> Result<(Reader<'a>, u64), Error<'a>> {
    let mut reader = Reader::new(bytes);
    let envelope = reader.take(ENVELOPE_SIZE)?;
    let mut known = Vec::with_capacity(ENVELOPE_SIZE);
    write_envelope(payload, 0, &mut known);
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
    if rank_bytes != [0; 4] {
        return Err(Error::Invalid {
            offset: 16,
            bytes: rank_bytes,
            reason: "mock proofs carry no rank",
        });
    }
    let header_bytes = &envelope[20..28];
    let header_elements = u64::from_le_bytes(header_bytes.try_into().expect("8-byte size"));
    let over_limit = match payload {
        PayloadKind::MockProof => header_elements != 0,
        PayloadKind::MockPcd => header_elements > MAX_HEADER_ELEMENTS,
    };
    if over_limit {
        return Err(Error::Invalid {
            offset: 20,
            bytes: header_bytes,
            reason: "mock header element count exceeds the limit",
        });
    }
    Ok((reader, header_elements))
}

/// Reads the fixed mock-proof payload from `reader`.
fn decode_proof_payload<'a>(reader: &mut Reader<'a>) -> Result<Proof, Error<'a>> {
    let index_offset = reader.offset();
    let step_index = reader.take_u64()?;
    let header_hash = reader.take_hash()?;
    let witness_hash = reader.take_hash()?;
    let binding_offset = reader.offset();
    let binding = reader.take_hash()?;
    let rerand_tag = reader.take_hash()?;

    let step_index = Index::from_value(step_index).map_err(|_| Error::Invalid {
        offset: index_offset,
        bytes: &reader.input[index_offset..index_offset + 8],
        reason: "invalid step index",
    })?;
    if compute_binding(step_index, &header_hash, &witness_hash) != binding {
        return Err(Error::Invalid {
            offset: binding_offset,
            bytes: &reader.input[binding_offset..binding_offset + 32],
            reason: "mock proof binding mismatch",
        });
    }
    Ok(Proof {
        step_index,
        header_hash,
        witness_hash,
        binding,
        rerand_tag,
    })
}

fn write_proof_payload(proof: &Proof, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&proof.step_index.get().to_le_bytes());
    bytes.extend_from_slice(&proof.header_hash);
    bytes.extend_from_slice(&proof.witness_hash);
    bytes.extend_from_slice(&proof.binding);
    bytes.extend_from_slice(&proof.rerand_tag);
}

impl Proof {
    /// Encodes this proof with its version envelope.
    ///
    /// This is the versioned wire format, unlike [`Proof::serialize`], which
    /// fills the fixed-size buffer the real proof's compressed encoding
    /// occupies. This checks representation, not proof validity.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::encoded_len());
        write_envelope(PayloadKind::MockProof, 0, &mut bytes);
        write_proof_payload(self, &mut bytes);
        bytes
    }

    /// The exact encoded length of a mock proof, envelope included.
    #[must_use]
    pub const fn encoded_len() -> usize {
        ENVELOPE_SIZE + PROOF_PAYLOAD_LEN
    }

    /// Decodes one mock proof, checking the envelope, the exact length and
    /// the internal binding before returning it.
    ///
    /// Attach the accompanying output data with [`Proof::carry`] and check it
    /// against the expected application with
    /// [`Application::verify`](crate::Application::verify) before accepting
    /// the proof or using it as a child.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<'_>> {
        let (mut reader, _) = open(bytes, PayloadKind::MockProof)?;
        let expected = Self::encoded_len();
        if bytes.len() != expected {
            return Err(Error::Length {
                expected,
                actual: bytes.len(),
            });
        }
        decode_proof_payload(&mut reader)
    }

    /// The exact length of a mock proof encoding, checked as
    /// [`from_bytes`](Self::from_bytes) checks it.
    #[cfg(any(test, feature = "serde"))]
    fn framed_len(bytes: &[u8]) -> Result<usize, Error<'_>> {
        open(bytes, PayloadKind::MockProof)?;
        Ok(Self::encoded_len())
    }
}

/// A [`Header`] whose data decodes from its wire element stream.
///
/// `Header::encode` decomposes data into `(Fp, Fq, Ep, Eq)` vectors; a
/// `WireHeader` also rebuilds data from them, which is what
/// [`Pcd::from_bytes`] needs. Implementations must accept exactly the values
/// their `encode` can produce: `Pcd::from_bytes` re-encodes the decoded data
/// and rejects the encoding unless it hashes to the proof's header hash.
pub trait WireHeader: Header {
    /// Rebuilds header data from its encoded element vectors, or `None` if
    /// they are not a value of this header.
    fn decode(fps: &[Fp], fqs: &[Fq], eps: &[Ep], eqs: &[Eq]) -> Option<Self::Data>;
}

impl WireHeader for () {
    fn decode(fps: &[Fp], fqs: &[Fq], eps: &[Ep], eqs: &[Eq]) -> Option<Self::Data> {
        (fps.is_empty() && fqs.is_empty() && eps.is_empty() && eqs.is_empty()).then_some(())
    }
}

impl<H: WireHeader> Pcd<H> {
    /// Encodes this PCD with its version envelope: the proof, the header
    /// suffix and the header's encoded elements.
    ///
    /// This checks representation, not proof validity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unencodable`] if the header encodes to more elements
    /// than the format admits or any point is the identity.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<'static>> {
        let (fps, fqs, eps, eqs) = H::encode(&self.data);
        let elements = (fps.len() + fqs.len() + eps.len() + eqs.len()) as u64;
        if elements > MAX_HEADER_ELEMENTS {
            return Err(Error::Unencodable);
        }
        let mut bytes = Vec::with_capacity(ENVELOPE_SIZE + PCD_HEAD_LEN + (elements as usize) * 32);
        write_envelope(PayloadKind::MockPcd, elements, &mut bytes);
        write_proof_payload(&self.proof, &mut bytes);
        bytes.extend_from_slice(&H::SUFFIX.get().to_le_bytes());
        for count in [fps.len(), fqs.len(), eps.len(), eqs.len()] {
            bytes.extend_from_slice(&(count as u64).to_le_bytes());
        }
        for element in fps.iter() {
            bytes.extend_from_slice(element.to_bytes().as_ref());
        }
        for element in fqs.iter() {
            bytes.extend_from_slice(element.to_bytes().as_ref());
        }
        for point in eps.iter() {
            let affine = point.to_affine();
            if affine.is_identity() {
                return Err(Error::Unencodable);
            }
            bytes.extend_from_slice(affine.to_bytes().as_ref());
        }
        for point in eqs.iter() {
            let affine = point.to_affine();
            if affine.is_identity() {
                return Err(Error::Unencodable);
            }
            bytes.extend_from_slice(affine.to_bytes().as_ref());
        }
        Ok(bytes)
    }

    /// Decodes one mock PCD, checking the envelope, the exact length the
    /// counts imply, the header suffix against `H`, every element's canonical
    /// representation, the header data's re-encoding against the proof's
    /// header hash, and the proof's internal binding.
    ///
    /// This establishes that the data is consistent with the proof, as
    /// [`Application::verify`](crate::Application::verify) checks it; the
    /// witness semantics were enforced when the proof was produced.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<'_>> {
        let (mut reader, elements) = open(bytes, PayloadKind::MockPcd)?;
        let proof = decode_proof_payload(&mut reader)?;

        let suffix_offset = reader.offset();
        let suffix = reader.take_u64()?;
        let suffix = Suffix::from_value(suffix).ok_or(Error::Invalid {
            offset: suffix_offset,
            bytes: &bytes[suffix_offset..suffix_offset + 8],
            reason: "invalid header suffix",
        })?;
        if suffix != H::SUFFIX {
            return Err(Error::Invalid {
                offset: suffix_offset,
                bytes: &bytes[suffix_offset..suffix_offset + 8],
                reason: "mock PCD header suffix mismatch",
            });
        }

        let counts_offset = reader.offset();
        let counts = [
            reader.take_u64()?,
            reader.take_u64()?,
            reader.take_u64()?,
            reader.take_u64()?,
        ];
        if counts.iter().sum::<u64>() != elements {
            return Err(Error::Invalid {
                offset: counts_offset,
                bytes: &bytes[counts_offset..counts_offset + 32],
                reason: "header element counts do not match the envelope",
            });
        }
        // The counts fix the exact length before any element is buffered.
        let expected = ENVELOPE_SIZE + PCD_HEAD_LEN + (elements as usize) * 32;
        if bytes.len() != expected {
            return Err(Error::Length {
                expected,
                actual: bytes.len(),
            });
        }

        let fps = (0..counts[0])
            .map(|_| reader.take_scalar::<Fp>())
            .collect::<Result<Vec<_>, _>>()?;
        let fqs = (0..counts[1])
            .map(|_| reader.take_scalar::<Fq>())
            .collect::<Result<Vec<_>, _>>()?;
        let eps = (0..counts[2])
            .map(|_| {
                reader
                    .take_point::<EpAffine>()
                    .map(|point| point.to_projective())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let eqs = (0..counts[3])
            .map(|_| {
                reader
                    .take_point::<EqAffine>()
                    .map(|point| point.to_projective())
            })
            .collect::<Result<Vec<_>, _>>()?;

        let data = H::decode(&fps, &fqs, &eps, &eqs).ok_or(Error::Invalid {
            offset: counts_offset,
            bytes: &bytes[counts_offset..],
            reason: "header data rejected by its header",
        })?;
        // The data must re-encode to the header the proof binds, exactly as
        // `Application::verify` checks. Decoded points are non-identity, so
        // re-encoding cannot fail.
        let encoded = H::encode(&data);
        if compute_header_hash(H::SUFFIX, &encoded).expect("decoded header data re-encodes")
            != proof.header_hash
        {
            return Err(Error::Invalid {
                offset: counts_offset,
                bytes: &bytes[counts_offset..],
                reason: "mock PCD header data does not match its proof",
            });
        }
        Ok(proof.carry::<H>(data))
    }

    /// The exact length of the encoding whose envelope `bytes` begins with,
    /// checked as [`from_bytes`](Self::from_bytes) checks it.
    #[cfg(any(test, feature = "serde"))]
    fn framed_len(bytes: &[u8]) -> Result<usize, Error<'_>> {
        let (_, elements) = open(bytes, PayloadKind::MockPcd)?;
        Ok(ENVELOPE_SIZE + PCD_HEAD_LEN + (elements as usize) * 32)
    }
}
