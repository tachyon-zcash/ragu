//! Versioned byte encoding for driver-backed mock proofs and PCDs.
//!
//! The 28-byte envelope uses the same magic and layout as ragu_pcd::wire.
//! Mock payload kinds 3 and 4 remain disjoint from the real proof kinds.
//! Schema and protocol version 2 identify the commitments, reusable polynomial
//! coefficients, and padded header hashing introduced by the driver-backed mock.
//! The envelope stores the proof rank and, for a PCD, the number of flattened
//! header field elements. A proof declares zero header elements. Its payload
//! contains the step index, header hash, three compressed commitments, witness
//! hash, binding hash, rerandomization tag, then three dense polynomials of
//! exactly R::num_coeffs() canonical coefficients each. The fixed-size legacy
//! buffer's unused padding is omitted. A PCD appends its header suffix, the
//! element count, and those canonical field elements after the proof payload.
//! Dimensions are bounded and the exact length is checked before element
//! decoding. An application and its parameters are not named in the bytes.
//! Decoding checks representation. Call Application::verify with the expected
//! application before accepting a decoded PCD.

use alloc::{vec, vec::Vec};

use ragu_circuits::polynomials::Rank;
use ragu_core::{Cycle, drivers::Driver as _, maybe::Maybe as _};
use ragu_primitives::{GadgetExt as _, Simulator};
use udon::{curve::Affine, field::Field};

use super::{
    header::{HEADER_POLYNOMIALS, Header, Suffix},
    proof::{PROOF_SIZE_COMPRESSED, Pcd, Proof},
};

#[cfg(feature = "serde")]
mod serde;

pub(crate) const ENVELOPE_SIZE: usize = 28;
const MAGIC: &[u8; 8] = b"RAGUPCD\0";
const ENVELOPE_VERSION: u16 = 3;
const PROTOCOL_VERSION: u16 = 2;
const SCHEMA_VERSION: u16 = 2;
const MAX_RANK: u32 = 32;
const MAX_HEADER_ELEMENTS: u64 = 1 << 12;
const HASH_SIZE: usize = 32;

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
}

/// A malformed byte encoding, or a value that has no wire representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error<'a> {
    /// The value cannot be encoded, for example because a point is the identity.
    Unencodable,
    /// The input has a different length from the format's exact length.
    Length {
        /// Expected byte length.
        expected: usize,
        /// Received byte length.
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
    /// The bytes are not a canonical representation of the expected value.
    Invalid {
        /// Start of the offending value.
        offset: usize,
        /// Offending input bytes.
        bytes: &'a [u8],
        /// Explanation of the rejection.
        reason: &'static str,
    },
}

impl core::fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unencodable => f.write_str("the value has no wire encoding"),
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

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
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

    fn take_scalar<F: Field>(&mut self) -> Result<F, Error<'a>> {
        let offset = self.offset;
        let mut repr = F::ZERO.to_bytes();
        let bytes = self.take(repr.as_ref().len())?;
        repr.as_mut().copy_from_slice(bytes);
        F::from_bytes(repr).ok_or(Error::Invalid {
            offset,
            bytes,
            reason: "non-canonical field element",
        })
    }
}

fn write_envelope<R: Rank>(kind: PayloadKind, header_elements: u64, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(MAGIC);
    for word in [
        ENVELOPE_VERSION,
        kind.tag(),
        SCHEMA_VERSION,
        PROTOCOL_VERSION,
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(&R::RANK.to_le_bytes());
    bytes.extend_from_slice(&header_elements.to_le_bytes());
}

fn open<'a, R: Rank>(bytes: &'a [u8], kind: PayloadKind) -> Result<(Reader<'a>, u64), Error<'a>> {
    let mut reader = Reader::new(bytes);
    let envelope = reader.take(ENVELOPE_SIZE)?;
    let mut expected = Vec::with_capacity(ENVELOPE_SIZE);
    write_envelope::<R>(kind, 0, &mut expected);
    for (start, end, reason) in [
        (0, 8, "invalid proof magic"),
        (8, 10, "unsupported proof envelope version"),
        (10, 12, "proof payload kind mismatch"),
        (12, 14, "unsupported proof schema version"),
        (14, 16, "unsupported proof protocol version"),
    ] {
        if envelope[start..end] != expected[start..end] {
            return Err(Error::Invalid {
                offset: start,
                bytes: &envelope[start..end],
                reason,
            });
        }
    }
    let rank_bytes = &envelope[16..20];
    let rank = u32::from_le_bytes(rank_bytes.try_into().expect("4-byte rank"));
    if rank > MAX_RANK || rank != R::RANK {
        return Err(Error::Invalid {
            offset: 16,
            bytes: rank_bytes,
            reason: "mock proof rank mismatch or exceeds the limit",
        });
    }
    let header_bytes = &envelope[20..28];
    let header_elements = u64::from_le_bytes(header_bytes.try_into().expect("8-byte size"));
    let invalid_header = match kind {
        PayloadKind::MockProof => header_elements != 0,
        PayloadKind::MockPcd => header_elements > MAX_HEADER_ELEMENTS,
    };
    if invalid_header {
        return Err(Error::Invalid {
            offset: 20,
            bytes: header_bytes,
            reason: "mock header element count exceeds the limit",
        });
    }
    Ok((reader, header_elements))
}

/// The occupied prefix of the older fixed-size proof buffer.
fn proof_prefix_len<C: Cycle>() -> usize {
    8 + HASH_SIZE
        + HEADER_POLYNOMIALS * C::HostCurve::identity().to_bytes().as_ref().len()
        + 3 * HASH_SIZE
}

fn proof_payload_len<C: Cycle, R: Rank>() -> usize {
    proof_prefix_len::<C>()
        + HEADER_POLYNOMIALS * R::num_coeffs() * C::CircuitField::ZERO.to_bytes().as_ref().len()
}

fn write_proof_payload<C: Cycle, R: Rank>(
    proof: &Proof<C, R>,
    bytes: &mut Vec<u8>,
) -> Result<(), Error<'static>> {
    let reusable = proof.to_reusable_bytes().map_err(|_| Error::Unencodable)?;
    let prefix = proof_prefix_len::<C>();
    bytes.extend_from_slice(&reusable[..prefix]);
    bytes.extend_from_slice(&reusable[PROOF_SIZE_COMPRESSED..]);
    Ok(())
}

fn decode_proof_payload<'a, C: Cycle, R: Rank>(
    reader: &mut Reader<'a>,
) -> Result<Proof<C, R>, Error<'a>> {
    let offset = reader.offset;
    let prefix_len = proof_prefix_len::<C>();
    let prefix = reader.take(prefix_len)?;
    let coefficients = reader.take(proof_payload_len::<C, R>() - prefix_len)?;
    let mut reusable = vec![0u8; PROOF_SIZE_COMPRESSED];
    reusable[..prefix_len].copy_from_slice(prefix);
    reusable.extend_from_slice(coefficients);
    Proof::from_reusable_bytes(&reusable).map_err(|_| Error::Invalid {
        offset,
        bytes: &reader.input[offset..reader.offset],
        reason: "invalid mock proof payload",
    })
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Encodes a reusable mock proof with a versioned envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<'static>> {
        if R::RANK > MAX_RANK {
            return Err(Error::Unencodable);
        }
        let mut bytes = Vec::with_capacity(Self::encoded_len::<0>());
        write_envelope::<R>(PayloadKind::MockProof, 0, &mut bytes);
        write_proof_payload(self, &mut bytes)?;
        Ok(bytes)
    }

    /// Exact length of this proof encoding, including its envelope.
    pub fn encoded_len<const HEADER_SIZE: usize>() -> usize {
        ENVELOPE_SIZE + proof_payload_len::<C, R>()
    }

    /// Decodes representation only. Verify with the expected application.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<'_>> {
        let (mut reader, _) = open::<R>(bytes, PayloadKind::MockProof)?;
        let expected = Self::encoded_len::<0>();
        if bytes.len() != expected {
            return Err(Error::Length {
                expected,
                actual: bytes.len(),
            });
        }
        decode_proof_payload(&mut reader)
    }

    #[cfg(feature = "serde")]
    fn framed_len(bytes: &[u8]) -> Result<usize, Error<'_>> {
        open::<R>(bytes, PayloadKind::MockProof)?;
        Ok(Self::encoded_len::<0>())
    }
}

/// A header whose data can be rebuilt from its flattened field elements.
pub trait WireHeader<F: Field>: Header<F> {
    /// Rebuilds data from exactly the elements emitted by Header::encode.
    fn decode(elements: &[F]) -> Option<Self::Data>;
}

impl<F: Field> WireHeader<F> for () {
    fn decode(elements: &[F]) -> Option<Self::Data> {
        elements.is_empty().then_some(())
    }
}

fn encode_header_elements<C: Cycle, H: Header<C::CircuitField>>(
    data: &H::Data,
) -> Result<Vec<C::CircuitField>, Error<'static>> {
    let mut dr = Simulator::<C::CircuitField>::new();
    let witness = Simulator::<C::CircuitField>::just(|| data.clone());
    let gadget = H::encode(&mut dr, &mut (), witness).map_err(|_| Error::Unencodable)?;
    let mut elements = Vec::new();
    gadget
        .write(&mut dr, &mut elements)
        .map_err(|_| Error::Unencodable)?;
    Ok(elements
        .into_iter()
        .map(|element| *element.value().take())
        .collect())
}

fn pcd_head_len<C: Cycle, R: Rank>() -> usize {
    proof_payload_len::<C, R>() + 16
}

impl<C: Cycle, R: Rank, H: WireHeader<C::CircuitField>> Pcd<C, R, H> {
    /// Encodes a mock PCD with its proof, header suffix, and header elements.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<'static>> {
        if R::RANK > MAX_RANK {
            return Err(Error::Unencodable);
        }
        let elements = encode_header_elements::<C, H>(&self.data)?;
        let count = u64::try_from(elements.len()).map_err(|_| Error::Unencodable)?;
        if count > MAX_HEADER_ELEMENTS {
            return Err(Error::Unencodable);
        }
        let scalar_len = C::CircuitField::ZERO.to_bytes().as_ref().len();
        let mut bytes = Vec::with_capacity(
            ENVELOPE_SIZE + pcd_head_len::<C, R>() + elements.len() * scalar_len,
        );
        write_envelope::<R>(PayloadKind::MockPcd, count, &mut bytes);
        write_proof_payload(&self.proof, &mut bytes)?;
        bytes.extend_from_slice(&H::SUFFIX.get().to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        for element in elements {
            bytes.extend_from_slice(element.to_bytes().as_ref());
        }
        Ok(bytes)
    }

    /// Decodes representation only. Verify with the expected application.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<'_>> {
        let (mut reader, elements) = open::<R>(bytes, PayloadKind::MockPcd)?;
        let proof = decode_proof_payload(&mut reader)?;
        let suffix_offset = reader.offset;
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
        let count_offset = reader.offset;
        let count = reader.take_u64()?;
        if count != elements {
            return Err(Error::Invalid {
                offset: count_offset,
                bytes: &bytes[count_offset..count_offset + 8],
                reason: "header element count does not match the envelope",
            });
        }
        let scalar_len = C::CircuitField::ZERO.to_bytes().as_ref().len();
        let expected = ENVELOPE_SIZE + pcd_head_len::<C, R>() + (elements as usize) * scalar_len;
        if bytes.len() != expected {
            return Err(Error::Length {
                expected,
                actual: bytes.len(),
            });
        }
        let header_offset = reader.offset;
        let values = (0..elements)
            .map(|_| reader.take_scalar::<C::CircuitField>())
            .collect::<Result<Vec<_>, _>>()?;
        let data = H::decode(&values).ok_or(Error::Invalid {
            offset: header_offset,
            bytes: &bytes[header_offset..],
            reason: "header data rejected by its header",
        })?;
        let reencoded = encode_header_elements::<C, H>(&data).map_err(|_| Error::Invalid {
            offset: header_offset,
            bytes: &bytes[header_offset..],
            reason: "decoded header data cannot be re-encoded",
        })?;
        if reencoded != values {
            return Err(Error::Invalid {
                offset: header_offset,
                bytes: &bytes[header_offset..],
                reason: "decoded header data changes its encoding",
            });
        }
        Ok(proof.carry::<H>(data))
    }

    #[cfg(feature = "serde")]
    fn framed_len(bytes: &[u8]) -> Result<usize, Error<'_>> {
        let (_, elements) = open::<R>(bytes, PayloadKind::MockPcd)?;
        Ok(ENVELOPE_SIZE
            + pcd_head_len::<C, R>()
            + (elements as usize) * C::CircuitField::ZERO.to_bytes().as_ref().len())
    }
}
