//! Canonical byte encoding for proof data.
//!
//! Proofs reach bytes through [`Proof::to_bytes`](crate::Proof::to_bytes) and
//! [`Proof::from_bytes`](crate::Proof::from_bytes), and the corresponding
//! [`CompressedProof`](crate::CompressedProof) methods, with a versioned
//! envelope; the optional `serde` adapters carry the same bytes. [`Error`]
//! reports malformed byte encodings.
//!
//! This is separate from the in-circuit element stream in
//! [`ragu_primitives::io`]. Every value has a fixed encoded length, determined
//! by its type and by the payload's dimensions: the rank, the header size and
//! the protocol's vector counts fix the layout, so no length is read from the
//! payload itself. Neither the rank of a compressed proof nor the header size
//! of any proof is part of its type, so the envelope supplies them.
//!
//! Integers are little-endian with their declared widths. Scalar and point
//! representations are specified by their respective types. Explicit scalar
//! and point codecs avoid overlapping blanket impls.
//!
//! # Envelope
//!
//! `to_bytes` writes a 28-byte envelope ahead of a payload, every integer
//! little-endian:
//!
//! | Offset | Size | Meaning |
//! | --- | --- | --- |
//! | 0 | 8 | Magic: `RAGUPCD` and a NUL |
//! | 8 | 2 | Envelope version: 3 |
//! | 10 | 2 | Payload kind: 1 proof, 2 compressed proof |
//! | 12 | 2 | Schema version of that payload kind: 1 |
//! | 14 | 2 | Protocol version: 1 (`ragu-pcd-v1`) |
//! | 16 | 4 | Rank |
//! | 20 | 8 | Header size, in field elements |
//!
//! Decoding checks the envelope and its dimensions, then the exact total
//! length those dimensions imply, before decoding the payload. Headers are
//! limited to 4096 field elements and compressed ranks to 32, so hostile
//! dimensions are rejected before allocating the payload. An ordinary proof's
//! declared rank must match its type. Unknown versions are never reinterpreted
//! or downgraded. The caller selects the expected application, profile and
//! cryptographic parameters through its deployment or consensus rules. They
//! are not identified in the encoding; the receiving types fix the payload
//! layout.
//!
//! # Versions
//!
//! The schema version fixes a payload's field order, each field's codec and
//! the profile's vector counts. The envelope version fixes the layout above.
//! The protocol version follows the verification semantics identified by the
//! transcript domain tags. Changing any of these means a new version and
//! explicit dispatch in the decoder, with either a migration path and
//! compatibility tests or failing closed on the old one; a crate release or an
//! implementation change alone changes none of them. The fuse fixtures pin
//! the payload bytes of every scenario, so a change to the format fails them
//! until they are regenerated, which is the moment to bump the version.
//!
//! # Input limits
//!
//! Bound transport input before buffering it. The versioned byte encoding's
//! expected lengths are available from
//! [`Proof::encoded_len`](crate::Proof::encoded_len) and
//! [`CompressedProof::encoded_len`](crate::CompressedProof::encoded_len).
//! A compressed proof's length does not fix its rank and header size;
//! verification checks the application's shape.
//! With `serde`, also configure the deserializer's size limit or
//! bound its input externally: a backend may allocate its byte buffer before
//! handing it to Ragu. Ragu bounds its own sequence buffer and checks the
//! encoding's exact length, but cannot limit those earlier backend
//! allocations. A deserializer borrowing from an existing slice can avoid
//! that buffer allocation.

use alloc::{sync::Arc, vec::Vec};
use core::{marker::PhantomData, mem::size_of};

use ragu_circuits::polynomials::Rank;
use ragu_primitives::vec::Len;
use udon::{curve::Affine, field::Field};

mod compressed;
mod format;
mod polynomial;
mod registry;
#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "serde"))]
pub(crate) use format::ENVELOPE_SIZE;

/// Largest compressed rank admitted by the byte formats.
pub(crate) const MAX_RANK: u32 = 32;
/// Largest child header admitted by the byte formats, in field elements.
pub(crate) const MAX_HEADER_SIZE: usize = 1 << 12;

/// The dimensions a payload's layout takes from its proof rather than from
/// its type: the rank, which fixes a compressed proof's IPA rounds, and the
/// header size, which fixes every child header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Dimensions {
    /// The rank, one IPA round per bit.
    pub(crate) rank: u32,
    /// The number of elements in each child header.
    pub(crate) header_size: usize,
}

impl Dimensions {
    /// The dimensions of an application's proofs.
    pub(crate) fn of<R: Rank, const HEADER_SIZE: usize>() -> Self {
        Self {
            rank: R::RANK,
            header_size: HEADER_SIZE,
        }
    }
}

/// The ordinary codec for integers and generated structs.
pub(crate) struct DefaultEncoding;
/// The canonical [`Field`] representation.
pub(crate) struct Scalar;
/// The checked, compressed [`Affine`] representation of a point other than
/// the identity. No proof slot admits the identity: the verifier allocates
/// every point by its affine coordinates. Encoding it fails, and decoding
/// its canonical bytes is rejected.
pub(crate) struct Point;
/// A vector of exactly [`Len::len`] elements using codec `C`, with no count on
/// the wire.
pub(crate) struct FixedSequence<C, L>(PhantomData<(C, L)>);
/// A vector of exactly the count [`Dimensions`] fix along dimension `D`, using
/// codec `C`, with no count on the wire.
pub(crate) struct SizedSequence<C, D>(PhantomData<(C, D)>);

/// A count [`Dimensions`] fix.
pub(crate) trait Dimension {
    /// The count in `dims`.
    fn of(dims: Dimensions) -> usize;
}

/// The number of elements in a child header.
pub(crate) struct HeaderSize;
impl Dimension for HeaderSize {
    fn of(dims: Dimensions) -> usize {
        dims.header_size
    }
}

/// The number of IPA rounds, one per bit of the rank.
pub(crate) struct Rounds;
impl Dimension for Rounds {
    fn of(dims: Dimensions) -> usize {
        dims.rank as usize
    }
}

/// Encodes a value using codec `C`.
pub(crate) trait Encode<C = DefaultEncoding> {
    /// Appends the canonical payload of `dims`, without an envelope.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unencodable`] if the value has no encoding: a vector
    /// of another length than the format and `dims` fix, or a point slot
    /// holding the identity, which the decoder rejects. This does not
    /// establish proof validity; application methods separately check the
    /// shape before traversing an untrusted proof's fields.
    fn encode(&self, output: &mut Vec<u8>, dims: Dimensions) -> Result<(), Error<'static>>;

    /// Encodes one complete value of `dims`.
    ///
    /// # Panics
    ///
    /// Panics if the value has no encoding.
    #[cfg(test)]
    fn to_bytes(&self, dims: Dimensions) -> Vec<u8> {
        let mut output = Vec::new();
        self.encode(&mut output, dims)
            .expect("the value has an encoding");
        output
    }
}

/// Encodes `values` as exactly `count` elements of codec `C`.
fn encode_sequence<T: Encode<C>, C>(
    values: &[T],
    count: usize,
    output: &mut Vec<u8>,
    dims: Dimensions,
) -> Result<(), Error<'static>> {
    if values.len() != count {
        return Err(Error::Unencodable);
    }
    values
        .iter()
        .try_for_each(|value| value.encode(output, dims))
}

/// The encoded length of the field `project` selects, for a codec listed
/// apart from its struct, whose type `encoded_len` cannot infer from a
/// value. `project` is never called.
pub(crate) fn field_len<S, T: Decode<C>, C>(_: fn(&S) -> &T, dims: Dimensions) -> usize {
    T::encoded_len(dims)
}

/// Decodes a value using codec `C`.
pub(crate) trait Decode<C = DefaultEncoding>: Sized {
    /// The exact number of payload bytes in `dims`.
    fn encoded_len(dims: Dimensions) -> usize;

    /// Reads one payload of `dims`, leaving subsequent bytes for the
    /// enclosing value.
    fn decode<'a>(reader: &mut Reader<'a>, dims: Dimensions) -> Result<Self, Error<'a>>;

    /// Decodes a complete value of `dims` and exactly the expected length.
    #[cfg(test)]
    fn from_bytes(input: &[u8], dims: Dimensions) -> Result<Self, Error<'_>> {
        let expected = Self::encoded_len(dims);
        if input.len() != expected {
            return Err(Error::Length {
                expected,
                actual: input.len(),
            });
        }
        Self::decode(&mut Reader::new(input), dims)
    }
}

/// A malformed byte encoding, or a value that has none.
///
/// Offending byte slices borrow the input rather than copying hostile data.
/// New versions of the format may add variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error<'a> {
    /// The value to encode has no encoding: a vector has another length than
    /// the format fixes, or a point slot holds the identity, which no slot
    /// admits. Decoding never reports this.
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

/// A borrowed byte cursor.
#[derive(Clone)]
pub(crate) struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Starts reading payloads from `input`.
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    /// Number of bytes already consumed.
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    /// The unconsumed input.
    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.input[self.offset..]
    }

    /// Reads exactly `length` bytes without copying or allocating.
    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], Error<'a>> {
        let bytes = self.remaining().get(..length).ok_or(Error::Truncated {
            offset: self.offset,
            requested: length,
            bytes: self.remaining(),
        })?;
        self.offset += length;
        Ok(bytes)
    }
}

macro_rules! integer {
    ($($ty:ty),*) => {$(
        impl Encode for $ty {
            fn encode(&self, output: &mut Vec<u8>, _: Dimensions) -> Result<(), Error<'static>> {
                output.extend_from_slice(&self.to_le_bytes());
                Ok(())
            }
        }
        impl Decode for $ty {
            fn encoded_len(_: Dimensions) -> usize { size_of::<Self>() }
            fn decode<'a>(reader: &mut Reader<'a>, _: Dimensions) -> Result<Self, Error<'a>> {
                let mut bytes = [0; size_of::<Self>()];
                bytes.copy_from_slice(reader.take(size_of::<Self>())?);
                Ok(Self::from_le_bytes(bytes))
            }
        }
    )*};
}
integer!(u8, u16, u32, u64);

impl<F: Field> Encode<Scalar> for F {
    fn encode(&self, output: &mut Vec<u8>, _: Dimensions) -> Result<(), Error<'static>> {
        output.extend_from_slice(Field::to_bytes(self).as_ref());
        Ok(())
    }
}
impl<F: Field> Decode<Scalar> for F {
    fn encoded_len(_: Dimensions) -> usize {
        F::ZERO.to_bytes().as_ref().len()
    }
    fn decode<'a>(reader: &mut Reader<'a>, _: Dimensions) -> Result<Self, Error<'a>> {
        let offset = reader.offset();
        let mut repr = F::ZERO.to_bytes();
        let bytes = reader.take(repr.as_ref().len())?;
        repr.as_mut().copy_from_slice(bytes);
        // `Field::from_bytes` accepts the canonical representation alone, so
        // every element has one spelling.
        F::from_bytes(repr).ok_or(Error::Invalid {
            offset,
            bytes,
            reason: "non-canonical field element",
        })
    }
}

impl<G: Affine> Encode<Point> for G {
    fn encode(&self, output: &mut Vec<u8>, _: Dimensions) -> Result<(), Error<'static>> {
        if self.is_identity() {
            return Err(Error::Unencodable);
        }
        output.extend_from_slice(self.to_bytes().as_ref());
        Ok(())
    }
}
impl<G: Affine> Decode<Point> for G {
    fn encoded_len(_: Dimensions) -> usize {
        G::identity().to_bytes().as_ref().len()
    }
    fn decode<'a>(reader: &mut Reader<'a>, _: Dimensions) -> Result<Self, Error<'a>> {
        let offset = reader.offset();
        let mut repr = G::identity().to_bytes();
        let bytes = reader.take(repr.as_ref().len())?;
        repr.as_mut().copy_from_slice(bytes);
        // `Affine::from_bytes` accepts the canonical representation of a
        // group element alone, so every point has one spelling.
        let value = G::from_bytes(repr).ok_or(Error::Invalid {
            offset,
            bytes,
            reason: "invalid compressed point",
        })?;
        if value.is_identity() {
            return Err(Error::Invalid {
                offset,
                bytes,
                reason: "identity point",
            });
        }
        Ok(value)
    }
}

// An `Arc` is its value on the wire. Only the ordinary codec: a blanket over
// every codec would overlap the scalar and point impls in coherence's eyes.
impl<T: Encode> Encode for Arc<T> {
    fn encode(&self, output: &mut Vec<u8>, dims: Dimensions) -> Result<(), Error<'static>> {
        T::encode(self, output, dims)
    }
}
impl<T: Decode> Decode for Arc<T> {
    fn encoded_len(dims: Dimensions) -> usize {
        T::encoded_len(dims)
    }
    fn decode<'a>(reader: &mut Reader<'a>, dims: Dimensions) -> Result<Self, Error<'a>> {
        T::decode(reader, dims).map(Arc::new)
    }
}

// The element count is fixed by `L`; a vector of another length has no
// encoding.
impl<T: Encode<C>, C, L: Len> Encode<FixedSequence<C, L>> for Vec<T> {
    fn encode(&self, output: &mut Vec<u8>, dims: Dimensions) -> Result<(), Error<'static>> {
        encode_sequence(self, L::len(), output, dims)
    }
}
impl<T: Decode<C>, C, L: Len> Decode<FixedSequence<C, L>> for Vec<T> {
    fn encoded_len(dims: Dimensions) -> usize {
        L::len() * T::encoded_len(dims)
    }
    fn decode<'a>(reader: &mut Reader<'a>, dims: Dimensions) -> Result<Self, Error<'a>> {
        (0..L::len()).map(|_| T::decode(reader, dims)).collect()
    }
}

// The element count is fixed by the dimensions.
impl<T: Encode<C>, C, D: Dimension> Encode<SizedSequence<C, D>> for Vec<T> {
    fn encode(&self, output: &mut Vec<u8>, dims: Dimensions) -> Result<(), Error<'static>> {
        encode_sequence(self, D::of(dims), output, dims)
    }
}
impl<T: Decode<C>, C, D: Dimension> Decode<SizedSequence<C, D>> for Vec<T> {
    fn encoded_len(dims: Dimensions) -> usize {
        D::of(dims) * T::encoded_len(dims)
    }
    fn decode<'a>(reader: &mut Reader<'a>, dims: Dimensions) -> Result<Self, Error<'a>> {
        (0..D::of(dims)).map(|_| T::decode(reader, dims)).collect()
    }
}

impl core::fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unencodable => f.write_str(
                "the value has no encoding: a vector of another length than the format fixes, \
                 or an identity point",
            ),
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
