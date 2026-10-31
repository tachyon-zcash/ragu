//! Canonical byte encoding for proof data.
//!
//! The encoding itself is internal: proofs reach bytes through
//! `ProofFormat`'s versioned envelope or through the optional `serde`
//! adapters. [`Error`] is what both report when bytes are malformed.
//!
//! This is separate from the in-circuit element stream in
//! `ragu_primitives::io`. Every value has a fixed encoded length, determined by
//! its type and by the payload's dimensions: the rank, the header size and the
//! protocol's vector counts fix the layout, so no length is read from the
//! payload itself. Neither the rank of a compressed proof nor the header size
//! of any proof is part of its type, so the envelope, or the `serde` adapters'
//! prelude, supplies them.
//!
//! Integers are little-endian with their declared widths. Scalar and point
//! representations are specified by their respective types. Explicit scalar
//! and point codecs avoid overlapping blanket impls.

use alloc::{sync::Arc, vec::Vec};
use core::{marker::PhantomData, mem::size_of};

use ragu_circuits::polynomials::Rank;
use ragu_primitives::vec::Len;
use udon::{curve::Affine, field::Field};

mod compressed;
pub(crate) mod format;
mod polynomial;
mod registry;
mod schema;
#[cfg(feature = "serde")]
mod serde;
#[cfg(test)]
mod tests;

pub(crate) use schema::proof_schema;

/// Version of the low-level codec framing, which the `serde` adapters lead
/// with. Nested payloads have no envelope.
#[cfg(any(test, feature = "serde"))]
pub(crate) const VERSION: u8 = 1;

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
/// every point by its affine coordinates. Encoding the identity yields its
/// canonical bytes, which decoding rejects.
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
    /// Appends the canonical payload, without a version envelope.
    fn encode(&self, output: &mut Vec<u8>);

    /// Encodes one complete value with the low-level codec version byte.
    #[cfg(test)]
    fn to_bytes(&self) -> Vec<u8> {
        let mut output = alloc::vec![VERSION];
        self.encode(&mut output);
        output
    }
}

/// The in-memory invariants a codec fixes, checked before a value is encoded
/// and before an untrusted proof's fields are traversed. Neither check
/// establishes proof validity.
pub(crate) trait Validate<C = DefaultEncoding> {
    /// Whether every vector has exactly the count the dimensions and the
    /// codec fix, so that traversing the value cannot index a missing entry
    /// or ignore a trailing one.
    fn has_shape(&self, dims: Dimensions) -> bool;

    /// Whether the value has an encoding: it has its shape, and no point
    /// slot holds the identity, which the decoder rejects.
    fn encodable(&self, dims: Dimensions) -> bool;
}

/// Whether `values` has exactly `count` elements, each passing `check`.
fn sequence<T>(values: &[T], count: usize, check: impl Fn(&T) -> bool) -> bool {
    values.len() == count && values.iter().all(check)
}

impl<F: Field> Validate<Scalar> for F {
    fn has_shape(&self, _: Dimensions) -> bool {
        true
    }
    fn encodable(&self, _: Dimensions) -> bool {
        true
    }
}
impl<G: Affine> Validate<Point> for G {
    fn has_shape(&self, _: Dimensions) -> bool {
        true
    }
    fn encodable(&self, _: Dimensions) -> bool {
        !self.is_identity()
    }
}
impl<T: Validate<C>, C, L: Len> Validate<FixedSequence<C, L>> for Vec<T> {
    fn has_shape(&self, dims: Dimensions) -> bool {
        sequence(self, L::len(), |value| T::has_shape(value, dims))
    }
    fn encodable(&self, dims: Dimensions) -> bool {
        sequence(self, L::len(), |value| T::encodable(value, dims))
    }
}
impl<T: Validate<C>, C, D: Dimension> Validate<SizedSequence<C, D>> for Vec<T> {
    fn has_shape(&self, dims: Dimensions) -> bool {
        sequence(self, D::of(dims), |value| T::has_shape(value, dims))
    }
    fn encodable(&self, dims: Dimensions) -> bool {
        sequence(self, D::of(dims), |value| T::encodable(value, dims))
    }
}
impl<T: Validate> Validate for Arc<T> {
    fn has_shape(&self, dims: Dimensions) -> bool {
        T::has_shape(self, dims)
    }
    fn encodable(&self, dims: Dimensions) -> bool {
        T::encodable(self, dims)
    }
}
impl<F: Field, R: Rank> Validate for ragu_circuits::polynomials::sparse::Polynomial<F, R> {
    fn has_shape(&self, _: Dimensions) -> bool {
        true
    }
    fn encodable(&self, _: Dimensions) -> bool {
        true
    }
}
impl Validate for ragu_circuits::registry::CircuitIndex {
    fn has_shape(&self, _: Dimensions) -> bool {
        true
    }
    fn encodable(&self, _: Dimensions) -> bool {
        true
    }
}

/// Decodes a value using codec `C`.
pub(crate) trait Decode<C = DefaultEncoding>: Sized {
    /// The exact number of payload bytes in `dims`, excluding the version
    /// byte.
    fn encoded_len(dims: Dimensions) -> usize;

    /// Reads one payload of `dims`, leaving subsequent bytes for the
    /// enclosing value.
    fn decode<'a>(reader: &mut Reader<'a>, dims: Dimensions) -> Result<Self, Error<'a>>;

    /// Decodes a complete versioned value of `dims` and exactly the expected
    /// length.
    #[cfg(test)]
    fn from_bytes(input: &[u8], dims: Dimensions) -> Result<Self, Error<'_>> {
        let expected = 1 + Self::encoded_len(dims);
        if input.len() != expected {
            return Err(Error::Length {
                expected,
                actual: input.len(),
            });
        }
        let mut reader = Reader::new(input);
        let version = reader.take(1)?;
        if version[0] != VERSION {
            return Err(Error::Invalid {
                offset: 0,
                bytes: version,
                reason: "unsupported wire version",
            });
        }
        Self::decode(&mut reader, dims)
    }
}

/// A malformed byte encoding, or a value that has none.
///
/// Offending byte slices borrow the input rather than copying hostile data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
            fn encode(&self, output: &mut Vec<u8>) {
                output.extend_from_slice(&self.to_le_bytes());
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
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(Field::to_bytes(self).as_ref());
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
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(self.to_bytes().as_ref());
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
    fn encode(&self, output: &mut Vec<u8>) {
        T::encode(self, output);
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
// encoding, and encoding one is a programming error rather than a wire case.
impl<T: Encode<C>, C, L: Len> Encode<FixedSequence<C, L>> for Vec<T> {
    fn encode(&self, output: &mut Vec<u8>) {
        debug_assert_eq!(self.len(), L::len(), "fixed sequence length");
        for value in self {
            value.encode(output);
        }
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

// The element count is fixed by the dimensions; callers check it with
// `Validate` before encoding, since the dimensions are not at hand here.
impl<T: Encode<C>, C, D: Dimension> Encode<SizedSequence<C, D>> for Vec<T> {
    fn encode(&self, output: &mut Vec<u8>) {
        for value in self {
            value.encode(output);
        }
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
