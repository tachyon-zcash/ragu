//! Canonical byte encoding for minimal proof data.
//!
//! This is separate from the in-circuit element stream in [`ragu_primitives::io`].
//! Every value has a fixed encoded length determined by its type: the rank,
//! the header size and the protocol's vector counts fix the layout, so no
//! length is read from the wire. [`Encode::encode`] and [`Decode::decode`]
//! compose payloads; [`Encode::to_bytes`] and [`Decode::from_bytes`] add/check
//! one version byte at the outer boundary and require the exact encoded length.
//! The caller must select the same schema, field/curve suite, rank and header
//! size. These low-level bytes do not identify their schema or application
//! context. Domain formats must provide that envelope (for example
//! `crate::ProofFormat`).
//!
//! Integers are little-endian with their declared widths. Scalar and point
//! representations are specified by their respective types. Explicit
//! [`Scalar`] and [`Point`] codecs avoid overlapping blanket impls. When more
//! than one codec applies, select it explicitly, for example
//! `<Vec<F> as Decode<FixedSequence<Scalar, L>>>::from_bytes(bytes)`.

use alloc::{sync::Arc, vec::Vec};
use core::{marker::PhantomData, mem::size_of};

use ragu_primitives::vec::Len;
use udon::{curve::Affine, field::Field};

mod polynomial;
mod registry;
#[cfg(test)]
mod tests;

/// Version of the low-level codec framing. Nested payloads have no envelope.
pub const VERSION: u8 = 1;

/// The ordinary codec for integers and generated structs.
pub struct DefaultEncoding;
/// The canonical [`Field`] representation.
pub struct Scalar;
/// The checked, compressed [`Affine`] representation of a point other than
/// the identity. No proof slot admits the identity: the verifier allocates
/// every point by its affine coordinates. Encoding the identity yields its
/// canonical bytes, which decoding rejects.
pub struct Point;
/// A vector of exactly [`Len::len`] elements using codec `C`, with no count on
/// the wire.
pub struct FixedSequence<C, L>(PhantomData<(C, L)>);

/// Encodes a value using codec `C`.
pub trait Encode<C = DefaultEncoding> {
    /// Appends the canonical payload, without a version envelope.
    fn encode(&self, output: &mut Vec<u8>);

    /// Encodes one complete value with the low-level codec version byte.
    fn to_bytes(&self) -> Vec<u8> {
        let mut output = alloc::vec![VERSION];
        self.encode(&mut output);
        output
    }
}

/// Decodes a value using codec `C`.
pub trait Decode<C = DefaultEncoding>: Sized {
    /// The exact number of payload bytes, excluding the version byte.
    fn encoded_len() -> usize;

    /// Reads one payload, leaving subsequent bytes for the enclosing value.
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>>;

    /// Decodes a complete versioned value of exactly the expected length.
    fn from_bytes(input: &[u8]) -> Result<Self, Error<'_>> {
        let expected = 1 + Self::encoded_len();
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
        Self::decode(&mut reader)
    }
}

/// A malformed byte encoding.
///
/// Offending byte slices borrow the input rather than copying hostile data.
#[derive(Debug)]
pub enum Error<'a> {
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
pub struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Starts reading payloads from `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    /// Number of bytes already consumed.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The unconsumed input.
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.offset..]
    }

    /// Reads exactly `length` bytes without copying or allocating.
    pub fn take(&mut self, length: usize) -> Result<&'a [u8], Error<'a>> {
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
            fn encoded_len() -> usize { size_of::<Self>() }
            fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
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
    fn encoded_len() -> usize {
        F::ZERO.to_bytes().as_ref().len()
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        let offset = reader.offset();
        let mut repr = F::ZERO.to_bytes();
        let bytes = reader.take(repr.as_ref().len())?;
        repr.as_mut().copy_from_slice(bytes);
        let value = F::from_bytes(repr).ok_or(Error::Invalid {
            offset,
            bytes,
            reason: "non-canonical field element",
        })?;
        if Field::to_bytes(&value).as_ref() != bytes {
            return Err(Error::Invalid {
                offset,
                bytes,
                reason: "non-canonical field element",
            });
        }
        Ok(value)
    }
}

impl<G: Affine> Encode<Point> for G {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(self.to_bytes().as_ref());
    }
}
impl<G: Affine> Decode<Point> for G {
    fn encoded_len() -> usize {
        G::identity().to_bytes().as_ref().len()
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        let offset = reader.offset();
        let mut repr = G::identity().to_bytes();
        let bytes = reader.take(repr.as_ref().len())?;
        repr.as_mut().copy_from_slice(bytes);
        let value = G::from_bytes(repr).ok_or(Error::Invalid {
            offset,
            bytes,
            reason: "invalid compressed point",
        })?;
        if value.to_bytes().as_ref() != bytes {
            return Err(Error::Invalid {
                offset,
                bytes,
                reason: "non-canonical compressed point",
            });
        }
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
    fn encoded_len() -> usize {
        T::encoded_len()
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        T::decode(reader).map(Arc::new)
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
    fn encoded_len() -> usize {
        L::len() * T::encoded_len()
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        (0..L::len()).map(|_| T::decode(reader)).collect()
    }
}

impl core::fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
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
