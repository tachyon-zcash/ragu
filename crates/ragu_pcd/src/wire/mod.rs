//! Canonical byte encoding for minimal proof data.
//!
//! This is separate from the in-circuit element stream in [`ragu_primitives::io`].
//! [`Encode::encode`] and [`Decode::decode`] compose payloads; [`Encode::to_bytes`]
//! and [`Decode::from_bytes`] add/check one version byte at the outer boundary.
//! The caller must select the same schema, field/curve suite and rank. These
//! low-level bytes do not identify their schema or application context. Domain
//! formats must provide that envelope (for example `crate::ProofFormat`).
//!
//! Integers and lengths are little-endian; lengths always occupy eight bytes.
//! Scalar and point representations are specified by their respective types.
//! Explicit [`Scalar`] and [`Point`] codecs avoid overlapping blanket impls.
//! When more than one codec applies, select it explicitly, for example
//! `<Vec<u64> as Decode>::from_bytes(bytes, limits)` for the ordinary vector
//! codec, or `<Vec<F> as Decode<Sequence<Scalar>>>::from_bytes(bytes, limits)`
//! for field elements. Custom decoders must use the reader's reservation helper
//! to participate in its resource budgets.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{marker::PhantomData, mem::size_of};

use udon::{curve::Affine, field::Field};

mod polynomial;
pub use polynomial::InvalidBlock;
mod registry;
#[cfg(test)]
mod tests;

/// Version of the low-level codec framing. Nested payloads have no envelope.
pub const VERSION: u8 = 1;

/// The ordinary codec for integers, containers and generated structs.
pub struct DefaultEncoding;
/// The canonical [`Field`] representation.
pub struct Scalar;
/// The checked, compressed [`Affine`] representation.
pub struct Point;
/// A length-prefixed vector whose elements use codec `C`.
pub struct Sequence<C>(PhantomData<C>);
/// A length-prefixed vector whose count must equal [`ragu_primitives::vec::Len::len`].
/// The count is checked before reservation or decoding any element.
pub struct FixedSequence<C, L>(PhantomData<(C, L)>);

/// Receives a polynomial and its claimed commitment during verification.
pub(crate) trait Checked<'a, P, Q> {
    fn check(&mut self, provided: &'a P, checked: &Q);
}

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
    /// Lower bound on the number of bytes in a payload, excluding its envelope.
    ///
    /// Container decoders use this to reject impossible lengths before allocation.
    fn min_encoded_len() -> usize;

    /// Reads one payload, leaving subsequent bytes for the enclosing value.
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>>;

    /// Decodes a complete versioned value, rejecting trailing bytes.
    fn from_bytes(input: &[u8], limits: Limits) -> Result<Self, Error<'_>> {
        let mut reader = Reader::new(input, limits);
        let version = reader.take(1)?;
        if version[0] != VERSION {
            return Err(Error::Invalid {
                offset: 0,
                bytes: version,
                reason: "unsupported wire version",
            });
        }
        let value = Self::decode(&mut reader)?;
        if !reader.remaining().is_empty() {
            return Err(Error::Invalid {
                offset: reader.offset(),
                bytes: reader.remaining(),
                reason: "trailing bytes",
            });
        }
        Ok(value)
    }
}

/// Aggregate resource budgets for a single decode, including nested containers.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum total number of container elements allocated and decoded.
    pub elements: usize,
    /// Maximum sum of requested vector storage sizes in bytes.
    ///
    /// This bounds requested capacity, not allocator bookkeeping or stack usage.
    pub allocation: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            elements: 1 << 20,
            allocation: 64 << 20,
        }
    }
}

/// A malformed or over-budget byte encoding.
///
/// Offending byte slices borrow the input rather than copying hostile data.
#[derive(Debug)]
pub enum Error<'a> {
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
    /// A wire count cannot be represented by this machine.
    Length {
        /// Offset immediately after reading the count.
        offset: usize,
        /// Offending count, without truncation to `usize`.
        value: u64,
    },
    /// A container would exceed a shared decoding budget.
    Limit {
        /// Position where the budget was checked.
        offset: usize,
        /// Budget that was exhausted.
        resource: &'static str,
        /// Requested amount.
        requested: usize,
        /// Remaining amount.
        remaining: usize,
    },
    /// Fallible reservation failed even though the request fit the budgets.
    Allocation {
        /// Position where the allocation was attempted.
        offset: usize,
        /// Requested number of elements.
        elements: usize,
    },
    /// An owning domain rejected a structurally invalid value.
    Value {
        /// Start of the offending value.
        offset: usize,
        /// Encoded value or header that identified the problem.
        bytes: &'a [u8],
        /// Domain-specific error, including its offending values.
        source: Box<dyn core::error::Error + Send + Sync>,
    },
}

/// A borrowed byte cursor with shared decoding budgets.
#[derive(Clone)]
pub struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
    limits: Limits,
}

impl<'a> Reader<'a> {
    /// Starts reading payloads from `input` with explicit budgets.
    pub fn new(input: &'a [u8], limits: Limits) -> Self {
        Self {
            input,
            offset: 0,
            limits,
        }
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

    /// Charges aggregate budgets and reserves space only after checking that
    /// the remaining input could contain `count` elements of at least
    /// `minimum_bytes` bytes each.
    pub(crate) fn charge<T>(
        &mut self,
        count: u64,
        minimum_bytes: usize,
    ) -> Result<usize, Error<'a>> {
        let wire_count = count;
        let count = usize::try_from(count).map_err(|_| Error::Length {
            offset: self.offset,
            value: count,
        })?;
        if count > self.limits.elements {
            return Err(Error::Limit {
                offset: self.offset,
                resource: "elements",
                requested: count,
                remaining: self.limits.elements,
            });
        }
        if minimum_bytes != 0 && count > self.remaining().len() / minimum_bytes {
            return Err(Error::Truncated {
                offset: self.offset,
                requested: count.saturating_mul(minimum_bytes),
                bytes: self.remaining(),
            });
        }
        let bytes = count.checked_mul(size_of::<T>()).ok_or(Error::Length {
            offset: self.offset,
            value: wire_count,
        })?;
        if bytes > self.limits.allocation {
            return Err(Error::Limit {
                offset: self.offset,
                resource: "allocation",
                requested: bytes,
                remaining: self.limits.allocation,
            });
        }
        self.limits.elements -= count;
        self.limits.allocation -= bytes;
        Ok(count)
    }

    /// Reserves vector storage after charging the shared resource budgets.
    pub fn reserve<T>(&mut self, count: u64, minimum_bytes: usize) -> Result<Vec<T>, Error<'a>> {
        let count = self.charge::<T>(count, minimum_bytes)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation {
                offset: self.offset,
                elements: count,
            })?;
        Ok(output)
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
            fn min_encoded_len() -> usize { size_of::<Self>() }
            fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
                let mut bytes = [0; size_of::<Self>()];
                bytes.copy_from_slice(reader.take(size_of::<Self>())?);
                Ok(Self::from_le_bytes(bytes))
            }
        }
    )*};
}
integer!(u8, u16, u32, u64, u128);

impl Encode for usize {
    fn encode(&self, output: &mut Vec<u8>) {
        (*self as u64).encode(output);
    }
}
impl Decode for usize {
    fn min_encoded_len() -> usize {
        8
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        let value = u64::decode(reader)?;
        Self::try_from(value).map_err(|_| Error::Length {
            offset: reader.offset(),
            value,
        })
    }
}

impl<F: Field> Encode<Scalar> for F {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(Field::to_bytes(self).as_ref());
    }
}
impl<F: Field> Decode<Scalar> for F {
    fn min_encoded_len() -> usize {
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
    fn min_encoded_len() -> usize {
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
        Ok(value)
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, output: &mut Vec<u8>) {
        <Self as Encode<Sequence<DefaultEncoding>>>::encode(self, output);
    }
}
impl<T: Decode> Decode for Vec<T> {
    fn min_encoded_len() -> usize {
        8
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        <Self as Decode<Sequence<DefaultEncoding>>>::decode(reader)
    }
}
impl<T: Encode<C>, C> Encode<Sequence<C>> for Vec<T> {
    fn encode(&self, output: &mut Vec<u8>) {
        (self.len() as u64).encode(output);
        for value in self {
            value.encode(output);
        }
    }
}
impl<T: Decode<C>, C> Decode<Sequence<C>> for Vec<T> {
    fn min_encoded_len() -> usize {
        8
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        let count = u64::decode(reader)?;
        let mut values = reader.reserve::<T>(count, T::min_encoded_len())?;
        for _ in 0..count {
            values.push(T::decode(reader)?);
        }
        Ok(values)
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
    fn min_encoded_len() -> usize {
        T::min_encoded_len()
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        T::decode(reader).map(Arc::new)
    }
}

impl<T: Encode<C>, C, L: ragu_primitives::vec::Len> Encode<FixedSequence<C, L>> for Vec<T> {
    fn encode(&self, output: &mut Vec<u8>) {
        <Self as Encode<Sequence<C>>>::encode(self, output);
    }
}
impl<T: Decode<C>, C, L: ragu_primitives::vec::Len> Decode<FixedSequence<C, L>> for Vec<T> {
    fn min_encoded_len() -> usize {
        8usize.saturating_add(L::len().saturating_mul(T::min_encoded_len()))
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        let offset = reader.offset();
        let bytes = reader.remaining();
        let count = u64::decode(reader)?;
        if count != L::len() as u64 {
            return Err(Error::Invalid {
                offset,
                bytes: &bytes[..8],
                reason: "incorrect fixed sequence length",
            });
        }
        let mut values = reader.reserve::<T>(count, T::min_encoded_len())?;
        for _ in 0..count {
            values.push(T::decode(reader)?);
        }
        Ok(values)
    }
}

impl core::fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
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
            Self::Length { offset, value } => write!(
                f,
                "length {value} at byte {offset} exceeds the host address space"
            ),
            Self::Limit {
                offset,
                resource,
                requested,
                remaining,
            } => write!(
                f,
                "{resource} budget exceeded at byte {offset}: requested {requested}, remaining {remaining}"
            ),
            Self::Allocation { offset, elements } => {
                write!(f, "could not allocate {elements} elements at byte {offset}")
            }
            Self::Value { offset, source, .. } => {
                write!(f, "invalid value at byte {offset}: {source}")
            }
        }
    }
}
impl core::error::Error for Error<'_> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Value { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
