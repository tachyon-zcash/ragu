//! Canonical byte encoding for the proof-format prototype (#191 / #660).
//!
//! This is separate from the in-circuit element stream in [`crate::io`].
//! [`Encode::encode`] and [`Decode::decode`] compose payloads; [`Encode::to_bytes`]
//! and [`Decode::from_bytes`] add/check one version byte at the outer boundary.
//! The caller must select the same schema, field/curve suite and rank. These
//! experimental bytes do not yet define the production proof format.
//!
//! Integers and lengths are little-endian; lengths always occupy eight bytes.
//! Scalar and point representations are specified by their respective types.
//! Explicit [`Scalar`] and [`Point`] codecs avoid overlapping blanket impls.
//! When more than one codec applies, select it explicitly, for example
//! `<Vec<u64> as Decode>::from_bytes(bytes, limits)` for the ordinary vector
//! codec, or `<Vec<F> as Decode<Sequence<Scalar>>>::from_bytes(bytes, limits)`
//! for field elements. Custom decoders must use the reader's reservation helper to participate in its resource budgets.

use alloc::{boxed::Box, vec::Vec};
use core::{marker::PhantomData, mem::size_of};

use ragu_arithmetic::{ff::PrimeField, group::GroupEncoding};

#[cfg(test)]
mod tests;

/// Version of the experimental envelope. Nested payloads have no envelope.
pub const VERSION: u8 = 1;

/// The ordinary codec for integers, containers and generated structs.
pub struct DefaultEncoding;
/// The canonical [`PrimeField`] representation.
pub struct Scalar;
/// The checked, compressed [`GroupEncoding`] representation.
pub struct Point;
/// A length-prefixed vector whose elements use codec `C`.
pub struct Sequence<C>(PhantomData<C>);

/// Generates a compressed struct and its ordered byte codecs.
///
/// Every field requires `#[ragu(provided)]` or `#[ragu(derived)]`. Provided
/// fields may select `#[ragu(provided, codec = Scalar)]` (or another codec).
/// The default name is `<Name>Compressed`; override it with
/// `#[ragu(compressed = Name)]` on the struct. Only named-field structs are
/// supported. Source generic parameters and bounds are preserved; type and
/// lifetime parameters must also be used by retained fields.
/// Compression clones provided fields, never derived fields.
/// Expansion remains a handwritten, domain-specific computation.
/// The annotations declare the access boundary; the derive does not establish
/// the mathematical correctness of a field's classification.
/// Generated fields retain documentation, configuration (`cfg` / `cfg_attr`),
/// and lint attributes. Helper attributes for other derives are not copied;
/// only `provided` / `derived` control which fields the wire codec includes.
/// Other keys in the shared `ragu` namespace are ignored.
///
/// ```
/// use ragu_primitives::wire::{Compress, Decode, Encode, Limits};
/// #[derive(Compress)]
/// #[ragu(compressed = Package)]
/// struct Desk {
///     #[ragu(provided)]
///     value: u64,
///     #[ragu(derived)]
///     scratch: u64,
/// }
/// let desk = Desk { value: 42, scratch: 9 };
/// let bytes = desk.compress().to_bytes();
/// let package = Package::from_bytes(&bytes, Limits::default()).unwrap();
/// assert_eq!(package.value, 42);
/// ```
///
/// An unclassified field is a macro error:
/// ```compile_fail
/// use ragu_primitives::wire::Compress;
/// #[derive(Compress)]
/// struct Desk { value: u64 }
/// ```
/// Omitted fields are unavailable through the compressed type:
/// ```compile_fail,E0609
/// use ragu_primitives::wire::Compress;
/// #[derive(Compress)]
/// struct Desk {
///     #[ragu(provided)]
///     value: u64,
///     #[ragu(derived)]
///     scratch: u64,
/// }
/// let package = Desk { value: 1, scratch: 2 }.compress();
/// let _ = package.scratch;
/// ```
pub use ragu_macros::Compress;

/// Projects a working representation onto explicitly provided fields.
pub trait Compress {
    /// Representation that excludes fields classified as derived.
    type Compressed;
    /// Clones only the provided fields into the compressed representation.
    fn compress(&self) -> Self::Compressed;
}

/// Paths used by generated code, including in `no_std` consumers.
#[doc(hidden)]
pub mod __private {
    pub use alloc::vec::Vec;
}

/// Encodes a value using codec `C`.
pub trait Encode<C = DefaultEncoding> {
    /// Appends the canonical payload, without a version envelope.
    fn encode(&self, output: &mut Vec<u8>);

    /// Encodes one complete value with the prototype version byte.
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
#[derive(Debug, thiserror::Error)]
pub enum Error<'a> {
    /// The next value extends beyond the input.
    #[error("truncated input at byte {offset}: need {requested} bytes, have {}", bytes.len())]
    Truncated {
        /// Start of the missing value.
        offset: usize,
        /// Number of bytes requested.
        requested: usize,
        /// Available bytes at that position.
        bytes: &'a [u8],
    },
    /// Bytes are not a canonical representation of the expected value.
    #[error("invalid encoding at byte {offset}: {reason}")]
    Invalid {
        /// Start of the offending value.
        offset: usize,
        /// The offending bytes.
        bytes: &'a [u8],
        /// Explanation of the rejected representation.
        reason: &'static str,
    },
    /// A wire count cannot be represented by this machine.
    #[error("length {value} at byte {offset} exceeds the host address space")]
    Length {
        /// Offset immediately after reading the count.
        offset: usize,
        /// Offending count, without truncation to `usize`.
        value: u64,
    },
    /// A container would exceed a shared decoding budget.
    #[error(
        "{resource} budget exceeded at byte {offset}: requested {requested}, remaining {remaining}"
    )]
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
    #[error("could not allocate {elements} elements at byte {offset}")]
    Allocation {
        /// Position where the allocation was attempted.
        offset: usize,
        /// Requested number of elements.
        elements: usize,
    },
    /// An owning domain rejected a structurally invalid value.
    #[error("invalid value at byte {offset}: {source}")]
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
    pub fn reserve<T>(&mut self, count: u64, minimum_bytes: usize) -> Result<Vec<T>, Error<'a>> {
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
        let bytes = count.checked_mul(size_of::<T>()).ok_or(Error::Limit {
            offset: self.offset,
            resource: "allocation",
            requested: usize::MAX,
            remaining: self.limits.allocation,
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

impl<F: PrimeField> Encode<Scalar> for F {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(self.to_repr().as_ref());
    }
}
impl<F: PrimeField> Decode<Scalar> for F {
    fn min_encoded_len() -> usize {
        F::Repr::default().as_ref().len()
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        let offset = reader.offset();
        let mut repr = F::Repr::default();
        let bytes = reader.take(repr.as_ref().len())?;
        repr.as_mut().copy_from_slice(bytes);
        let value = Option::<F>::from(F::from_repr(repr)).ok_or(Error::Invalid {
            offset,
            bytes,
            reason: "non-canonical field element",
        })?;
        if value.to_repr().as_ref() != bytes {
            return Err(Error::Invalid {
                offset,
                bytes,
                reason: "non-canonical field element",
            });
        }
        Ok(value)
    }
}

impl<G: GroupEncoding> Encode<Point> for G {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(self.to_bytes().as_ref());
    }
}
impl<G: GroupEncoding> Decode<Point> for G {
    fn min_encoded_len() -> usize {
        G::Repr::default().as_ref().len()
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        let offset = reader.offset();
        let mut repr = G::Repr::default();
        let bytes = reader.take(repr.as_ref().len())?;
        repr.as_mut().copy_from_slice(bytes);
        let value = Option::<G>::from(G::from_bytes(&repr)).ok_or(Error::Invalid {
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
