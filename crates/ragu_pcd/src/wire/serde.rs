//! `serde` support for [`Proof`] and [`CompressedProof`]: each serializes as
//! one byte string, so every serde data format carries the same bytes and the
//! same decoding checks apply.
//!
//! The string is the codec version byte; a prelude recording the rank, as a
//! little-endian `u32`, and the header size, as a little-endian `u64`, which
//! neither type carries; and then the payload, in the layout
//! [`ProofFormat`](crate::ProofFormat) envelopes. The prelude fixes the
//! payload's exact length, which deserialization checks before decoding it,
//! and formats without a bytes type are buffered only up to that length.
//!
//! A [`Proof`] writes only the fields its encoding retains. Deserializing one
//! yields a proof whose derived fields the application fills, never reading
//! them from the input, when one of its methods first takes it.
//!
//! The prelude is not a trusted context and identifies no application: use
//! `ProofFormat` for an envelope bound to an application's identifiers.

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use ragu_circuits::polynomials::Rank;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
    ser,
};

use crate::{
    CompressedProof, Proof,
    profile::ProfiledCycle,
    wire::{self, Decode, Dimensions, Encode, Error, Reader},
};

/// The version byte and the prelude: the rank as a `u32` and the header size
/// as a `u64`, as the envelope records them.
const PRELUDE_LEN: usize = 1 + 4 + 8;

/// The largest rank a compressed proof's prelude may declare. A compressed
/// proof's rank fixes its IPA rounds, one per bit, so this bounds the length
/// a prelude implies; a proof's rank is its type's.
const MAX_RANK: u32 = 32;

/// The largest header size a prelude may declare, bounding the length it
/// implies.
const MAX_HEADER_SIZE: usize = 1 << 12;

/// A type serialized as one framed byte string.
trait Framed: Encode + Decode {
    /// What a deserializer expects, for its error messages.
    const EXPECTING: &'static str;

    /// The dimensions this value is encoded in, or `None` if it has no
    /// encoding.
    fn dims(&self) -> Option<Dimensions>;

    /// Rejects dimensions a prelude declares that no value of this type has.
    fn admits(dims: Dimensions) -> Result<(), &'static str>;
}

fn admits_header_size(dims: Dimensions) -> Result<(), &'static str> {
    if dims.header_size > MAX_HEADER_SIZE {
        return Err("proof header size exceeds the limit");
    }
    Ok(())
}

impl<C: ProfiledCycle, R: Rank> Framed for Proof<C, R> {
    const EXPECTING: &'static str = "a proof in its wire format";

    fn dims(&self) -> Option<Dimensions> {
        let dims = Dimensions {
            rank: R::RANK,
            header_size: self.left_header.len(),
        };
        (Self::admits(dims).is_ok() && self.well_formed_in(dims)).then_some(dims)
    }

    fn admits(dims: Dimensions) -> Result<(), &'static str> {
        if dims.rank != R::RANK {
            return Err("proof rank mismatch");
        }
        admits_header_size(dims)
    }
}

impl<C: ProfiledCycle> Framed for CompressedProof<C> {
    const EXPECTING: &'static str = "a compressed proof in its wire format";

    fn dims(&self) -> Option<Dimensions> {
        let dims = Dimensions {
            rank: u32::try_from(self.native.opening.rounds.len()).ok()?,
            header_size: self.instance.left_header.len(),
        };
        (Self::admits(dims).is_ok() && self.well_formed_in(dims)).then_some(dims)
    }

    fn admits(dims: Dimensions) -> Result<(), &'static str> {
        if dims.rank > MAX_RANK {
            return Err("compressed proof rank exceeds the limit");
        }
        admits_header_size(dims)
    }
}

/// The framed byte string of `value`, which has dimensions `dims`.
fn framed<T: Framed>(value: &T, dims: Dimensions) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PRELUDE_LEN + T::encoded_len(dims));
    bytes.push(wire::VERSION);
    dims.rank.encode(&mut bytes);
    (dims.header_size as u64).encode(&mut bytes);
    value.encode(&mut bytes);
    bytes
}

/// Reads the prelude at the start of `input`, returning the dimensions it
/// declares and the exact length of the framed string it implies.
fn prelude<T: Framed>(input: &[u8]) -> Result<(Dimensions, usize), Error<'_>> {
    let mut reader = Reader::new(input);
    let version = reader.take(1)?;
    if version[0] != wire::VERSION {
        return Err(Error::Invalid {
            offset: 0,
            bytes: version,
            reason: "unsupported wire version",
        });
    }
    // Integers have layouts independent of the dimensions.
    let unshaped = Dimensions::default();
    let rank = u32::decode(&mut reader, unshaped)?;
    let header_size = u64::decode(&mut reader, unshaped)?;
    let invalid = |reason| Error::Invalid {
        offset: 1,
        bytes: &input[1..PRELUDE_LEN],
        reason,
    };
    let dims = Dimensions {
        rank,
        header_size: usize::try_from(header_size)
            .map_err(|_| invalid("proof header size exceeds the limit"))?,
    };
    T::admits(dims).map_err(invalid)?;
    Ok((dims, PRELUDE_LEN + T::encoded_len(dims)))
}

/// Decodes a complete framed string of exactly the length its prelude implies.
fn decode_framed<T: Framed>(input: &[u8]) -> Result<T, Error<'_>> {
    let (dims, expected) = prelude::<T>(input)?;
    if input.len() != expected {
        return Err(Error::Length {
            expected,
            actual: input.len(),
        });
    }
    let mut reader = Reader::new(input);
    reader.take(PRELUDE_LEN)?;
    T::decode(&mut reader, dims)
}

fn serialize_framed<T: Framed, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
    // A value of other dimensions than its type admits has no encoding.
    let Some(dims) = value.dims() else {
        return Err(ser::Error::custom("proof does not have its type's shape"));
    };
    serializer.serialize_bytes(&framed(value, dims))
}

/// Accepts the byte string however the format presents it: borrowed, owned,
/// or as a sequence in formats without a bytes type.
struct Bytes<T>(PhantomData<T>);

/// Buffers a framed string from a sequence. Length hints are untrusted: grow
/// from observed input, with fallible reservations capped at the prelude's
/// length until it is read, and at the length it implies after.
fn read_framed<'de, T: Framed, A: SeqAccess<'de>>(mut seq: A) -> Result<Vec<u8>, A::Error> {
    let mut bytes = Vec::new();
    let mut limit = PRELUDE_LEN;
    let mut known = false;
    while let Some(byte) = seq.next_element::<u8>()? {
        if known && bytes.len() == limit {
            return Err(de::Error::custom("encoded proof exceeds its fixed length"));
        }
        if bytes.len() == bytes.capacity() {
            let additional = bytes.capacity().max(4096).min(limit - bytes.len());
            bytes
                .try_reserve_exact(additional)
                .map_err(de::Error::custom)?;
        }
        bytes.push(byte);
        if !known && bytes.len() == PRELUDE_LEN {
            limit = prelude::<T>(&bytes).map_err(de::Error::custom)?.1;
            known = true;
        }
    }
    Ok(bytes)
}

impl<'de, T: Framed> Visitor<'de> for Bytes<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(T::EXPECTING)
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        // The decoder borrows its error from the input, so it is rendered
        // before the input goes out of scope.
        decode_framed(bytes).map_err(E::custom)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        let bytes = read_framed::<T, A>(seq)?;
        self.visit_bytes(&bytes)
    }
}

impl<C: ProfiledCycle, R: Rank> Serialize for Proof<C, R> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_framed(self, serializer)
    }
}

impl<'de, C: ProfiledCycle, R: Rank> Deserialize<'de> for Proof<C, R> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(Bytes(PhantomData))
    }
}

impl<C: ProfiledCycle> Serialize for CompressedProof<C> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_framed(self, serializer)
    }
}

impl<'de, C: ProfiledCycle> Deserialize<'de> for CompressedProof<C> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(Bytes(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use ragu_circuits::polynomials::ProductionRank;
    use ragu_core::pasta::Pasta;
    use serde::de::{
        DeserializeSeed,
        value::{Error, SeqDeserializer},
    };

    use super::*;

    type TestProof = Proof<Pasta, ProductionRank>;
    type TestCompressed = CompressedProof<Pasta>;

    struct EmptyWithHugeHint;

    impl<'de> SeqAccess<'de> for EmptyWithHugeHint {
        type Error = Error;

        fn next_element_seed<T: DeserializeSeed<'de>>(
            &mut self,
            _: T,
        ) -> Result<Option<T::Value>, Error> {
            Ok(None)
        }

        fn size_hint(&self) -> Option<usize> {
            Some(usize::MAX)
        }
    }

    /// A prelude declaring `rank` and `header_size`.
    fn prelude_bytes(rank: u32, header_size: u64) -> Vec<u8> {
        let mut bytes = alloc::vec![wire::VERSION];
        bytes.extend_from_slice(&rank.to_le_bytes());
        bytes.extend_from_slice(&header_size.to_le_bytes());
        bytes
    }

    #[test]
    fn sequence_size_hint_does_not_control_allocation() {
        let error = Bytes::<TestProof>(PhantomData)
            .visit_seq(EmptyWithHugeHint)
            .err()
            .expect("empty input must fail to decode");
        assert!(error.to_string().contains("truncated"), "{error}");
    }

    #[test]
    fn sequence_buffer_stops_at_the_length_the_prelude_implies() {
        let dims = Dimensions::of::<ProductionRank, 4>();
        let limit = PRELUDE_LEN + TestCompressed::encoded_len(dims);
        let prelude = prelude_bytes(dims.rank, dims.header_size as u64);
        let input = |extra: usize| {
            prelude
                .iter()
                .copied()
                .chain(core::iter::repeat_n(0u8, limit - PRELUDE_LEN + extra))
        };
        // The declared length is read whole; one byte more is refused.
        assert_eq!(
            read_framed::<TestCompressed, _>(SeqDeserializer::<_, Error>::new(input(0)))
                .unwrap()
                .len(),
            limit
        );
        let error = read_framed::<TestCompressed, _>(SeqDeserializer::<_, Error>::new(input(1)))
            .unwrap_err();
        assert!(
            error.to_string().contains("exceeds its fixed length"),
            "{error}"
        );

        // An iterator without an upper size hint must stop at the limit too.
        let unbounded = prelude
            .iter()
            .copied()
            .chain(core::iter::repeat(0u8))
            .filter(|_| true);
        let error = read_framed::<TestCompressed, _>(SeqDeserializer::<_, Error>::new(unbounded))
            .unwrap_err();
        assert!(
            error.to_string().contains("exceeds its fixed length"),
            "{error}"
        );
    }

    #[test]
    fn prelude_bounds_the_shape_before_any_payload_is_buffered() {
        for (prelude, reason) in [
            (prelude_bytes(12, 4), "proof rank mismatch"),
            (
                prelude_bytes(13, MAX_HEADER_SIZE as u64 + 1),
                "proof header size exceeds the limit",
            ),
            (
                prelude_bytes(13, u64::MAX),
                "proof header size exceeds the limit",
            ),
        ] {
            let error = read_framed::<TestProof, _>(SeqDeserializer::<_, Error>::new(
                prelude.into_iter().chain(core::iter::repeat(0u8)),
            ))
            .unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
        }
        let error = read_framed::<TestCompressed, _>(SeqDeserializer::<_, Error>::new(
            prelude_bytes(MAX_RANK + 1, 4)
                .into_iter()
                .chain(core::iter::repeat(0u8)),
        ))
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("compressed proof rank exceeds the limit"),
            "{error}"
        );
    }
}
