//! `serde` support for [`Proof`] and [`CompressedProof`]: each serializes as
//! one byte string holding exactly the bytes [`Proof::to_bytes`] and
//! [`CompressedProof::to_bytes`] write, envelope included, so every serde data
//! format carries the same bytes and the same decoding checks apply.
//!
//! The envelope fixes the string's exact length, which deserialization checks
//! before decoding the payload, and formats without a bytes type are buffered
//! only up to that length. A deserializer may allocate its own byte buffer
//! before calling the visitor; callers must limit that allocation through the
//! backend or its input.
//!
//! The caller selects the expected application and cryptographic parameters
//! through its deployment or consensus rules, as with [`Proof::from_bytes`].
//! Deserialization checks representation; verification uses that application.

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
    wire::{ENVELOPE_SIZE, Error},
};

/// A type serialized as its versioned byte encoding.
trait Framed: Sized {
    /// What a deserializer expects, for its error messages.
    const EXPECTING: &'static str;

    /// The encoding with its envelope.
    fn to_wire(&self) -> Result<Vec<u8>, Error<'static>>;

    /// Decodes one complete encoding.
    fn from_wire(bytes: &[u8]) -> Result<Self, Error<'_>>;

    /// The exact length of the encoding whose envelope `bytes` begins with.
    fn wire_len(bytes: &[u8]) -> Result<usize, Error<'_>>;
}

impl<C: ProfiledCycle, R: Rank> Framed for Proof<C, R> {
    const EXPECTING: &'static str = "a proof in its wire format";

    fn to_wire(&self) -> Result<Vec<u8>, Error<'static>> {
        Self::to_bytes(self)
    }

    fn from_wire(bytes: &[u8]) -> Result<Self, Error<'_>> {
        Self::from_bytes(bytes)
    }

    fn wire_len(bytes: &[u8]) -> Result<usize, Error<'_>> {
        Self::framed_len(bytes)
    }
}

impl<C: ProfiledCycle> Framed for CompressedProof<C> {
    const EXPECTING: &'static str = "a compressed proof in its wire format";

    fn to_wire(&self) -> Result<Vec<u8>, Error<'static>> {
        Self::to_bytes(self)
    }

    fn from_wire(bytes: &[u8]) -> Result<Self, Error<'_>> {
        Self::from_bytes(bytes)
    }

    fn wire_len(bytes: &[u8]) -> Result<usize, Error<'_>> {
        Self::framed_len(bytes)
    }
}

fn serialize_framed<T: Framed, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
    let bytes = value.to_wire().map_err(ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

/// Accepts the byte string however the format presents it: borrowed, owned,
/// or as a sequence in formats without a bytes type.
struct Bytes<T>(PhantomData<T>);

/// Buffers an encoding from a sequence. Length hints are untrusted: grow from
/// observed input, with fallible reservations capped at the envelope's length
/// until it is read, and at the length it implies after.
fn read_framed<'de, T: Framed, A: SeqAccess<'de>>(mut seq: A) -> Result<Vec<u8>, A::Error> {
    let mut bytes = Vec::new();
    let mut limit = ENVELOPE_SIZE;
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
        if !known && bytes.len() == ENVELOPE_SIZE {
            limit = T::wire_len(&bytes).map_err(de::Error::custom)?;
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
        T::from_wire(bytes).map_err(E::custom)
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
    use crate::wire::{
        Decode, Dimensions, MAX_HEADER_SIZE, MAX_RANK,
        format::{PayloadKind, write_envelope},
    };

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

    /// An envelope of `payload` declaring `rank` and `header_size`.
    fn envelope(payload: PayloadKind, rank: u32, header_size: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_envelope(
            payload,
            Dimensions {
                rank,
                header_size: 0,
            },
            &mut bytes,
        );
        bytes[20..28].copy_from_slice(&header_size.to_le_bytes());
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
    fn sequence_buffer_stops_at_the_length_the_envelope_implies() {
        let dims = Dimensions::of::<ProductionRank, 4>();
        let limit = ENVELOPE_SIZE + <TestCompressed as Decode>::encoded_len(dims);
        let envelope = envelope(PayloadKind::Compressed, dims.rank, dims.header_size as u64);
        let input = |extra: usize| {
            envelope
                .iter()
                .copied()
                .chain(core::iter::repeat_n(0u8, limit - ENVELOPE_SIZE + extra))
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
        let unbounded = envelope
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
    fn envelope_bounds_the_shape_before_any_payload_is_buffered() {
        for (envelope, reason) in [
            (
                envelope(PayloadKind::Compressed, 13, 4),
                "proof payload kind mismatch",
            ),
            (envelope(PayloadKind::Proof, 12, 4), "proof rank mismatch"),
            (
                envelope(PayloadKind::Proof, 13, MAX_HEADER_SIZE as u64 + 1),
                "proof header size exceeds the limit",
            ),
            (
                envelope(PayloadKind::Proof, 13, u64::MAX),
                "proof header size exceeds the limit",
            ),
        ] {
            let error = read_framed::<TestProof, _>(SeqDeserializer::<_, Error>::new(
                envelope.into_iter().chain(core::iter::repeat(0u8)),
            ))
            .unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
        }
        let error = read_framed::<TestCompressed, _>(SeqDeserializer::<_, Error>::new(
            envelope(PayloadKind::Compressed, MAX_RANK + 1, 4)
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
