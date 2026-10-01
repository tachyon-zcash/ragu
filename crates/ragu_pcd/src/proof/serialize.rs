//! `serde` support for [`MinimalProof`]: one byte string in the wire
//! format, so every serde data format carries the same bytes and the same
//! decoding checks apply.
//!
//! Encoded and decoded inputs use the schema's rank-derived bounds. Formats
//! without a bytes type need a temporary buffer before decoding. This adapter
//! carries the low-level payload; use `ProofFormat` for a context-bound envelope.

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use ragu_circuits::polynomials::Rank;
use ragu_core::Cycle;
use ragu_primitives::wire::{Decode, Encode};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
};

use super::MinimalProof;

impl<C: Cycle, R: Rank> Serialize for MinimalProof<C, R>
where
    Self: Encode,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

/// Accepts the byte string however the format presents it: borrowed, owned,
/// or as a sequence in formats without a bytes type.
struct Bytes<C, R>(PhantomData<(C, R)>);

fn read_bytes<'de, A: SeqAccess<'de>>(mut seq: A, limit: usize) -> Result<Vec<u8>, A::Error> {
    // Length hints are untrusted. Grow from observed input, with fallible
    // reservations capped before allocation, including for hintless formats.
    let mut bytes = Vec::new();
    while let Some(byte) = seq.next_element::<u8>()? {
        if bytes.len() == limit {
            return Err(de::Error::custom("encoded proof exceeds byte limit"));
        }
        if bytes.len() == bytes.capacity() {
            let additional = bytes.capacity().max(4096).min(limit - bytes.len());
            bytes
                .try_reserve_exact(additional)
                .map_err(de::Error::custom)?;
        }
        bytes.push(byte);
    }
    Ok(bytes)
}

impl<'de, C: Cycle, R: Rank> Visitor<'de> for Bytes<C, R>
where
    MinimalProof<C, R>: Decode,
{
    type Value = MinimalProof<C, R>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a minimal proof in its wire format")
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        if bytes.len() > MinimalProof::<C, R>::max_encoded_size() {
            return Err(E::custom("encoded proof exceeds byte limit"));
        }
        // The decoder borrows its error from the input, so it is rendered
        // before the input goes out of scope.
        MinimalProof::from_bytes(bytes, MinimalProof::<C, R>::decode_limits()).map_err(E::custom)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        let bytes = read_bytes(seq, MinimalProof::<C, R>::max_encoded_size())?;
        self.visit_bytes(&bytes)
    }
}

impl<'de, C: Cycle, R: Rank> Deserialize<'de> for MinimalProof<C, R>
where
    Self: Decode,
{
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

    #[test]
    fn sequence_size_hint_does_not_control_allocation() {
        let error = Bytes::<Pasta, ProductionRank>(PhantomData)
            .visit_seq(EmptyWithHugeHint)
            .err()
            .expect("empty input must fail to decode");
        assert!(error.to_string().contains("truncated input"), "{error}");
    }

    #[test]
    fn sequence_buffer_rejects_input_beyond_its_limit() {
        let sequence = || SeqDeserializer::<_, Error>::new([1u8, 2, 3, 4].into_iter());
        assert_eq!(read_bytes(sequence(), 4).unwrap(), [1, 2, 3, 4]);
        let error = read_bytes(sequence(), 3).unwrap_err();
        assert!(error.to_string().contains("exceeds byte limit"), "{error}");

        // An iterator without an upper size hint must stop at the limit too.
        let sequence = SeqDeserializer::<_, Error>::new(core::iter::repeat(0u8).filter(|_| true));
        let error = read_bytes(sequence, 3).unwrap_err();
        assert!(error.to_string().contains("exceeds byte limit"), "{error}");
    }
}
