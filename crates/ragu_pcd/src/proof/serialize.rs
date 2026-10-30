//! `serde` support for [`MinimalProof`]: one byte string in the wire
//! format, so every serde data format carries the same bytes and the same
//! decoding checks apply.
//!
//! The byte string has the fixed length the type determines: serializing a
//! proof of another shape is an error, anything else is rejected on
//! deserialization, and formats without a bytes type are buffered only up to
//! that length. This adapter carries the low-level payload; use `ProofFormat`
//! for a context-bound envelope.

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use ragu_circuits::polynomials::Rank;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
    ser,
};

use super::MinimalProof;
use crate::{
    profile::ProfiledCycle,
    wire::{Decode, Encode},
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Serialize
    for MinimalProof<C, R, HEADER_SIZE>
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // A proof of another shape has no encoding of this length.
        if !self.well_formed() {
            return Err(ser::Error::custom(
                "proof does not have the profile's shape",
            ));
        }
        serializer.serialize_bytes(&self.to_bytes())
    }
}

/// Accepts the byte string however the format presents it: borrowed, owned,
/// or as a sequence in formats without a bytes type.
struct Bytes<C, R, const HEADER_SIZE: usize>(PhantomData<(C, R)>);

fn read_bytes<'de, A: SeqAccess<'de>>(mut seq: A, limit: usize) -> Result<Vec<u8>, A::Error> {
    // Length hints are untrusted. Grow from observed input, with fallible
    // reservations capped at the one valid length, including for hintless formats.
    let mut bytes = Vec::new();
    while let Some(byte) = seq.next_element::<u8>()? {
        if bytes.len() == limit {
            return Err(de::Error::custom("encoded proof exceeds its fixed length"));
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

impl<'de, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Visitor<'de>
    for Bytes<C, R, HEADER_SIZE>
{
    type Value = MinimalProof<C, R, HEADER_SIZE>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a minimal proof in its wire format")
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        // The decoder borrows its error from the input, so it is rendered
        // before the input goes out of scope.
        MinimalProof::from_bytes(bytes).map_err(E::custom)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        let bytes = read_bytes(seq, 1 + MinimalProof::<C, R, HEADER_SIZE>::encoded_len())?;
        self.visit_bytes(&bytes)
    }
}

impl<'de, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> Deserialize<'de>
    for MinimalProof<C, R, HEADER_SIZE>
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
        let error = Bytes::<Pasta, ProductionRank, 4>(PhantomData)
            .visit_seq(EmptyWithHugeHint)
            .err()
            .expect("empty input must fail to decode");
        assert!(
            error.to_string().contains("incorrect encoded length"),
            "{error}"
        );
    }

    #[test]
    fn sequence_buffer_rejects_input_beyond_its_limit() {
        let sequence = || SeqDeserializer::<_, Error>::new([1u8, 2, 3, 4].into_iter());
        assert_eq!(read_bytes(sequence(), 4).unwrap(), [1, 2, 3, 4]);
        let error = read_bytes(sequence(), 3).unwrap_err();
        assert!(
            error.to_string().contains("exceeds its fixed length"),
            "{error}"
        );

        // An iterator without an upper size hint must stop at the limit too.
        let sequence = SeqDeserializer::<_, Error>::new(core::iter::repeat(0u8).filter(|_| true));
        let error = read_bytes(sequence, 3).unwrap_err();
        assert!(
            error.to_string().contains("exceeds its fixed length"),
            "{error}"
        );
    }
}
