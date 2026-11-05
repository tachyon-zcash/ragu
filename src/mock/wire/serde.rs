//! `serde` support for mock [`Proof`] and [`Pcd`]: each serializes as one
//! byte string holding exactly the bytes `to_bytes` writes, envelope
//! included, so every serde data format carries the same bytes and the same
//! decoding checks apply.
//!
//! Mirrors `ragu_pcd::wire::serde`. The envelope fixes a proof's exact
//! length and bounds a PCD's length by its header element count, which
//! deserialization checks before decoding the payload; formats without a
//! bytes type are buffered only up to that bound. A deserializer may
//! allocate its own byte buffer before calling the visitor; callers must
//! limit that allocation through the backend or its input.

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use ragu_circuits::polynomials::Rank;
use ragu_core::Cycle;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, SeqAccess, Visitor},
    ser,
};

use super::{
    super::{Pcd, Proof},
    ENVELOPE_SIZE, Error, WireHeader,
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

impl<C: Cycle, R: Rank> Framed for Proof<C, R> {
    const EXPECTING: &'static str = "a mock proof in its wire format";

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

impl<C: Cycle, R: Rank, H: WireHeader<C::CircuitField>> Framed for Pcd<C, R, H> {
    const EXPECTING: &'static str = "a mock PCD in its wire format";

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

/// Buffers an encoding from a sequence. Length hints are untrusted: grow
/// from observed input, with fallible reservations capped at the envelope's
/// length until it is read, and at the length it implies after.
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

impl<C: Cycle, R: Rank> Serialize for Proof<C, R> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_framed(self, serializer)
    }
}

impl<'de, C: Cycle, R: Rank> Deserialize<'de> for Proof<C, R> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(Bytes(PhantomData))
    }
}

impl<C: Cycle, R: Rank, H: WireHeader<C::CircuitField>> Serialize for Pcd<C, R, H> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_framed(self, serializer)
    }
}

impl<'de, C: Cycle, R: Rank, H: WireHeader<C::CircuitField>> Deserialize<'de> for Pcd<C, R, H> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(Bytes(PhantomData))
    }
}
