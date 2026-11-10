//! Framing for a mock PCD and its header data.
//!
//! The outer envelope has payload kind 4 and stores the number of flattened
//! header elements. Its payload is a complete proof encoding (kind 1), the
//! header suffix, the element count, and canonical field elements. Keeping the
//! proof encoding intact lets this format follow the mock proof codec as it
//! evolves without duplicating its binding and polynomial checks.

use alloc::vec::Vec;

use ragu_circuits::polynomials::Rank;
use ragu_core::{Cycle, drivers::Driver as _, maybe::Maybe as _};
use ragu_pcd::profile::ProfiledCycle;
use ragu_primitives::{GadgetExt as _, Simulator};
use udon::field::Field;

use super::{ENVELOPE_SIZE, Error, PayloadKind, open, write_envelope};
use crate::mock::{
    Pcd, Proof,
    header::{Header, Suffix},
};

/// A header whose data can be rebuilt from its flattened field elements.
pub trait WireHeader<F: Field>: Header<F> {
    /// Rebuilds data from exactly the elements emitted by `Header::encode`.
    fn decode(elements: &[F]) -> Option<Self::Data>;
}

impl<F: Field> WireHeader<F> for () {
    fn decode(elements: &[F]) -> Option<Self::Data> {
        elements.is_empty().then_some(())
    }
}

fn encode_header_elements<C: Cycle, H: Header<C::CircuitField>>(
    data: &H::Data,
) -> Result<Vec<C::CircuitField>, Error<'static>> {
    let mut dr = Simulator::<C::CircuitField>::new();
    let witness = Simulator::<C::CircuitField>::just(|| data.clone());
    let gadget = H::encode(&mut dr, &mut (), witness).map_err(|_| Error::Unencodable)?;
    let mut elements = Vec::new();
    gadget
        .write(&mut dr, &mut elements)
        .map_err(|_| Error::Unencodable)?;
    Ok(elements
        .into_iter()
        .map(|element| *element.value().take())
        .collect())
}

pub(super) fn encoded_len<C: ProfiledCycle, R: Rank>(elements: usize) -> usize {
    ENVELOPE_SIZE
        + Proof::<C, R>::encoded_len::<0>()
        + 16
        + elements * C::CircuitField::ZERO.to_bytes().as_ref().len()
}

impl<C: ProfiledCycle, R: Rank, H: WireHeader<C::CircuitField>> Pcd<C, R, H> {
    /// Encodes the proof and header data in a bounded, versioned frame.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error<'static>> {
        let elements = encode_header_elements::<C, H>(&self.data)?;
        if elements.len() > super::MAX_HEADER_SIZE {
            return Err(Error::Unencodable);
        }
        let proof = self.proof.to_bytes()?;
        let mut bytes = Vec::with_capacity(encoded_len::<C, R>(elements.len()));
        write_envelope(PayloadKind::Pcd, R::RANK, elements.len(), &mut bytes);
        bytes.extend_from_slice(&proof);
        bytes.extend_from_slice(&H::SUFFIX.get().to_le_bytes());
        bytes.extend_from_slice(&(elements.len() as u64).to_le_bytes());
        for element in elements {
            bytes.extend_from_slice(element.to_bytes().as_ref());
        }
        Ok(bytes)
    }

    /// Decodes representation only. Verify with the expected application.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<'_>> {
        let (mut reader, _, elements) = open(bytes, PayloadKind::Pcd, Some(R::RANK))?;
        let expected = encoded_len::<C, R>(elements);
        if bytes.len() != expected {
            return Err(Error::Length {
                expected,
                actual: bytes.len(),
            });
        }

        let proof = Proof::<C, R>::from_bytes(reader.take(Proof::<C, R>::encoded_len::<0>())?)?;
        let suffix_offset = reader.offset();
        let suffix_bytes = reader.take(8)?;
        let suffix = Suffix::from_value(u64::from_le_bytes(
            suffix_bytes.try_into().expect("eight-byte suffix"),
        ))
        .ok_or(Error::Invalid {
            offset: suffix_offset,
            bytes: suffix_bytes,
            reason: "invalid header suffix",
        })?;
        if suffix != H::SUFFIX {
            return Err(Error::Invalid {
                offset: suffix_offset,
                bytes: suffix_bytes,
                reason: "mock PCD header suffix mismatch",
            });
        }
        let count_offset = reader.offset();
        let count_bytes = reader.take(8)?;
        if u64::from_le_bytes(count_bytes.try_into().expect("eight-byte count")) != elements as u64
        {
            return Err(Error::Invalid {
                offset: count_offset,
                bytes: count_bytes,
                reason: "header element count does not match the envelope",
            });
        }

        let header_offset = reader.offset();
        let mut values = Vec::with_capacity(elements);
        let mut repr = C::CircuitField::ZERO.to_bytes();
        for _ in 0..elements {
            let offset = reader.offset();
            let value_bytes = reader.take(repr.as_ref().len())?;
            repr.as_mut().copy_from_slice(value_bytes);
            values.push(C::CircuitField::from_bytes(repr).ok_or(Error::Invalid {
                offset,
                bytes: value_bytes,
                reason: "non-canonical field element",
            })?);
        }
        let data = H::decode(&values).ok_or(Error::Invalid {
            offset: header_offset,
            bytes: &bytes[header_offset..],
            reason: "header data rejected by its header",
        })?;
        let reencoded = encode_header_elements::<C, H>(&data).map_err(|_| Error::Invalid {
            offset: header_offset,
            bytes: &bytes[header_offset..],
            reason: "decoded header data cannot be re-encoded",
        })?;
        if reencoded != values {
            return Err(Error::Invalid {
                offset: header_offset,
                bytes: &bytes[header_offset..],
                reason: "decoded header data changes its encoding",
            });
        }
        Ok(proof.carry::<H>(data))
    }
}
