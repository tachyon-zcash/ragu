//! Versioned application envelope over fixed-length minimal and compressed proofs.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;
use udon::field::Field;

use super::MinimalProof;
use crate::{
    Application, SelectableBackend,
    profile::ProfiledCycle,
    wire::{Decode, Encode, Error, Reader, Scalar},
};

const MAGIC: &[u8; 8] = b"RAGUPCD\0";
const ENVELOPE_VERSION: u16 = 1;
/// The payload kind of a minimal proof. The envelope carries one kind per
/// proof representation, each with its own schema.
const MINIMAL_PAYLOAD: u16 = 1;
const COMPRESSED_PAYLOAD: u16 = 2;
const MINIMAL_SCHEMA_VERSION: u16 = 1;
const COMPRESSED_SCHEMA_VERSION: u16 = 1;
// Matches the verification semantics identified by RAGU_TAG and IPA_TAG.
const PROTOCOL_VERSION: u16 = 1;
const ENVELOPE_SIZE: usize = 92;

/// Trusted identifiers for the cryptographic suite and complete application setup.
///
/// Assign these in your deployment manifest, never from an incoming proof. Use
/// collision-resistant digests of canonical manifests: `suite` must identify the
/// ordered curves, scalar/point encodings, generators and Poseidon parameters;
/// `application` must identify the profile, ordered circuits, registry tags,
/// both protocol transcript domains, and header semantics. Change the corresponding identifier whenever that manifest changes.
/// These identifiers detect context mismatches; they do not authenticate a proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofContext {
    /// Identifier of the complete cryptographic suite and parameters.
    pub suite: [u8; 32],
    /// Identifier of the application and registry setup.
    pub application: [u8; 32],
}

/// A versioned proof format for one application's trusted context.
///
/// Construct with [`Application::proof_format`]. Minimal encodings have exactly
/// [`encoded_len`](Self::encoded_len) bytes; compressed encodings have exactly
/// [`compressed_encoded_len`](Self::compressed_encoded_len) bytes. Other lengths are rejected before
/// the envelope is read, and the envelope is checked before the payload.
/// Decoding validates representation only: a receiver rebuilds the proof
/// with [`Application::expand`], compresses it with [`Application::compress`]
/// and accepts it on [`Application::verify_compressed`]. The uncompressed
/// `verify_minimal`, under `test-utils`, is a test oracle for that path. See
/// the crate's `WIRE_FORMAT.md` for the version and compatibility contract.
pub struct ProofFormat<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> {
    context: ProofContext,
    marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Selects the byte format using identifiers from a trusted setup manifest.
    ///
    /// The application supplies the profile, rank and header size. The caller supplies the
    /// suite and application identifiers described by [`ProofContext`]; they
    /// cannot be inferred from Rust type names or from untrusted proof bytes.
    pub fn proof_format(&self, context: ProofContext) -> ProofFormat<C, R, HEADER_SIZE> {
        ProofFormat {
            context,
            marker: PhantomData,
        }
    }
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> ProofFormat<C, R, HEADER_SIZE> {
    fn envelope(&self, payload: u16) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENVELOPE_SIZE);
        bytes.extend_from_slice(MAGIC);
        ENVELOPE_VERSION.encode(&mut bytes);
        payload.encode(&mut bytes);
        match payload {
            MINIMAL_PAYLOAD => MINIMAL_SCHEMA_VERSION,
            COMPRESSED_PAYLOAD => COMPRESSED_SCHEMA_VERSION,
            _ => unreachable!("internal payload kind"),
        }
        .encode(&mut bytes);
        PROTOCOL_VERSION.encode(&mut bytes);
        R::RANK.encode(&mut bytes);
        (HEADER_SIZE as u64).encode(&mut bytes);
        bytes.extend_from_slice(&self.context.suite);
        bytes.extend_from_slice(&self.context.application);
        bytes
    }

    /// The exact size of every encoding: the envelope plus the payload the
    /// profile, rank and header size fix. Bound transport input to this
    /// before buffering.
    pub fn encoded_len(&self) -> usize {
        ENVELOPE_SIZE + MinimalProof::<C, R, HEADER_SIZE>::encoded_len()
    }

    /// Exact byte length of a compressed proof, including the shared envelope.
    pub fn compressed_encoded_len(&self) -> usize {
        ENVELOPE_SIZE
            + <crate::CompressedProof<C> as Decode<
                crate::compress::codec::Compressed<R, HEADER_SIZE>,
            >>::encoded_len()
    }

    /// Encodes a compressed proof of this application's shape. This does not
    /// verify the proof. Payload kind 2 distinguishes it from a minimal proof.
    pub fn encode_compressed(
        &self,
        proof: &crate::CompressedProof<C>,
    ) -> Result<Vec<u8>, Error<'static>> {
        if !proof.well_formed::<R>()
            || proof.instance.left_header.len() != HEADER_SIZE
            || proof.instance.right_header.len() != HEADER_SIZE
        {
            return Err(Error::Invalid {
                offset: 0,
                bytes: &[],
                reason: "invalid compressed proof structure",
            });
        }
        let mut bytes = self.envelope(COMPRESSED_PAYLOAD);
        <crate::CompressedProof<C> as Encode<crate::compress::codec::Compressed<R, HEADER_SIZE>>>::encode(proof, &mut bytes);
        Ok(bytes)
    }

    /// Decodes a compressed proof after checking its exact length and context.
    /// Attach the accompanying header data with `carry` and use
    /// [`Application::verify_compressed`] before accepting it.
    pub fn decode_compressed<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<crate::CompressedProof<C>, Error<'a>> {
        let mut reader = self.open(bytes, COMPRESSED_PAYLOAD, self.compressed_encoded_len())?;
        <crate::CompressedProof<C> as Decode<crate::compress::codec::Compressed<R, HEADER_SIZE>>>::decode(&mut reader)
    }

    /// Encodes a structurally valid proof, including its version and context.
    /// Does not establish cryptographic validity.
    pub fn encode(
        &self,
        proof: &MinimalProof<C, R, HEADER_SIZE>,
    ) -> Result<Vec<u8>, Error<'static>> {
        if !proof.well_formed() {
            return Err(Error::Invalid {
                offset: 0,
                bytes: &[],
                reason: "invalid proof structure",
            });
        }
        let mut bytes = self.envelope(MINIMAL_PAYLOAD);
        proof.encode(&mut bytes);
        Ok(bytes)
    }

    /// Decodes exactly one encoding, rejecting other lengths, unknown versions,
    /// mismatched context and malformed representation, in that order.
    pub fn decode<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<MinimalProof<C, R, HEADER_SIZE>, Error<'a>> {
        let mut reader = self.open(bytes, MINIMAL_PAYLOAD, self.encoded_len())?;
        MinimalProof::decode(&mut reader)
    }

    /// Checks the length and the envelope of one encoding of `payload`,
    /// leaving the reader at the payload.
    fn open<'a>(
        &self,
        bytes: &'a [u8],
        payload: u16,
        expected: usize,
    ) -> Result<Reader<'a>, Error<'a>> {
        if bytes.len() != expected {
            return Err(Error::Length {
                expected,
                actual: bytes.len(),
            });
        }
        let mut reader = Reader::new(bytes);
        let envelope = reader.take(ENVELOPE_SIZE)?;
        let known = self.envelope(payload);
        // Report the exact rejected envelope component. All checks precede
        // payload decoding, including rejection of a future schema version.
        for (start, end, reason) in [
            (0, 8, "invalid proof magic"),
            (8, 10, "unsupported proof envelope version"),
            (10, 12, "proof payload kind mismatch"),
            (12, 14, "unsupported proof schema version"),
            (14, 16, "unsupported proof protocol version"),
            (16, 20, "proof rank mismatch"),
            (20, 28, "proof header size mismatch"),
            (28, 60, "proof suite mismatch"),
            (60, 92, "proof application mismatch"),
        ] {
            if envelope[start..end] != known[start..end] {
                return Err(Error::Invalid {
                    offset: start,
                    bytes: &envelope[start..end],
                    reason,
                });
            }
        }
        Ok(reader)
    }
}

/// A child header: exactly `HEADER_SIZE` field elements, the application's
/// declared size, which the envelope also records and checks.
pub(super) struct Header<const HEADER_SIZE: usize>;
impl<F: Field, const HEADER_SIZE: usize> Encode<Header<HEADER_SIZE>> for Vec<F> {
    fn encode(&self, output: &mut Vec<u8>) {
        debug_assert_eq!(self.len(), HEADER_SIZE, "child header length");
        for value in self {
            <F as Encode<Scalar>>::encode(value, output);
        }
    }
}
impl<F: Field, const HEADER_SIZE: usize> Decode<Header<HEADER_SIZE>> for Vec<F> {
    fn encoded_len() -> usize {
        HEADER_SIZE * <F as Decode<Scalar>>::encoded_len()
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        (0..HEADER_SIZE)
            .map(|_| <F as Decode<Scalar>>::decode(reader))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::{ProductionRank, TestRank};
    use ragu_core::pasta::{Fp, Pasta};

    use super::*;
    use crate::profile::{Shape, Standard};

    // Schema v1 is the standard profile's shape under `ragu-pcd-v1`. A
    // change to either moves the layout or the verifier semantics and needs
    // a new schema or protocol version, not a silent re-pin.
    #[test]
    fn schema_v1_pins_protocol_and_shape() {
        assert_eq!(crate::RAGU_TAG, b"ragu-pcd-v1");
        assert_eq!(crate::ipa::IPA_TAG, b"ragu-ipa-v1");
        assert_eq!(ragu_primitives::ENDOSCALAR_BITS, 143);
        assert_eq!(
            Shape::of::<Standard>(),
            Shape {
                native_rx: 45,
                nested_points: 105,
                nested_steps: 26,
                nested_rx: 39,
                native_points: 93,
                native_steps: 23,
            }
        );
    }

    #[test]
    fn encoded_length_is_a_function_of_profile_rank_and_header_size() {
        // Every polynomial of the shape but the two derived stages, with
        // `2^rank` coefficients each; a commitment per polynomial plus the
        // nested challenges partial; two headers; one scalar; one circuit
        // index. The envelope adds 92 bytes.
        fn payload<R: Rank, const H: usize>() -> usize {
            let polynomials = Shape::of::<Standard>().polynomials();
            (polynomials - 2) * R::num_coeffs() * 32 + (polynomials + 1) * 32 + 2 * H * 32 + 32 + 4
        }
        assert_eq!(
            MinimalProof::<Pasta, ProductionRank, 4>::encoded_len(),
            payload::<ProductionRank, 4>()
        );
        assert_eq!(
            MinimalProof::<Pasta, TestRank, 1>::encoded_len(),
            payload::<TestRank, 1>()
        );
        let format = ProofFormat::<Pasta, ProductionRank, 4> {
            context: ProofContext {
                suite: [0; 32],
                application: [0; 32],
            },
            marker: PhantomData,
        };
        assert_eq!(format.encoded_len(), 92 + payload::<ProductionRank, 4>());
        // 93 instance points; 27 instance scalars; per side 6+2R points,
        // 21 scalars; plus the circuit index and common envelope.
        assert_eq!(
            format.compressed_encoded_len(),
            92 + 4 + (93 + 27 + 2 * (6 + 2 * 13 + 21)) * 32
        );
    }

    #[test]
    fn header_codec_reads_exactly_the_declared_size() {
        let header = alloc::vec![Fp::ONE, Fp::from(2), Fp::from(3), Fp::from(4)];
        let bytes = <Vec<Fp> as Encode<Header<4>>>::to_bytes(&header);
        assert_eq!(bytes.len(), 1 + 4 * 32);
        assert_eq!(
            <Vec<Fp> as Decode<Header<4>>>::from_bytes(&bytes).unwrap(),
            header
        );
        let Error::Length { expected, actual } =
            <Vec<Fp> as Decode<Header<3>>>::from_bytes(&bytes).unwrap_err()
        else {
            panic!("expected a length error")
        };
        assert_eq!((expected, actual), (97, 129));
    }
}
