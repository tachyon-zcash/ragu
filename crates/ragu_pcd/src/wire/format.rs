//! Versioned application envelope over fixed-length proofs and compressed proofs.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;

use crate::{
    Application, CompressedProof, Proof, SelectableBackend,
    profile::{Profile, ProfiledCycle},
    wire::{Decode, Dimensions, Encode, Error, Reader},
};

const MAGIC: &[u8; 8] = b"RAGUPCD\0";
const ENVELOPE_VERSION: u16 = 2;
/// Each proof representation has its own payload kind and schema version.
#[derive(Clone, Copy)]
enum PayloadKind {
    Proof,
    Compressed,
}

impl PayloadKind {
    fn tag(self) -> u16 {
        match self {
            Self::Proof => 1,
            Self::Compressed => 2,
        }
    }

    fn schema_version(self) -> u16 {
        match self {
            Self::Proof => PROOF_SCHEMA_VERSION,
            Self::Compressed => COMPRESSED_SCHEMA_VERSION,
        }
    }
}
const PROOF_SCHEMA_VERSION: u16 = 1;
const COMPRESSED_SCHEMA_VERSION: u16 = 1;
// Matches the verification semantics identified by RAGU_TAG and IPA_TAG.
const PROTOCOL_VERSION: u16 = 1;
const ENVELOPE_SIZE: usize = 124;

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
/// Construct with [`Application::proof_format`]. Proof encodings have exactly
/// [`encoded_len`](Self::encoded_len) bytes; compressed encodings have exactly
/// [`compressed_encoded_len`](Self::compressed_encoded_len) bytes. Decoding checks
/// the exact length, then the envelope, then the payload representation.
///
/// Decoding does not verify a proof. A decoded [`Proof`] carries only the
/// fields its encoding retains; the application derives the rest when one of
/// its methods first takes it. Compress it with [`Application::compress`] and
/// accept it on [`Application::verify_compressed`] before using it in another
/// proof. A decoded compressed proof can be verified directly after attaching
/// its accompanying header data. See the crate's `WIRE_FORMAT.md` for the
/// version and compatibility contract.
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
    /// The rank and header size the envelope records, which fix the payload's
    /// layout.
    fn dims() -> Dimensions {
        Dimensions::of::<R, HEADER_SIZE>()
    }

    /// Stable profile tag derived from the receiving profile's canonical name.
    ///
    /// BLAKE2b-256 hashes the UTF-8 bytes of [`Profile::NAME`] with
    /// personalization `ragu-profile-v1`. Names must be stable and unique as
    /// required by `Profile`; this tag does not replace the complete setup ID.
    pub fn profile_tag(&self) -> [u8; 32] {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ragu-profile-v1")
            .hash(C::Profile::NAME.as_bytes());
        hash.as_bytes().try_into().expect("32-byte profile tag")
    }

    fn write_envelope(&self, payload: PayloadKind, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(MAGIC);
        ENVELOPE_VERSION.encode(bytes);
        payload.tag().encode(bytes);
        payload.schema_version().encode(bytes);
        PROTOCOL_VERSION.encode(bytes);
        R::RANK.encode(bytes);
        (HEADER_SIZE as u64).encode(bytes);
        bytes.extend_from_slice(&self.profile_tag());
        bytes.extend_from_slice(&self.context.suite);
        bytes.extend_from_slice(&self.context.application);
    }

    /// Exact byte length of a proof, including the envelope.
    ///
    /// Bound transport input to this size before buffering a proof.
    pub fn encoded_len(&self) -> usize {
        ENVELOPE_SIZE + <Proof<C, R> as Decode>::encoded_len(Self::dims())
    }

    /// Exact byte length of a compressed proof, including the shared envelope.
    pub fn compressed_encoded_len(&self) -> usize {
        ENVELOPE_SIZE + <CompressedProof<C> as Decode>::encoded_len(Self::dims())
    }

    /// Encodes a compressed proof of this application's shape. This does not
    /// verify the proof. Payload kind 2 distinguishes it from an uncompressed
    /// proof.
    pub fn encode_compressed(&self, proof: &CompressedProof<C>) -> Result<Vec<u8>, Error<'static>> {
        if !proof.well_formed::<R, HEADER_SIZE>() {
            return Err(Error::Invalid {
                offset: 0,
                bytes: &[],
                reason: "invalid compressed proof structure",
            });
        }
        let mut bytes = Vec::with_capacity(self.compressed_encoded_len());
        self.write_envelope(PayloadKind::Compressed, &mut bytes);
        <CompressedProof<C> as Encode>::encode(proof, &mut bytes);
        Ok(bytes)
    }

    /// Decodes a compressed proof after checking its exact length and context.
    /// Attach the accompanying header data with `carry` and use
    /// [`Application::verify_compressed`] before accepting it.
    pub fn decode_compressed<'a>(&self, bytes: &'a [u8]) -> Result<CompressedProof<C>, Error<'a>> {
        let mut reader = self.open(
            bytes,
            PayloadKind::Compressed,
            self.compressed_encoded_len(),
        )?;
        <CompressedProof<C> as Decode>::decode(&mut reader, Self::dims())
    }

    /// Encodes a structurally valid proof, including its version and context.
    /// Does not establish cryptographic validity. Only the fields the
    /// encoding retains are written; see [`ProofFormat::decode`].
    pub fn encode(&self, proof: &Proof<C, R>) -> Result<Vec<u8>, Error<'static>> {
        if !proof.well_formed::<HEADER_SIZE>() {
            return Err(Error::Invalid {
                offset: 0,
                bytes: &[],
                reason: "invalid proof structure",
            });
        }
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.write_envelope(PayloadKind::Proof, &mut bytes);
        proof.encode(&mut bytes);
        Ok(bytes)
    }

    /// Decodes exactly one encoding, rejecting other lengths, unknown versions,
    /// mismatched context and malformed representation, in that order.
    ///
    /// The decoded proof holds the retained fields alone. The application
    /// derives the others, never reading them from the input, when one of its
    /// methods first takes the proof.
    pub fn decode<'a>(&self, bytes: &'a [u8]) -> Result<Proof<C, R>, Error<'a>> {
        let mut reader = self.open(bytes, PayloadKind::Proof, self.encoded_len())?;
        Proof::decode(&mut reader, Self::dims())
    }

    /// Checks the length and the envelope of one encoding of `payload`,
    /// leaving the reader at the payload.
    fn open<'a>(
        &self,
        bytes: &'a [u8],
        payload: PayloadKind,
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
        let mut known = Vec::with_capacity(ENVELOPE_SIZE);
        self.write_envelope(payload, &mut known);
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
            (28, 60, "proof profile mismatch"),
            (60, 92, "proof suite mismatch"),
            (92, 124, "proof application mismatch"),
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

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::{ProductionRank, TestRank};
    use ragu_core::pasta::{Fp, Pasta};
    use udon::field::Field;

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
        // index. The envelope adds 124 bytes.
        fn payload<R: Rank, const H: usize>() -> usize {
            let polynomials = Shape::of::<Standard>().polynomials();
            (polynomials - 2) * R::num_coeffs() * 32 + (polynomials + 1) * 32 + 2 * H * 32 + 32 + 4
        }
        assert_eq!(
            <Proof<Pasta, ProductionRank> as Decode>::encoded_len(Dimensions::of::<
                ProductionRank,
                4,
            >()),
            payload::<ProductionRank, 4>()
        );
        assert_eq!(
            <Proof<Pasta, TestRank> as Decode>::encoded_len(Dimensions::of::<TestRank, 1>()),
            payload::<TestRank, 1>()
        );
        let format = ProofFormat::<Pasta, ProductionRank, 4> {
            context: ProofContext {
                suite: [0; 32],
                application: [0; 32],
            },
            marker: PhantomData,
        };
        assert_eq!(format.encoded_len(), 124 + payload::<ProductionRank, 4>());
        // 93 instance points; 27 instance scalars; per side 6+2R points,
        // 21 scalars; plus the circuit index and common envelope.
        assert_eq!(
            format.compressed_encoded_len(),
            124 + 4 + (93 + 27 + 2 * (6 + 2 * 13 + 21)) * 32
        );
    }

    #[test]
    fn profile_tag_rejects_same_shape_with_identical_context() {
        use crate::profile::{Aggregator, Profiled};
        let context = ProofContext {
            suite: [1; 32],
            application: [2; 32],
        };
        let standard = ProofFormat::<Pasta, TestRank, 4> {
            context,
            marker: PhantomData,
        };
        let aggregator = ProofFormat::<Profiled<Pasta, Aggregator>, TestRank, 4> {
            context,
            marker: PhantomData,
        };
        assert_eq!(
            standard.profile_tag(),
            [
                0x82, 0xcf, 0xab, 0x66, 0x41, 0x72, 0x3d, 0x59, 0x14, 0x59, 0x7a, 0xbc, 0x3f, 0x2f,
                0xea, 0xcd, 0x8c, 0xe0, 0x62, 0x57, 0x46, 0x73, 0xab, 0x7e, 0xc8, 0x7f, 0xab, 0x3a,
                0x24, 0x2f, 0xfd, 0x12
            ]
        );
        assert_ne!(standard.profile_tag(), aggregator.profile_tag());
        for (kind, length, other_length) in [
            (
                PayloadKind::Proof,
                standard.encoded_len(),
                aggregator.encoded_len(),
            ),
            (
                PayloadKind::Compressed,
                standard.compressed_encoded_len(),
                aggregator.compressed_encoded_len(),
            ),
        ] {
            assert_eq!(length, other_length, "test requires equal profile shapes");
            let mut bytes = Vec::with_capacity(length);
            standard.write_envelope(kind, &mut bytes);
            bytes.resize(length, 0);
            assert!(matches!(
                aggregator.open(&bytes, kind, other_length),
                Err(Error::Invalid {
                    offset: 28,
                    reason: "proof profile mismatch",
                    ..
                })
            ));
            // A v1 envelope cannot be reinterpreted as the new layout, even
            // when padded to the receiving type's expected length.
            bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
            assert!(matches!(
                standard.open(&bytes, kind, length),
                Err(Error::Invalid {
                    offset: 8,
                    reason: "unsupported proof envelope version",
                    ..
                })
            ));
        }
    }

    #[test]
    fn header_codec_reads_exactly_the_declared_size() {
        use crate::wire::{HeaderSize, Scalar, SizedSequence};
        type Headers = SizedSequence<Scalar, HeaderSize>;
        let dims = |header_size| Dimensions {
            rank: 0,
            header_size,
        };
        let header = alloc::vec![Fp::ONE, Fp::from(2), Fp::from(3), Fp::from(4)];
        let bytes = <Vec<Fp> as Encode<Headers>>::to_bytes(&header);
        assert_eq!(bytes.len(), 1 + 4 * 32);
        assert_eq!(
            <Vec<Fp> as Decode<Headers>>::from_bytes(&bytes, dims(4)).unwrap(),
            header
        );
        let Error::Length { expected, actual } =
            <Vec<Fp> as Decode<Headers>>::from_bytes(&bytes, dims(3)).unwrap_err()
        else {
            panic!("expected a length error")
        };
        assert_eq!((expected, actual), (97, 129));
    }
}
