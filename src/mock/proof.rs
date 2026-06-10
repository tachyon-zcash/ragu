//! Mock PCD proof and proof-carrying data.
//!
//! ## Serialized layout
//!
//! | Offset      | Size | Content                                            |
//! |-------------|------|----------------------------------------------------|
//! | 0..8        | 8    | step_index (u64 LE, value-space partitioned)       |
//! | 8..40       | 32   | header hash                                        |
//! | 40..72      | 32   | witness hash                                       |
//! | 72..104     | 32   | binding hash                                       |
//! | 104..136    | 32   | rerandomization tag                                |
//! | 136..23000  | …    | zero padding                                       |

use alloc::{boxed::Box, vec};

use crate::{
    header::{Header, Suffix},
    step::Index,
};

/// Compressed proof size in bytes.
pub const PROOF_SIZE_COMPRESSED: usize = 23_000;

const STEP_INDEX_SIZE: usize = 8;
const HASH_SIZE: usize = 32;

/// Mocks `ragu_pcd::Proof`.
#[derive(Clone)]
pub struct Proof {
    pub(crate) step_index: Index,
    pub(crate) header_hash: [u8; HASH_SIZE],
    pub(crate) witness_hash: [u8; HASH_SIZE],
    pub(crate) binding: [u8; HASH_SIZE],
    pub(crate) rerand_tag: [u8; HASH_SIZE],
}

/// Mocks `ragu_pcd::Pcd`.
pub struct Pcd<H: Header> {
    pub(crate) proof: Proof,
    pub(crate) data: H::Data,
}

impl<H: Header> Pcd<H> {
    /// Returns a reference to the data that the proof accompanies.
    ///
    /// Mirrors `ragu_pcd::Pcd::data`.
    #[must_use]
    pub fn data(&self) -> &H::Data {
        &self.data
    }

    /// Returns a reference to the recursive proof.
    ///
    /// Mirrors `ragu_pcd::Pcd::proof`.
    #[must_use]
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// Consumes the proof-carrying data and returns the proof and data
    /// separately.
    ///
    /// Mirrors `ragu_pcd::Pcd::into_parts`.
    #[must_use]
    pub fn into_parts(self) -> (Proof, H::Data) {
        (self.proof, self.data)
    }
}

impl<H: Header> Clone for Pcd<H> {
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
    }
}

impl Proof {
    #[must_use]
    pub fn trivial() -> Self {
        Self::new(<() as Header>::SUFFIX, Index::internal(1), &[], &[])
    }

    #[must_use]
    pub(crate) fn new(
        suffix: Suffix,
        step_index: Index,
        encoded_header: &[u8],
        witness_data: &[u8],
    ) -> Self {
        let header_hash = compute_header_hash(suffix, encoded_header);
        let witness_hash = compute_witness_hash(witness_data);
        let binding = compute_binding(step_index, &header_hash, &witness_hash);
        Self {
            step_index,
            header_hash,
            witness_hash,
            binding,
            rerand_tag: [0u8; HASH_SIZE],
        }
    }

    /// Mirrors `ragu_pcd::Proof::carry`.
    #[must_use]
    pub fn carry<H: Header>(self, data: H::Data) -> Pcd<H> {
        Pcd { proof: self, data }
    }

    /// Serialize into the full compressed proof buffer.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "buffer is sized to PROOF_SIZE_COMPRESSED by construction"
    )]
    pub fn serialize(&self) -> Box<[u8; PROOF_SIZE_COMPRESSED]> {
        let mut bytes = vec::Vec::with_capacity(PROOF_SIZE_COMPRESSED);
        bytes.extend_from_slice(&self.step_index.get().to_le_bytes());
        bytes.extend_from_slice(&self.header_hash);
        bytes.extend_from_slice(&self.witness_hash);
        bytes.extend_from_slice(&self.binding);
        bytes.extend_from_slice(&self.rerand_tag);
        bytes.resize(PROOF_SIZE_COMPRESSED, 0);
        bytes
            .into_boxed_slice()
            .try_into()
            .expect("buffer sized to PROOF_SIZE_COMPRESSED")
    }

    #[must_use]
    pub(crate) fn rerandomize(&self) -> Self {
        let serialized = self.serialize();
        Self {
            step_index: self.step_index,
            header_hash: self.header_hash,
            witness_hash: self.witness_hash,
            binding: self.binding,
            rerand_tag: compute_rerand_tag(serialized.as_ref()),
        }
    }
}

impl From<Proof> for [u8; PROOF_SIZE_COMPRESSED] {
    fn from(proof: Proof) -> [u8; PROOF_SIZE_COMPRESSED] {
        *proof.serialize()
    }
}

impl TryFrom<&[u8; PROOF_SIZE_COMPRESSED]> for Proof {
    type Error = crate::error::Error;

    fn try_from(bytes: &[u8; PROOF_SIZE_COMPRESSED]) -> Result<Self, Self::Error> {
        let slice: &[u8] = bytes.as_slice();
        let (step_index_bytes, rest) = slice
            .split_first_chunk::<STEP_INDEX_SIZE>()
            .ok_or(crate::error::Error("step_index slot missing"))?;
        let (header_hash, rest) = rest
            .split_first_chunk::<HASH_SIZE>()
            .ok_or(crate::error::Error("header_hash slot missing"))?;
        let (witness_hash, rest) = rest
            .split_first_chunk::<HASH_SIZE>()
            .ok_or(crate::error::Error("witness_hash slot missing"))?;
        let (binding, rest) = rest
            .split_first_chunk::<HASH_SIZE>()
            .ok_or(crate::error::Error("binding slot missing"))?;
        let (rerand_tag, _padding) = rest
            .split_first_chunk::<HASH_SIZE>()
            .ok_or(crate::error::Error("rerand_tag slot missing"))?;

        let step_index_value = u64::from_le_bytes(*step_index_bytes);
        let step_index = Index::from_value(step_index_value)?;

        let expected_binding = compute_binding(step_index, header_hash, witness_hash);
        if expected_binding != *binding {
            return Err(crate::error::Error("mock_ragu internal binding mismatch"));
        }

        Ok(Self {
            step_index,
            header_hash: *header_hash,
            witness_hash: *witness_hash,
            binding: *binding,
            rerand_tag: *rerand_tag,
        })
    }
}

pub(crate) fn compute_header_hash(suffix: Suffix, encoded: &[u8]) -> [u8; HASH_SIZE] {
    let hash = blake2b_simd::Params::new()
        .hash_length(HASH_SIZE)
        .personal(b"MkRagu_HdrHash_\0")
        .to_state()
        .update(&suffix.get().to_le_bytes())
        .update(encoded)
        .finalize();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub(crate) fn compute_witness_hash(witness_bytes: &[u8]) -> [u8; HASH_SIZE] {
    let hash = blake2b_simd::Params::new()
        .hash_length(HASH_SIZE)
        .personal(b"MkRagu_Witness_\0")
        .hash(witness_bytes);
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub(crate) fn compute_binding(
    step_index: Index,
    header_hash: &[u8; HASH_SIZE],
    witness_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let hash = blake2b_simd::Params::new()
        .hash_length(HASH_SIZE)
        .personal(b"MkRagu_Binding_\0")
        .to_state()
        .update(&step_index.get().to_le_bytes())
        .update(header_hash)
        .update(witness_hash)
        .finalize();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub(crate) fn compute_rerand_tag(proof_bytes: &[u8]) -> [u8; HASH_SIZE] {
    let hash = blake2b_simd::Params::new()
        .hash_length(HASH_SIZE)
        .personal(b"MkRagu_Rerand_\0\0")
        .hash(proof_bytes);
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(hash.as_bytes());
    out
}
