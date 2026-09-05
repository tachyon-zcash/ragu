use alloc::{boxed::Box, vec, vec::Vec};

use ragu_arithmetic::{CurveAffine as _, CurveExt, ff::PrimeField as _};
use ragu_core::{Error, Result};
use ragu_pasta::{Ep, Eq, Fp, Fq};

use super::{
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
    /// Mirrors `ragu_pcd`'s bootstrap proof: the output of the internal
    /// bootstrap step, carrying the unit header.
    ///
    /// Public so that downstream consumers integrating against the mock can
    /// still obtain a starting proof directly, as they could from the former
    /// `Proof::trivial`.
    #[must_use]
    pub fn bootstrap() -> Self {
        Self::new(
            <() as Header>::SUFFIX,
            Index::internal(1),
            &(Vec::new(), Vec::new(), Vec::new(), Vec::new()),
            &[],
        )
        .expect("empty header cannot fail to hash")
    }

    pub(crate) fn new(
        suffix: Suffix,
        step_index: Index,
        encoded_header: &(Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>),
        witness_data: &[u8],
    ) -> Result<Self> {
        let header_hash = compute_header_hash(suffix, encoded_header)?;
        let witness_hash = compute_witness_hash(witness_data);
        let binding = compute_binding(step_index, &header_hash, &witness_hash);
        Ok(Self {
            step_index,
            header_hash,
            witness_hash,
            binding,
            rerand_tag: [0u8; HASH_SIZE],
        })
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
    type Error = ragu_core::Error;

    fn try_from(bytes: &[u8; PROOF_SIZE_COMPRESSED]) -> Result<Self> {
        let slice: &[u8] = bytes.as_slice();
        let (step_index_bytes, rest) = slice
            .split_first_chunk::<STEP_INDEX_SIZE>()
            .ok_or_else(|| Error::MalformedEncoding("step_index slot missing".into()))?;
        let (header_hash, rest) = rest
            .split_first_chunk::<HASH_SIZE>()
            .ok_or_else(|| Error::MalformedEncoding("header_hash slot missing".into()))?;
        let (witness_hash, rest) = rest
            .split_first_chunk::<HASH_SIZE>()
            .ok_or_else(|| Error::MalformedEncoding("witness_hash slot missing".into()))?;
        let (binding, rest) = rest
            .split_first_chunk::<HASH_SIZE>()
            .ok_or_else(|| Error::MalformedEncoding("binding slot missing".into()))?;
        let (rerand_tag, _padding) = rest
            .split_first_chunk::<HASH_SIZE>()
            .ok_or_else(|| Error::MalformedEncoding("rerand_tag slot missing".into()))?;

        let step_index_value = u64::from_le_bytes(*step_index_bytes);
        let step_index = Index::from_value(step_index_value)?;

        let expected_binding = compute_binding(step_index, header_hash, witness_hash);
        if expected_binding != *binding {
            return Err(Error::MalformedEncoding(
                "mock_ragu internal binding mismatch".into(),
            ));
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

pub(crate) fn compute_header_hash(
    suffix: Suffix,
    encoded: &(Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>),
) -> Result<[u8; HASH_SIZE]> {
    let (fps, fqs, eps, eqs) = encoded;
    let mut state = blake2b_simd::Params::new()
        .hash_length(HASH_SIZE)
        .personal(b"MkRagu_HdrHash_\0")
        .to_state();

    {
        state.update(b"Suffix");
        state.update(&suffix.get().to_le_bytes());
    }

    {
        state.update(b"Fp");
        state.update(&(fps.len() as u64).to_le_bytes());
        for element in fps {
            state.update(element.to_repr().as_ref());
        }
    }

    {
        state.update(b"Fq");
        state.update(&(fqs.len() as u64).to_le_bytes());
        for element in fqs {
            state.update(element.to_repr().as_ref());
        }
    }

    absorb_points(&mut state, b"Ep", eps)?;
    absorb_points(&mut state, b"Eq", eqs)?;

    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(state.finalize().as_bytes());
    Ok(out)
}

/// Absorbs `points` as affine coordinate pairs, rejecting the identity — which
/// has no coordinates, and which real ragu's in-circuit `encode` could not
/// witness either.
fn absorb_points<G: CurveExt>(
    state: &mut blake2b_simd::State,
    tag: &[u8],
    points: &[G],
) -> Result<()> {
    state.update(tag);
    state.update(&(points.len() as u64).to_le_bytes());
    for point in points {
        let affine = point.to_affine();
        let coordinates = affine
            .coordinates()
            .into_option()
            .ok_or_else(|| Error::InvalidWitness("point at infinity cannot be witnessed".into()))?;
        state.update(coordinates.x().to_repr().as_ref());
        state.update(coordinates.y().to_repr().as_ref());
    }
    Ok(())
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
