use alloc::{boxed::Box, vec, vec::Vec};
use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;
use ragu_core::{Cycle, Error, Result, maybe::Maybe as _};
use ragu_primitives::{GadgetExt as _, Simulator};
use udon::{curve::Affine, field::Field};

use super::{
    header::{HEADER_POLYNOMIALS, Header},
    step::{Encoded, HeaderInput, Index},
};

/// Compressed proof size in bytes.
pub const PROOF_SIZE_COMPRESSED: usize = 23_000;

const STEP_INDEX_SIZE: usize = 8;
const HASH_SIZE: usize = 32;

/// Mocks `ragu_pcd::Proof`.
#[derive(Clone, Debug)]
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) step_index: Index,
    pub(crate) header_hash: [u8; HASH_SIZE],
    pub(crate) witness_hash: [u8; HASH_SIZE],
    pub(crate) binding: [u8; HASH_SIZE],
    pub(crate) rerand_tag: [u8; HASH_SIZE],
    pub(crate) commitments: [C::HostCurve; HEADER_POLYNOMIALS],
    pub(crate) polynomials: [Vec<C::CircuitField>; HEADER_POLYNOMIALS],
    _rank: PhantomData<R>,
}

/// Mocks `ragu_pcd::Pcd`.
pub struct Pcd<C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    pub(crate) proof: Proof<C, R>,
    pub(crate) data: H::Data,
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Pcd<C, R, H> {
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
    pub fn proof(&self) -> &Proof<C, R> {
        &self.proof
    }

    /// Consumes the proof-carrying data and returns the proof and data
    /// separately.
    ///
    /// Mirrors `ragu_pcd::Pcd::into_parts`.
    #[must_use]
    pub fn into_parts(self) -> (Proof<C, R>, H::Data) {
        (self.proof, self.data)
    }

    pub(crate) fn input(&self) -> HeaderInput<'_, C::CircuitField, H> {
        HeaderInput {
            data: &self.data,
            polynomials: &self.proof.polynomials,
        }
    }

    #[must_use]
    pub fn polynomials(&self) -> [Vec<C::CircuitField>; HEADER_POLYNOMIALS] {
        self.proof.polynomials.clone()
    }

    #[must_use]
    pub fn commitments(&self) -> [C::HostCurve; HEADER_POLYNOMIALS] {
        self.proof.commitments
    }
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Clone for Pcd<C, R, H> {
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    pub(crate) fn reusable_len() -> usize {
        PROOF_SIZE_COMPRESSED
            + HEADER_POLYNOMIALS * R::num_coeffs() * C::CircuitField::ZERO.to_bytes().as_ref().len()
    }

    pub(crate) fn to_reusable_bytes(&self) -> Result<Vec<u8>> {
        if self.polynomials.iter().any(Vec::is_empty)
            || self.polynomials.iter().any(|p| p.len() > R::num_coeffs())
            || self.commitments.iter().any(|p| p.is_identity())
        {
            return Err(Error::MalformedEncoding(
                "proof has no reusable polynomial representation".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(Self::reusable_len());
        bytes.extend_from_slice(self.serialize().as_ref());
        for coefficients in &self.polynomials {
            for coefficient in coefficients.iter().copied().chain(core::iter::repeat_n(
                C::CircuitField::ZERO,
                R::num_coeffs() - coefficients.len(),
            )) {
                bytes.extend_from_slice(coefficient.to_bytes().as_ref());
            }
        }
        Ok(bytes)
    }

    pub(crate) fn from_reusable_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::reusable_len() {
            return Err(Error::MalformedEncoding(
                "invalid reusable mock proof length".into(),
            ));
        }
        let (prefix, coefficients) = bytes.split_at(PROOF_SIZE_COMPRESSED);
        let prefix: &[u8; PROOF_SIZE_COMPRESSED] = prefix.try_into().expect("fixed proof prefix");
        let mut proof = Self::try_from(prefix)?;
        let mut repr = C::CircuitField::ZERO.to_bytes();
        for (polynomial, bytes) in proof
            .polynomials
            .iter_mut()
            .zip(coefficients.chunks_exact(R::num_coeffs() * repr.as_ref().len()))
        {
            for bytes in bytes.chunks_exact(repr.as_ref().len()) {
                repr.as_mut().copy_from_slice(bytes);
                polynomial.push(C::CircuitField::from_bytes(repr).ok_or_else(|| {
                    Error::MalformedEncoding("noncanonical polynomial coefficient".into())
                })?);
            }
            while polynomial.last() == Some(&C::CircuitField::ZERO) {
                polynomial.pop();
            }
            if polynomial.is_empty() {
                return Err(Error::MalformedEncoding(
                    "an online polynomial must not be zero".into(),
                ));
            }
            polynomial.shrink_to_fit();
        }
        Ok(proof)
    }

    pub(crate) fn new<H: Header<C::CircuitField>, const HEADER_SIZE: usize>(
        step_index: Index,
        dr: &mut Simulator<C::CircuitField>,
        encoded_header: &Encoded<'_, Simulator<C::CircuitField>, H, HEADER_SIZE>,
        witness_data: &[u8],
        polynomials: [Vec<C::CircuitField>; HEADER_POLYNOMIALS],
        commitments: [C::HostCurve; HEADER_POLYNOMIALS],
    ) -> Result<Self> {
        let header_hash = compute_header_hash(dr, encoded_header)?;
        let witness_hash = compute_witness_hash(witness_data);
        let binding = compute_binding(step_index, &header_hash, &witness_hash, &commitments);
        Ok(Self {
            step_index,
            header_hash,
            witness_hash,
            binding,
            rerand_tag: [0u8; HASH_SIZE],
            commitments,
            polynomials,
            _rank: PhantomData,
        })
    }

    /// Mirrors `ragu_pcd::Proof::carry`.
    #[must_use]
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> Pcd<C, R, H> {
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
        for point in &self.commitments {
            bytes.extend_from_slice(point.to_bytes().as_ref());
        }
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
            commitments: self.commitments,
            polynomials: self.polynomials.clone(),
            _rank: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> From<Proof<C, R>> for [u8; PROOF_SIZE_COMPRESSED] {
    fn from(proof: Proof<C, R>) -> [u8; PROOF_SIZE_COMPRESSED] {
        *proof.serialize()
    }
}

impl<C: Cycle, R: Rank> TryFrom<&[u8; PROOF_SIZE_COMPRESSED]> for Proof<C, R> {
    type Error = ragu_core::Error;

    fn try_from(bytes: &[u8; PROOF_SIZE_COMPRESSED]) -> Result<Self> {
        let slice: &[u8] = bytes.as_slice();
        let (step_index_bytes, rest) = slice
            .split_first_chunk::<STEP_INDEX_SIZE>()
            .ok_or_else(|| Error::MalformedEncoding("step_index slot missing".into()))?;
        let (header_hash, rest) = rest
            .split_first_chunk::<HASH_SIZE>()
            .ok_or_else(|| Error::MalformedEncoding("header_hash slot missing".into()))?;
        let mut repr = C::HostCurve::identity().to_bytes();
        let (points, rest) = rest.split_at(HEADER_POLYNOMIALS * repr.as_ref().len());
        let mut commitments = [C::HostCurve::identity(); HEADER_POLYNOMIALS];
        for (point, bytes) in commitments
            .iter_mut()
            .zip(points.chunks_exact(repr.as_ref().len()))
        {
            repr.as_mut().copy_from_slice(bytes);
            *point = C::HostCurve::from_bytes(repr)
                .ok_or_else(|| Error::MalformedEncoding("invalid mock commitment".into()))?;
            if point.is_identity() {
                return Err(Error::MalformedEncoding("identity mock commitment".into()));
            }
        }
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

        let expected_binding = compute_binding(step_index, header_hash, witness_hash, &commitments);
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
            commitments,
            polynomials: core::array::from_fn(|_| Vec::new()),
            _rank: PhantomData,
        })
    }
}

pub(crate) fn compute_header_hash<F: Field, H: Header<F>, const HEADER_SIZE: usize>(
    dr: &mut Simulator<F>,
    header: &Encoded<'_, Simulator<F>, H, HEADER_SIZE>,
) -> Result<[u8; HASH_SIZE]> {
    let mut elements = Vec::new();
    header.as_gadget().write(dr, &mut elements)?;
    if elements.len() >= HEADER_SIZE {
        return Err(Error::MalformedEncoding(
            "header encoding exceeds HEADER_SIZE - 1".into(),
        ));
    }
    let mut fps: Vec<F> = elements.iter().map(|e| *e.value().take()).collect();
    fps.resize(HEADER_SIZE - 1, F::ZERO);
    fps.push(F::from(H::SUFFIX.get()));

    let mut state = blake2b_simd::Params::new()
        .hash_length(HASH_SIZE)
        .personal(b"MkRagu_HdrHash_\0")
        .to_state();

    {
        state.update(b"Suffix");
        state.update(&H::SUFFIX.get().to_le_bytes());
    }

    {
        state.update(b"Fp");
        state.update(&(fps.len() as u64).to_le_bytes());
        for element in fps {
            state.update(element.to_bytes().as_ref());
        }
    }

    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(state.finalize().as_bytes());
    Ok(out)
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

pub(crate) fn compute_binding<A: Affine>(
    step_index: Index,
    header_hash: &[u8; HASH_SIZE],
    witness_hash: &[u8; HASH_SIZE],
    commitments: &[A; HEADER_POLYNOMIALS],
) -> [u8; HASH_SIZE] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(HASH_SIZE)
        .personal(b"MkRagu_Binding_\0")
        .to_state();
    state
        .update(&step_index.get().to_le_bytes())
        .update(header_hash)
        .update(witness_hash);
    for point in commitments {
        state.update(point.to_bytes().as_ref());
    }
    let hash = state.finalize();
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
