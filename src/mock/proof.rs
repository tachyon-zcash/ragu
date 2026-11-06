use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;
use ragu_core::{Cycle, Error, FixedGenerators, PoseidonPermutation, Result, maybe::Maybe as _};
use ragu_primitives::{GadgetExt as _, Simulator};
use udon::{curve::Affine, field::Field};

use super::{
    header::{HEADER_POLYNOMIALS, Header},
    step::{Encoded, HeaderInput, Index},
    wire::{self, Reader},
};

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
    pub(crate) header_size: usize,
    pub(crate) setup_hash: [u8; HASH_SIZE],
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
    pub fn encoded_len<const HEADER_SIZE: usize>() -> usize {
        CompressedProof::<C>::encoded_len::<R, HEADER_SIZE>()
            + HEADER_POLYNOMIALS * R::num_coeffs() * C::CircuitField::ZERO.to_bytes().as_ref().len()
    }

    pub fn to_bytes(&self) -> core::result::Result<Vec<u8>, wire::Error<'static>> {
        if self
            .polynomials
            .iter()
            .any(|p| p.is_empty() || p.len() > R::num_coeffs())
        {
            return Err(wire::Error::Unencodable);
        }
        let mut bytes = self.compressed().encode(wire::PayloadKind::Proof)?;
        bytes.reserve(Self::encoded_len::<0>() - bytes.len());
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

    pub fn from_bytes(bytes: &[u8]) -> core::result::Result<Self, wire::Error<'_>> {
        let (mut reader, rank, header_size) =
            wire::open(bytes, wire::PayloadKind::Proof, Some(R::RANK))?;
        if bytes.len() != Self::encoded_len::<0>() {
            return Err(wire::Error::Length {
                expected: Self::encoded_len::<0>(),
                actual: bytes.len(),
            });
        }
        let metadata_size = CompressedProof::<C>::encoded_len::<R, 0>();
        let metadata = CompressedProof::<C>::read(&mut reader, rank, header_size)?;
        let coefficients = &bytes[metadata_size..];
        let mut proof = Self {
            step_index: metadata.step_index,
            header_hash: metadata.header_hash,
            witness_hash: metadata.witness_hash,
            binding: metadata.binding,
            rerand_tag: metadata.rerand_tag,
            commitments: metadata.commitments,
            header_size: metadata.header_size,
            setup_hash: metadata.setup_hash,
            polynomials: core::array::from_fn(|_| Vec::new()),
            _rank: PhantomData,
        };
        let mut repr = C::CircuitField::ZERO.to_bytes();
        let mut offset = metadata_size;
        for (polynomial, bytes) in proof
            .polynomials
            .iter_mut()
            .zip(coefficients.chunks_exact(R::num_coeffs() * repr.as_ref().len()))
        {
            for bytes in bytes.chunks_exact(repr.as_ref().len()) {
                repr.as_mut().copy_from_slice(bytes);
                polynomial.push(
                    C::CircuitField::from_bytes(repr).ok_or(wire::Error::Invalid {
                        offset,
                        bytes,
                        reason: "noncanonical polynomial coefficient",
                    })?,
                );
                offset += repr.as_ref().len();
            }
            while polynomial.last() == Some(&C::CircuitField::ZERO) {
                polynomial.pop();
            }
            if polynomial.is_empty() {
                return Err(wire::Error::Invalid {
                    offset,
                    bytes,
                    reason: "an online polynomial must not be zero",
                });
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
        setup_hash: [u8; HASH_SIZE],
    ) -> Result<Self> {
        let header_hash = compute_header_hash(dr, encoded_header)?;
        let witness_hash = compute_witness_hash(witness_data);
        let binding = compute_binding(
            step_index,
            &header_hash,
            &witness_hash,
            &commitments,
            &setup_hash,
            R::RANK,
            HEADER_SIZE,
        );
        Ok(Self {
            step_index,
            header_hash,
            witness_hash,
            binding,
            rerand_tag: [0u8; HASH_SIZE],
            commitments,
            polynomials,
            header_size: HEADER_SIZE,
            setup_hash,
            _rank: PhantomData,
        })
    }

    /// Mirrors `ragu_pcd::Proof::carry`.
    #[must_use]
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> Pcd<C, R, H> {
        Pcd { proof: self, data }
    }

    pub(crate) fn compressed(&self) -> CompressedProof<C> {
        CompressedProof {
            step_index: self.step_index,
            header_hash: self.header_hash,
            witness_hash: self.witness_hash,
            binding: self.binding,
            rerand_tag: self.rerand_tag,
            commitments: self.commitments,
            rank: R::RANK,
            header_size: self.header_size,
            setup_hash: self.setup_hash,
        }
    }

    #[must_use]
    pub(crate) fn rerandomize(&self) -> Self {
        let serialized = self.hash_input();
        Self {
            step_index: self.step_index,
            header_hash: self.header_hash,
            witness_hash: self.witness_hash,
            binding: self.binding,
            rerand_tag: compute_rerand_tag(serialized.as_ref()),
            commitments: self.commitments,
            polynomials: self.polynomials.clone(),
            header_size: self.header_size,
            setup_hash: self.setup_hash,
            _rank: PhantomData,
        }
    }

    pub(crate) fn hash_input(&self) -> [u8; 2 * HASH_SIZE] {
        let mut bytes = [0; 2 * HASH_SIZE];
        bytes[..HASH_SIZE].copy_from_slice(&self.binding);
        bytes[HASH_SIZE..].copy_from_slice(&self.rerand_tag);
        bytes
    }
}

#[derive(Clone, Debug)]
pub struct CompressedProof<C: Cycle> {
    pub(crate) step_index: Index,
    pub(crate) header_hash: [u8; HASH_SIZE],
    pub(crate) witness_hash: [u8; HASH_SIZE],
    pub(crate) binding: [u8; HASH_SIZE],
    pub(crate) rerand_tag: [u8; HASH_SIZE],
    pub(crate) commitments: [C::HostCurve; HEADER_POLYNOMIALS],
    pub(crate) rank: u32,
    pub(crate) header_size: usize,
    pub(crate) setup_hash: [u8; HASH_SIZE],
}

impl<C: Cycle> CompressedProof<C> {
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> CompressedPcd<C, H> {
        CompressedPcd { proof: self, data }
    }

    pub fn encoded_len<R: Rank, const HEADER_SIZE: usize>() -> usize {
        let _ = (R::RANK, HEADER_SIZE);
        wire::ENVELOPE_SIZE
            + STEP_INDEX_SIZE
            + 5 * HASH_SIZE
            + HEADER_POLYNOMIALS * C::HostCurve::identity().to_bytes().as_ref().len()
    }

    pub fn to_bytes(&self) -> core::result::Result<Vec<u8>, wire::Error<'static>> {
        self.encode(wire::PayloadKind::Compressed)
    }

    fn encode(
        &self,
        kind: wire::PayloadKind,
    ) -> core::result::Result<Vec<u8>, wire::Error<'static>> {
        if self.rank > wire::MAX_RANK
            || self.header_size > wire::MAX_HEADER_SIZE
            || self.commitments.iter().any(|point| point.is_identity())
        {
            return Err(wire::Error::Unencodable);
        }
        let mut bytes = Vec::with_capacity(Self::encoded_len::<
            ragu_circuits::polynomials::ProductionRank,
            0,
        >());
        wire::write_envelope(kind, self.rank, self.header_size, &mut bytes);
        bytes.extend_from_slice(&self.step_index.get().to_le_bytes());
        bytes.extend_from_slice(&self.header_hash);
        for point in &self.commitments {
            bytes.extend_from_slice(point.to_bytes().as_ref());
        }
        bytes.extend_from_slice(&self.witness_hash);
        bytes.extend_from_slice(&self.binding);
        bytes.extend_from_slice(&self.rerand_tag);
        bytes.extend_from_slice(&self.setup_hash);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> core::result::Result<Self, wire::Error<'_>> {
        let (mut reader, rank, header_size) =
            wire::open(bytes, wire::PayloadKind::Compressed, None)?;
        let expected = Self::encoded_len::<ragu_circuits::polynomials::ProductionRank, 0>();
        if bytes.len() != expected {
            return Err(wire::Error::Length {
                expected,
                actual: bytes.len(),
            });
        }
        Self::read(&mut reader, rank, header_size)
    }

    fn read<'a>(
        reader: &mut Reader<'a>,
        rank: u32,
        header_size: usize,
    ) -> core::result::Result<Self, wire::Error<'a>> {
        let index_offset = reader.offset();
        let index_bytes = reader.take(STEP_INDEX_SIZE)?;
        let step_index_value =
            u64::from_le_bytes(index_bytes.try_into().expect("eight-byte index"));
        let step_index = Index::from_value(step_index_value).map_err(|_| wire::Error::Invalid {
            offset: index_offset,
            bytes: index_bytes,
            reason: "invalid step index",
        })?;
        let header_hash = reader.array()?;
        let mut repr = C::HostCurve::identity().to_bytes();
        let mut commitments = [C::HostCurve::identity(); HEADER_POLYNOMIALS];
        for point in &mut commitments {
            let offset = reader.offset();
            let point_bytes = reader.take(repr.as_ref().len())?;
            repr.as_mut().copy_from_slice(point_bytes);
            *point = C::HostCurve::from_bytes(repr).ok_or(wire::Error::Invalid {
                offset,
                bytes: point_bytes,
                reason: "invalid commitment",
            })?;
            if point.is_identity() {
                return Err(wire::Error::Invalid {
                    offset,
                    bytes: point_bytes,
                    reason: "identity commitment",
                });
            }
        }
        let witness_hash = reader.array()?;
        let binding_offset = reader.offset();
        let binding_bytes = reader.take(HASH_SIZE)?;
        let binding = binding_bytes.try_into().expect("hash-sized binding");
        let rerand_tag = reader.array()?;
        let setup_hash = reader.array()?;

        let expected_binding = compute_binding(
            step_index,
            &header_hash,
            &witness_hash,
            &commitments,
            &setup_hash,
            rank,
            header_size,
        );
        if expected_binding != binding {
            return Err(wire::Error::Invalid {
                offset: binding_offset,
                bytes: binding_bytes,
                reason: "mock proof binding mismatch",
            });
        }
        Ok(Self {
            step_index,
            header_hash,
            witness_hash,
            binding,
            rerand_tag,
            commitments,
            rank,
            header_size,
            setup_hash,
        })
    }
}

pub struct CompressedPcd<C: Cycle, H: Header<C::CircuitField>> {
    pub(crate) proof: CompressedProof<C>,
    pub(crate) data: H::Data,
}

impl<C: Cycle, H: Header<C::CircuitField>> CompressedPcd<C, H> {
    pub fn data(&self) -> &H::Data {
        &self.data
    }
    pub fn proof(&self) -> &CompressedProof<C> {
        &self.proof
    }
    pub fn into_parts(self) -> (CompressedProof<C>, H::Data) {
        (self.proof, self.data)
    }
}

impl<C: Cycle, H: Header<C::CircuitField>> Clone for CompressedPcd<C, H> {
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
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
    setup_hash: &[u8; HASH_SIZE],
    rank: u32,
    header_size: usize,
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
    state
        .update(setup_hash)
        .update(&rank.to_le_bytes())
        .update(&(header_size as u64).to_le_bytes());
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

pub(crate) fn compute_setup_hash<C: Cycle, R: Rank>(params: &C::Params) -> [u8; HASH_SIZE] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(HASH_SIZE)
        .personal(b"MkRagu_Setup___\0")
        .to_state();
    absorb_generators(&mut state, C::host_generators(params), R::num_coeffs());
    absorb_generators(&mut state, C::nested_generators(params), R::num_coeffs());
    absorb_poseidon(&mut state, C::circuit_poseidon(params));
    absorb_poseidon(&mut state, C::scalar_poseidon(params));
    let mut out = [0; HASH_SIZE];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

fn absorb_generators<P: Affine>(
    state: &mut blake2b_simd::State,
    generators: &impl FixedGenerators<P>,
    count: usize,
) {
    state.update(&(count as u64).to_le_bytes());
    for point in generators.g()[..count]
        .iter()
        .chain(core::iter::once(generators.h()))
    {
        state.update(point.to_bytes().as_ref());
    }
}

fn absorb_poseidon<F: Field, P: PoseidonPermutation<F>>(
    state: &mut blake2b_simd::State,
    params: &P,
) {
    for count in [
        P::T,
        P::RATE,
        P::FULL_ROUNDS,
        P::PARTIAL_ROUNDS,
        P::ALPHA as usize,
    ] {
        state.update(&(count as u64).to_le_bytes());
    }
    for table in [params.round_constants(), params.mds_matrix()] {
        state.update(&(table.len() as u64).to_le_bytes());
        for row in table {
            for value in row.as_ref() {
                state.update(value.to_bytes().as_ref());
            }
        }
    }
}
