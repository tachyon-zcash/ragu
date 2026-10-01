//! Versioned application envelope and rank-derived decoding bounds.

use alloc::vec::Vec;
use core::{marker::PhantomData, mem::size_of};

use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::Cycle;
use ragu_primitives::{
    vec::Len,
    wire::{Decode, Encode, Error, Limits, Reader, Scalar, Sequence},
};
use udon::field::Field;

use super::MinimalProof;
use crate::{
    Application, SelectableBackend,
    internal::{native, nested::NumStepsLen},
};

const MAGIC: &[u8; 8] = b"RAGUPCD\0";
const ENVELOPE_VERSION: u16 = 1;
const SCHEMA_VERSION: u16 = 1;
// Matches the verification semantics identified by crate::RAGU_TAG.
const PROTOCOL_VERSION: u16 = 1;
const ENVELOPE_SIZE: usize = 90;

/// Trusted identifiers for the cryptographic suite and complete application setup.
///
/// Assign these in your deployment manifest, never from an incoming proof. Use
/// collision-resistant digests of canonical manifests: `suite` must identify the
/// ordered curves, scalar/point encodings, generators and Poseidon parameters;
/// `application` must identify the ordered circuits, registry tags, and header
/// semantics. Change the corresponding identifier whenever that manifest changes.
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
/// Construct with [`Application::proof_format`]. The envelope is checked before
/// proof allocation. Decoding validates representation; call
/// [`Application::verify_minimal`] with the accompanying data before accepting it.
/// See the crate's `WIRE_FORMAT.md` for the version and compatibility contract.
pub struct ProofFormat<C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    context: ProofContext,
    marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Selects the byte format using identifiers from a trusted setup manifest.
    ///
    /// The application supplies rank and header size. The caller supplies the
    /// suite and application identifiers described by [`ProofContext`]; they
    /// cannot be inferred from Rust type names or from untrusted proof bytes.
    pub fn proof_format(&self, context: ProofContext) -> ProofFormat<C, R, HEADER_SIZE> {
        ProofFormat {
            context,
            marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> ProofFormat<C, R, HEADER_SIZE> {
    fn envelope(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENVELOPE_SIZE);
        bytes.extend_from_slice(MAGIC);
        ENVELOPE_VERSION.encode(&mut bytes);
        SCHEMA_VERSION.encode(&mut bytes);
        PROTOCOL_VERSION.encode(&mut bytes);
        R::RANK.encode(&mut bytes);
        (HEADER_SIZE as u64).encode(&mut bytes);
        bytes.extend_from_slice(&self.context.suite);
        bytes.extend_from_slice(&self.context.application);
        bytes
    }

    /// Encodes a structurally valid proof, including its version and context.
    /// Does not establish cryptographic validity.
    pub fn encode(&self, proof: &MinimalProof<C, R>) -> Result<Vec<u8>, Error<'static>> {
        if !proof.is_well_formed()
            || proof.left_header.len() != HEADER_SIZE
            || proof.right_header.len() != HEADER_SIZE
            || HEADER_SIZE > R::num_coeffs()
        {
            return Err(Error::Invalid {
                offset: 0,
                bytes: &[],
                reason: "invalid proof structure",
            });
        }
        let mut bytes = self.envelope();
        proof.encode(&mut bytes);
        Ok(bytes)
    }

    /// Aggregate decoding budgets covering every schema-valid proof at this rank.
    /// Includes temporary and normalized polynomial vector storage.
    pub fn decode_limits(&self) -> Limits {
        MinimalProof::<C, R>::decode_limits()
    }

    /// Maximum complete envelope size in bytes. Use this to bound transport
    /// input before buffering; decoded storage has a separate budget.
    pub fn max_encoded_size(&self) -> usize {
        MinimalProof::<C, R>::max_encoded_size().saturating_add(ENVELOPE_SIZE - 1)
    }

    /// Decodes with the rank-derived budgets, rejecting unknown versions,
    /// mismatched context, malformed structure, and trailing bytes.
    pub fn decode<'a>(&self, bytes: &'a [u8]) -> Result<MinimalProof<C, R>, Error<'a>> {
        self.decode_with_limits(bytes, self.decode_limits())
    }

    /// Decodes with an additional application resource policy. Each budget is
    /// capped at the schema's rank-derived maximum. Lower limits may reject
    /// otherwise valid proofs; callers must also limit transport buffering.
    pub fn decode_with_limits<'a>(
        &self,
        bytes: &'a [u8],
        limits: Limits,
    ) -> Result<MinimalProof<C, R>, Error<'a>> {
        let bound = self.decode_limits();
        let mut reader = Reader::new(
            bytes,
            Limits {
                elements: limits.elements.min(bound.elements),
                allocation: limits.allocation.min(bound.allocation),
            },
        );
        let envelope = reader.take(ENVELOPE_SIZE)?;
        let expected = self.envelope();
        // Report the exact rejected envelope component. All checks precede
        // payload decoding, including rejection of a future schema version.
        for (start, end, reason) in [
            (0, 8, "invalid proof magic"),
            (8, 10, "unsupported proof envelope version"),
            (10, 12, "unsupported proof schema version"),
            (12, 14, "unsupported proof protocol version"),
            (14, 18, "proof rank mismatch"),
            (18, 26, "proof header size mismatch"),
            (26, 58, "proof suite mismatch"),
            (58, 90, "proof application mismatch"),
        ] {
            if envelope[start..end] != expected[start..end] {
                return Err(Error::Invalid {
                    offset: start,
                    bytes: &envelope[start..end],
                    reason,
                });
            }
        }
        let maximum = self.max_encoded_size();
        if bytes.len() > maximum {
            return Err(Error::Limit {
                offset: ENVELOPE_SIZE,
                resource: "encoded bytes",
                requested: bytes.len(),
                remaining: maximum,
            });
        }
        // Check both child-header counts before any polynomial or header
        // allocation. Their offset is fixed by schema v1.
        let mut headers = Reader::new(
            bytes,
            Limits {
                elements: 0,
                allocation: 0,
            },
        );
        headers.take(
            ENVELOPE_SIZE
                + <C::ScalarField as Decode<Scalar>>::min_encoded_len()
                + CircuitIndex::min_encoded_len(),
        )?;
        for _ in 0..2 {
            let offset = headers.offset();
            let count_bytes = headers.take(8)?;
            let count = u64::from_le_bytes(count_bytes.try_into().expect("eight bytes"));
            if count != HEADER_SIZE as u64 || HEADER_SIZE > R::num_coeffs() {
                return Err(Error::Invalid {
                    offset,
                    bytes: count_bytes,
                    reason: "incorrect child header length",
                });
            }
            headers.take(
                HEADER_SIZE.saturating_mul(<C::CircuitField as Decode<Scalar>>::min_encoded_len()),
            )?;
        }
        let proof = MinimalProof::decode(&mut reader)?;
        if !reader.remaining().is_empty() {
            return Err(Error::Invalid {
                offset: reader.offset(),
                bytes: reader.remaining(),
                reason: "trailing bytes",
            });
        }
        if !proof.is_well_formed() {
            return Err(Error::Invalid {
                offset: ENVELOPE_SIZE,
                bytes: &[],
                reason: "invalid proof structure",
            });
        }
        Ok(proof)
    }
}

// Schema v1 contains 23 individual native polynomials, seven bridge
// polynomials and nine individual nested polynomials, plus these three vectors.
// WIRE_FORMAT.md pins the complete ordered schema; changing it requires a version bump.
fn vector_slots() -> usize {
    native::NUM_BINDERS + native::NUM_ENDOSCALING_STEPS + NumStepsLen::len()
}

impl<C: Cycle, R: Rank> MinimalProof<C, R> {
    /// Conservative aggregate budgets for schema v1 at this rank.
    ///
    /// For each polynomial of capacity N: at most N/2 wire blocks, N decoded
    /// coefficients, N/2 normalized block slots, and N normalized coefficients.
    /// Also counts the six protocol vectors and two headers (each at most N).
    /// Bounds requested vector storage, not allocator overhead, fixed-size Arc
    /// allocations, input buffering, or verification work.
    pub fn decode_limits() -> Limits {
        let n = R::num_coeffs();
        let slots = vector_slots();
        let polys = 39 + slots;
        let field = size_of::<C::CircuitField>().max(size_of::<C::ScalarField>());
        let block = size_of::<(usize, Vec<C::CircuitField>)>()
            .max(size_of::<(usize, Vec<C::ScalarField>)>());
        let poly = size_of::<sparse::Polynomial<C::CircuitField, R>>()
            .max(size_of::<sparse::Polynomial<C::ScalarField, R>>());
        let point = size_of::<C::HostCurve>().max(size_of::<C::NestedCurve>());
        Limits {
            elements: polys
                .saturating_mul(3 * n)
                .saturating_add(2 * slots)
                .saturating_add(2 * n),
            allocation: polys
                .saturating_mul(n)
                .saturating_mul(block.saturating_add(field.saturating_mul(2)))
                .saturating_add(slots.saturating_mul(poly.saturating_add(point)))
                .saturating_add((2 * n).saturating_mul(field)),
        }
    }

    /// Upper bound on the low-level versioned payload bytes for schema v1.
    pub fn max_encoded_size() -> usize {
        let n = R::num_coeffs();
        let polys = 39 + vector_slots();
        let field = <C::CircuitField as Decode<Scalar>>::min_encoded_len()
            .max(<C::ScalarField as Decode<Scalar>>::min_encoded_len());
        // FixedSequence's minimum includes all vector members' minimum sizes.
        // A polynomial adds at most N coefficients and N/2 sixteen-byte headers.
        1usize
            .saturating_add(Self::min_encoded_len())
            .saturating_add(
                polys
                    .saturating_mul(n)
                    .saturating_mul(field.saturating_add(8)),
            )
            .saturating_add((2 * n).saturating_mul(field))
    }
}

// Header size is application-specific, but cannot exceed a rank's circuit
// capacity. The envelope enforces the application's exact value before decode.
pub(super) struct HeaderSequence<R>(PhantomData<R>);
impl<F: Field, R: Rank> Encode<HeaderSequence<R>> for Vec<F> {
    fn encode(&self, output: &mut Vec<u8>) {
        <Self as Encode<Sequence<Scalar>>>::encode(self, output);
    }
}
impl<F: Field, R: Rank> Decode<HeaderSequence<R>> for Vec<F> {
    fn min_encoded_len() -> usize {
        8
    }
    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        let offset = reader.offset();
        let bytes = reader.remaining();
        let count = u64::decode(reader)?;
        if count > R::num_coeffs() as u64 {
            return Err(Error::Invalid {
                offset,
                bytes: &bytes[..8],
                reason: "header length exceeds rank",
            });
        }
        let mut values = reader.reserve::<F>(count, <F as Decode<Scalar>>::min_encoded_len())?;
        for _ in 0..count {
            values.push(<F as Decode<Scalar>>::decode(reader)?);
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use ragu_circuits::polynomials::ProductionRank;
    use ragu_core::pasta::{Fp, Pasta};

    use super::*;

    #[test]
    fn oversized_header_is_rejected_before_allocation() {
        let bytes = (ProductionRank::num_coeffs() as u64 + 1).to_bytes();
        let result = <Vec<Fp> as Decode<HeaderSequence<ProductionRank>>>::from_bytes(
            &bytes,
            Limits {
                elements: 0,
                allocation: 0,
            },
        );
        assert!(matches!(
            result,
            Err(Error::Invalid {
                reason: "header length exceeds rank",
                ..
            })
        ));
    }

    #[test]
    fn schema_v1_pins_protocol_and_vector_counts() {
        assert_eq!(crate::RAGU_TAG, b"ragu-pcd-v1");
        assert_eq!(native::NUM_BINDERS, 5);
        assert_eq!(native::NUM_ENDOSCALING_STEPS, 25);
        assert_eq!(NumStepsLen::len(), 28);
    }

    #[test]
    fn rank_bounds_cover_dense_and_fragmented_complete_payloads() {
        type R = ProductionRank;
        type P = MinimalProof<Pasta, R>;
        for gap in [1usize, 2, 6] {
            let mut proof = P::from_bytes(
                include_bytes!("../../tests/fixtures/wire/pre_udon_proof.bin"),
                P::decode_limits(),
            )
            .unwrap();
            fn polynomial<F: Field>(gap: usize) -> sparse::Polynomial<F, ProductionRank> {
                sparse::Polynomial::from_coeffs(
                    (0..ProductionRank::num_coeffs())
                        .map(|i| if i % gap == 0 { F::ONE } else { F::ZERO })
                        .collect(),
                )
            }
            macro_rules! fill { ($($field:ident),* $(,)?) => { $(proof.$field = polynomial(gap);)* }; }
            macro_rules! fill_arc { ($($field:ident),* $(,)?) => { $(proof.$field = Arc::new(polynomial(gap));)* }; }
            fill!(
                native_application_rx,
                native_preamble_rx,
                native_inner_error_rx,
                native_outer_error_rx,
                native_a_poly,
                native_b_poly,
                native_query_rx,
                native_registry_xy_poly,
                native_eval_rx,
                native_p_poly,
                native_hashes_1_rx,
                native_hashes_2_rx,
                native_inner_collapse_rx,
                native_outer_collapse_rx,
                native_compute_v_rx,
                native_bind_beta_rx,
                native_bind_endoscalar_rx,
                native_points_binding_rx,
                native_points_children_rx,
                native_points_registry_wx_rx,
                native_points_ab_rx,
                native_points_f_rx,
                native_points_walk_rx,
                nested_endoscalar_rx,
                nested_a_poly,
                nested_b_poly,
                nested_registry_xy_poly,
                nested_p_poly,
                nested_export_rx,
                nested_collapse_rx,
                nested_compute_v_rx
            );
            fill_arc!(
                bridge_preamble_rx,
                bridge_s_prime_rx,
                bridge_inner_error_rx,
                bridge_outer_error_rx,
                bridge_query_rx,
                bridge_f_rx,
                bridge_eval_rx,
                nested_points_rx
            );
            proof.native_bind_challenges_rxs = (0..proof.native_bind_challenges_rxs.len())
                .map(|_| polynomial(gap))
                .collect();
            proof.native_endoscaling_step_rxs = (0..proof.native_endoscaling_step_rxs.len())
                .map(|_| polynomial(gap))
                .collect();
            proof.nested_endoscaling_step_rxs = (0..proof.nested_endoscaling_step_rxs.len())
                .map(|_| polynomial(gap))
                .collect();
            proof.left_header = alloc::vec![Fp::ONE; R::num_coeffs()];
            proof.right_header = proof.left_header.clone();
            let bytes = proof.to_bytes();
            assert!(bytes.len() <= P::max_encoded_size());
            let decoded = P::from_bytes(&bytes, P::decode_limits()).unwrap();
            assert_eq!(decoded.to_bytes(), bytes);
            std::println!(
                "gap={gap}: bytes={}, bounds: elements={}, allocation={}, encoded={}",
                bytes.len(),
                P::decode_limits().elements,
                P::decode_limits().allocation,
                P::max_encoded_size()
            );
        }
    }
}
