#![allow(dead_code)]

pub(crate) mod components;
pub(crate) use components::*;

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    mesh::CircuitIndex,
    polynomials::{Rank, structured, unstructured},
};
use ragu_primitives::vec::Len;

use alloc::vec;

use crate::circuits::nested::NUM_ENDOSCALING_POINTS;
use crate::components::endoscalar::NumStepsLen;
use crate::header::Header;

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    /// The recursive proof for the accompanying data.
    pub proof: Proof<C, R>,

    /// Data needed to witness a [`Header`] within a [`Step`](super::Step).
    pub data: H::Data<'source>,
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Clone for Pcd<'_, C, R, H> {
    fn clone(&self) -> Self {
        Pcd {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
    }
}

/// Represents a recursive proof for the correctness of some computation.
#[derive(Clone)]
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) application: Application<C, R>,
    pub(crate) preamble: Preamble<C, R>,
    pub(crate) s_prime: SPrime<C, R>,
    pub(crate) error_n: ErrorN<C, R>,
    pub(crate) error_m: ErrorM<C, R>,
    pub(crate) ab: AB<C, R>,
    pub(crate) query: Query<C, R>,
    pub(crate) f: F<C, R>,
    pub(crate) eval: Eval<C, R>,
    pub(crate) p: P<C, R>,
    pub(crate) challenges: Challenges<C>,
    pub(crate) circuits: InternalCircuits<C, R>,
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data<'_>) -> Pcd<'_, C, R, H> {
        Pcd { proof: self, data }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> crate::Application<'_, C, R, HEADER_SIZE> {
    pub(crate) fn trivial_pcd<'source>(&self) -> Pcd<'source, C, R, ()> {
        self.trivial_proof().carry(())
    }

    pub(crate) fn trivial_proof(&self) -> Proof<C, R> {
        let host_blind = C::CircuitField::ONE;
        let nested_blind = C::ScalarField::ONE;

        let zero_structured_host = structured::Polynomial::<C::CircuitField, R>::new();
        let zero_structured_nested = structured::Polynomial::<C::ScalarField, R>::new();
        let zero_unstructured = unstructured::Polynomial::<C::CircuitField, R>::new();

        let host_commitment =
            zero_structured_host.commit(C::host_generators(self.params), host_blind);
        let nested_commitment =
            zero_structured_nested.commit(C::nested_generators(self.params), nested_blind);

        Proof {
            application: Application {
                circuit_id: CircuitIndex::new(0),
                left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                rx: zero_structured_host.clone(),
                blind: host_blind,
                commitment: host_commitment,
            },
            preamble: Preamble {
                native_rx: zero_structured_host.clone(),
                native_blind: host_blind,
                native_commitment: host_commitment,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment,
            },
            s_prime: SPrime {
                mesh_wx0_poly: zero_unstructured.clone(),
                mesh_wx0_blind: host_blind,
                mesh_wx0_commitment: host_commitment,
                mesh_wx1_poly: zero_unstructured.clone(),
                mesh_wx1_blind: host_blind,
                mesh_wx1_commitment: host_commitment,
                nested_s_prime_rx: zero_structured_nested.clone(),
                nested_s_prime_blind: nested_blind,
                nested_s_prime_commitment: nested_commitment,
            },
            error_n: ErrorN {
                native_rx: zero_structured_host.clone(),
                native_blind: host_blind,
                native_commitment: host_commitment,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment,
            },
            error_m: ErrorM {
                mesh_wy_poly: zero_structured_host.clone(),
                mesh_wy_blind: host_blind,
                mesh_wy_commitment: host_commitment,
                native_rx: zero_structured_host.clone(),
                native_blind: host_blind,
                native_commitment: host_commitment,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment,
            },
            ab: AB {
                a_poly: zero_structured_host.clone(),
                a_blind: host_blind,
                a_commitment: host_commitment,
                b_poly: zero_structured_host.clone(),
                b_blind: host_blind,
                b_commitment: host_commitment,
                c: C::CircuitField::ZERO,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment,
            },
            query: Query {
                mesh_xy_poly: zero_unstructured.clone(),
                mesh_xy_blind: host_blind,
                mesh_xy_commitment: host_commitment,
                native_rx: zero_structured_host.clone(),
                native_blind: host_blind,
                native_commitment: host_commitment,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment,
            },
            f: F {
                poly: zero_unstructured.clone(),
                blind: host_blind,
                commitment: host_commitment,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment,
            },
            eval: Eval {
                native_rx: zero_structured_host.clone(),
                native_blind: host_blind,
                native_commitment: host_commitment,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment,
            },
            p: P {
                poly: zero_unstructured.clone(),
                blind: host_blind,
                commitment: host_commitment,
                v: C::CircuitField::ZERO,
                endoscalar_rx: zero_structured_nested.clone(),
                points_rx: zero_structured_nested.clone(),
                step_rxs: vec![
                    zero_structured_nested.clone();
                    NumStepsLen::<NUM_ENDOSCALING_POINTS>::len()
                ],
            },
            challenges: Challenges::trivial(),
            circuits: InternalCircuits {
                hashes_1_rx: zero_structured_host.clone(),
                hashes_1_blind: host_blind,
                hashes_1_commitment: host_commitment,
                hashes_2_rx: zero_structured_host.clone(),
                hashes_2_blind: host_blind,
                hashes_2_commitment: host_commitment,
                partial_collapse_rx: zero_structured_host.clone(),
                partial_collapse_blind: host_blind,
                partial_collapse_commitment: host_commitment,
                full_collapse_rx: zero_structured_host.clone(),
                full_collapse_blind: host_blind,
                full_collapse_commitment: host_commitment,
                compute_v_rx: zero_structured_host.clone(),
                compute_v_blind: host_blind,
                compute_v_commitment: host_commitment,
                endoscale_challenges_rx: zero_structured_host,
                endoscale_challenges_blind: host_blind,
                endoscale_challenges_commitment: host_commitment,
            },
        }
    }
}
