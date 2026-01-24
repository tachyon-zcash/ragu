#![allow(dead_code)]

pub(crate) mod components;
pub(crate) use components::*;

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    polynomials::{Rank, structured, unstructured},
    registry::CircuitIndex,
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

/// The cryptographic proof structure containing staged witness polynomials,
/// commitments, and accumulated claims. Use [`Proof::carry`] to bundle with
/// application data into [`Pcd`].
#[derive(Clone)]
pub struct Proof<C: Cycle, R: Rank> {
    /// Circuit identifier, left/right header commitments, and the application
    /// witness polynomial with its blinding factor and commitment.
    pub(crate) application: Application<C, R>,

    /// Native and nested curve witness polynomials, blinds, and commitments
    /// that establish the initial transcript state.
    pub(crate) preamble: Preamble<C, R>,

    /// Mesh polynomials `wx0`, `wx1` on the host curve, plus nested curve
    /// s-prime witness for circuit selector evaluation.
    pub(crate) s_prime: SPrime<C, R>,

    /// Native and nested curve components for the N-sized revdot claim reduction.
    pub(crate) error_n: ErrorN<C, R>,

    /// Mesh `wy` polynomial plus native and nested curve components for
    /// the M-sized revdot claim reductions.
    pub(crate) error_m: ErrorM<C, R>,

    /// Folding polynomials `a(X)` and `b(X)` with their commitments, the
    /// revdot product scalar `c`, and nested curve components.
    pub(crate) ab: AB<C, R>,

    /// Mesh `xy` polynomial plus native and nested curve components for
    /// batched polynomial queries at challenge points.
    pub(crate) query: Query<C, R>,

    /// Batched verification polynomial combining evaluation claims, with
    /// nested curve components.
    pub(crate) f: F<C, R>,

    /// Native and nested curve staged witnesses for the IPA evaluation stage.
    pub(crate) eval: Eval<C, R>,

    /// Final batch proof: polynomial `p(X)`, its blinding factor, commitment,
    /// and evaluation `v = p(u)` at the challenge point.
    pub(crate) p: P<C, R>,

    /// Fiat-Shamir challenges: `w`, `y`, `z`, `mu`, `nu`, `mu_prime`, `nu_prime`,
    /// `x`, `alpha`, `u`, `beta`.
    pub(crate) challenges: Challenges<C>,

    /// Witness polynomials for internal recursion circuits: `hashes_1`,
    /// `hashes_2`, `partial_collapse`, `full_collapse`, and `compute_v`.
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
                registry_wx0_poly: zero_unstructured.clone(),
                registry_wx0_blind: host_blind,
                registry_wx0_commitment: host_commitment,
                registry_wx1_poly: zero_unstructured.clone(),
                registry_wx1_blind: host_blind,
                registry_wx1_commitment: host_commitment,
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
                registry_wy_poly: zero_structured_host.clone(),
                registry_wy_blind: host_blind,
                registry_wy_commitment: host_commitment,
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
                registry_xy_poly: zero_unstructured.clone(),
                registry_xy_blind: host_blind,
                registry_xy_commitment: host_commitment,
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
                compute_v_rx: zero_structured_host,
                compute_v_blind: host_blind,
                compute_v_commitment: host_commitment,
            },
        }
    }
}
