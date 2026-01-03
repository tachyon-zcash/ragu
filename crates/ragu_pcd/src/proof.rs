#![allow(dead_code)]

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    mesh::CircuitIndex,
    polynomials::{Rank, structured, unstructured},
};
use ragu_core::{
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;

use alloc::vec;
use alloc::vec::Vec;

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
    /// Application-specific proof data.
    pub(crate) application: Application<C, R>,
    pub(crate) preamble: Preamble<C, R>,
    pub(crate) s_prime: SPrime<C, R>,
    pub(crate) error_m: ErrorM<C, R>,
    pub(crate) error_n: ErrorN<C, R>,
    pub(crate) ab: AB<C, R>,
    pub(crate) query: Query<C, R>,
    pub(crate) f: F<C, R>,
    pub(crate) eval: Eval<C, R>,
    pub(crate) p: P<C, R>,
    pub(crate) challenges: Challenges<C>,
    pub(crate) circuits: InternalCircuits<C, R>,
}

/// Application-specific proof data including circuit ID, headers, and commitment.
#[derive(Clone)]
pub(crate) struct Application<C: Cycle, R: Rank> {
    /// The circuit ID for the registered `Step` that the prover claims to have
    /// used to produce this proof. The prover could have used any circuit ID
    /// within the mesh here, but because circuits impose a discriminant public
    /// input in the linear term (including internal circuits) the verifier can
    /// prevent the use of invalid circuits.
    ///
    /// It is, however, very important for the verifier (or recursive
    /// verification circuit) to check that the circuit ID is valid within the
    /// mesh domain by ensuring it is part of its domain. See the
    /// [`crate::components::root_of_unity`] module for information.
    pub(crate) circuit_id: CircuitIndex,

    /// The `left_header` the prover claims to have used as the output header
    /// of the left child proof.
    pub(crate) left_header: Vec<C::CircuitField>,

    /// The `right_header` the prover claims to have used as the output header
    /// of the right child proof.
    pub(crate) right_header: Vec<C::CircuitField>,

    /// The witness polynomial the prover claims satisfies the application
    /// `Step` circuit identified.
    pub(crate) rx: structured::Polynomial<C::CircuitField, R>,

    pub(crate) blind: C::CircuitField,
    pub(crate) commitment: C::HostCurve,
}

/// Preamble stage proof with native and nested layer commitments.
#[derive(Clone)]
pub(crate) struct Preamble<C: Cycle, R: Rank> {
    pub(crate) stage_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) stage_blind: C::CircuitField,
    /// Computed as stage_rx.commit(generators, stage_blind)
    pub(crate) stage_commitment: C::HostCurve,

    /// Computed from stage_commitment and child proof commitments
    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    /// Computed as nested_rx.commit(generators, nested_blind)
    pub(crate) nested_commitment: C::NestedCurve,
}

/// S' stage proof: m(w, x_i, Y) and nested commitment.
#[derive(Clone)]
pub(crate) struct SPrime<C: Cycle, R: Rank> {
    pub(crate) mesh_wx0_poly: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_wx0_blind: C::CircuitField,
    pub(crate) mesh_wx0_commitment: C::HostCurve,

    pub(crate) mesh_wx1_poly: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_wx1_blind: C::CircuitField,
    pub(crate) mesh_wx1_commitment: C::HostCurve,

    pub(crate) nested_s_prime_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_s_prime_blind: C::ScalarField,
    pub(crate) nested_s_prime_commitment: C::NestedCurve,
}

/// Error M stage proof with mesh_wy bundled (Layer 1: N instances of M-sized reductions).
#[derive(Clone)]
pub(crate) struct ErrorM<C: Cycle, R: Rank> {
    // Mesh m(w, X, y) components
    pub(crate) mesh_wy_poly: structured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_wy_blind: C::CircuitField,
    pub(crate) mesh_wy_commitment: C::HostCurve,

    // Error M stage components
    pub(crate) stage_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) stage_blind: C::CircuitField,
    pub(crate) stage_commitment: C::HostCurve,

    // Nested layer (bundles mesh_wy_commitment + stage_commitment)
    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// Error N stage proof (Layer 2: Single N-sized reduction).
#[derive(Clone)]
pub(crate) struct ErrorN<C: Cycle, R: Rank> {
    pub(crate) stage_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) stage_blind: C::CircuitField,
    pub(crate) stage_commitment: C::HostCurve,
    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// A/B polynomial proof for folding. A and B depend on (mu, nu).
#[derive(Clone)]
pub(crate) struct AB<C: Cycle, R: Rank> {
    pub(crate) a_poly: structured::Polynomial<C::CircuitField, R>,
    pub(crate) a_blind: C::CircuitField,
    pub(crate) a_commitment: C::HostCurve,

    pub(crate) b_poly: structured::Polynomial<C::CircuitField, R>,
    pub(crate) b_blind: C::CircuitField,
    pub(crate) b_commitment: C::HostCurve,

    /// The revdot product of `a_poly` and `b_poly`.
    pub(crate) c: C::CircuitField,

    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// Query stage proof with mesh_xy bundled.
#[derive(Clone)]
pub(crate) struct Query<C: Cycle, R: Rank> {
    // Mesh m(x, y) components
    pub(crate) mesh_xy_poly: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_xy_blind: C::CircuitField,
    pub(crate) mesh_xy_commitment: C::HostCurve,

    // Query stage components
    pub(crate) stage_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) stage_blind: C::CircuitField,
    pub(crate) stage_commitment: C::HostCurve,

    // Nested layer (bundles mesh_xy_commitment + stage_commitment)
    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// F polynomial proof with native and nested layer commitments.
#[derive(Clone)]
pub(crate) struct F<C: Cycle, R: Rank> {
    pub(crate) poly: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) blind: C::CircuitField,
    pub(crate) commitment: C::HostCurve,

    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// Evaluation stage proof with native and nested layer commitments.
#[derive(Clone)]
pub(crate) struct Eval<C: Cycle, R: Rank> {
    pub(crate) stage_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) stage_blind: C::CircuitField,
    pub(crate) stage_commitment: C::HostCurve,

    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// Batch polynomial evaluation proof.
#[derive(Clone)]
pub(crate) struct P<C: Cycle, R: Rank> {
    /// $p(X)$
    pub(crate) poly: unstructured::Polynomial<C::CircuitField, R>,
    /// Blinding factor for $p(X)$ commitment
    pub(crate) blind: C::CircuitField,
    /// $p(X)$ commitment
    pub(crate) commitment: C::HostCurve,

    /// $v = p(u)$
    pub(crate) v: C::CircuitField,
}

/// Fiat-Shamir challenges derived during proof generation.
#[derive(Clone)]
pub(crate) struct Challenges<C: Cycle> {
    pub(crate) w: C::CircuitField,
    pub(crate) y: C::CircuitField,
    pub(crate) z: C::CircuitField,
    pub(crate) mu: C::CircuitField,
    pub(crate) nu: C::CircuitField,
    pub(crate) mu_prime: C::CircuitField,
    pub(crate) nu_prime: C::CircuitField,
    pub(crate) x: C::CircuitField,
    pub(crate) alpha: C::CircuitField,
    pub(crate) u: C::CircuitField,
    pub(crate) beta: C::CircuitField,
}

impl<C: Cycle> Challenges<C> {
    /// Creates a new set of Fiat-Shamir challenges from Element gadgets.
    ///
    /// The `MaybeKind = Always<()>` constraint ensures this can only be called
    /// in contexts where witness values are guaranteed to exist.
    pub(crate) fn new<'dr, D>(
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        mu: &Element<'dr, D>,
        nu: &Element<'dr, D>,
        mu_prime: &Element<'dr, D>,
        nu_prime: &Element<'dr, D>,
        x: &Element<'dr, D>,
        alpha: &Element<'dr, D>,
        u: &Element<'dr, D>,
        beta: &Element<'dr, D>,
    ) -> Self
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        Self {
            w: *w.value().take(),
            y: *y.value().take(),
            z: *z.value().take(),
            mu: *mu.value().take(),
            nu: *nu.value().take(),
            mu_prime: *mu_prime.value().take(),
            nu_prime: *nu_prime.value().take(),
            x: *x.value().take(),
            alpha: *alpha.value().take(),
            u: *u.value().take(),
            beta: *beta.value().take(),
        }
    }

    /// Creates trivial challenges with all zero values (for dummy proofs).
    pub(crate) fn trivial() -> Self {
        Self {
            w: C::CircuitField::ZERO,
            y: C::CircuitField::ZERO,
            z: C::CircuitField::ZERO,
            mu: C::CircuitField::ZERO,
            nu: C::CircuitField::ZERO,
            mu_prime: C::CircuitField::ZERO,
            nu_prime: C::CircuitField::ZERO,
            x: C::CircuitField::ZERO,
            alpha: C::CircuitField::ZERO,
            u: C::CircuitField::ZERO,
            beta: C::CircuitField::ZERO,
        }
    }
}

/// Circuit polynomial commitments (hashes, partial_collapse, full_collapse, compute_v).
#[derive(Clone)]
pub(crate) struct InternalCircuits<C: Cycle, R: Rank> {
    pub(crate) hashes_1_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) hashes_1_blind: C::CircuitField,
    pub(crate) hashes_1_commitment: C::HostCurve,
    pub(crate) hashes_2_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) hashes_2_blind: C::CircuitField,
    pub(crate) hashes_2_commitment: C::HostCurve,
    pub(crate) partial_collapse_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) partial_collapse_blind: C::CircuitField,
    pub(crate) partial_collapse_commitment: C::HostCurve,
    pub(crate) full_collapse_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) full_collapse_blind: C::CircuitField,
    pub(crate) full_collapse_commitment: C::HostCurve,
    pub(crate) compute_v_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) compute_v_blind: C::CircuitField,
    pub(crate) compute_v_commitment: C::HostCurve,
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data<'_>) -> Pcd<'_, C, R, H> {
        Pcd { proof: self, data }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> crate::Application<'_, C, R, HEADER_SIZE> {
    /// Creates a minimal trivial proof wrapped as a PCD with empty header.
    /// Used internally for rerandomization.
    pub(crate) fn trivial_pcd<'source>(&self) -> Pcd<'source, C, R, ()> {
        self.trivial_proof().carry(())
    }

    /// Creates a trivial proof for the empty [`Header`] implementation `()`.
    ///
    /// Trivial proofs use zero polynomials and deterministic blindings. They
    /// are not meant to verify on their own, but are used as inputs to `fuse`
    /// to produce valid proofs.
    ///
    /// See also: `seed()` for the public API to seed new computations.
    pub(crate) fn trivial_proof(&self) -> Proof<C, R> {
        // Deterministic blindings
        let host_blind = C::CircuitField::ONE;
        let nested_blind = C::ScalarField::ONE;

        // Zero polynomials and their commitments
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
                stage_rx: zero_structured_host.clone(),
                stage_blind: host_blind,
                stage_commitment: host_commitment,
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
            error_m: ErrorM {
                mesh_wy_poly: zero_structured_host.clone(),
                mesh_wy_blind: host_blind,
                mesh_wy_commitment: host_commitment,
                stage_rx: zero_structured_host.clone(),
                stage_blind: host_blind,
                stage_commitment: host_commitment,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment,
            },
            error_n: ErrorN {
                stage_rx: zero_structured_host.clone(),
                stage_blind: host_blind,
                stage_commitment: host_commitment,
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
                stage_rx: zero_structured_host.clone(),
                stage_blind: host_blind,
                stage_commitment: host_commitment,
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
                stage_rx: zero_structured_host.clone(),
                stage_blind: host_blind,
                stage_commitment: host_commitment,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment,
            },
            p: P {
                poly: zero_unstructured.clone(),
                blind: host_blind,
                commitment: host_commitment,

                // p(X) = 0 => v = p(u) = 0
                v: C::CircuitField::ZERO,
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
