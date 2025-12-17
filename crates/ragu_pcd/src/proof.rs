use arithmetic::{Cycle, FixedGenerators};
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    mesh::CircuitIndex,
    polynomials::{Rank, structured, unstructured},
};

use alloc::vec;
use alloc::vec::Vec;

use crate::{Application, header::Header, internal_circuits::dummy};

/// Represents a recursive proof for the correctness of some computation.
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) preamble: PreambleProof<C, R>,
    pub(crate) s_prime: SPrimeProof<C, R>,
    pub(crate) mesh_wy: MeshWyProof<C, R>,
    pub(crate) error: ErrorProof<C, R>,
    pub(crate) ab: ABProof<C, R>,
    pub(crate) mesh_xy: MeshXyProof<C, R>,
    pub(crate) query: QueryProof<C, R>,
    pub(crate) f: FProof<C, R>,
    pub(crate) p: PProof<C, R>,
    pub(crate) eval: EvalProof<C, R>,
    pub(crate) internal_circuits: InternalCircuits<C, R>,
    pub(crate) application: ApplicationProof<C, R>,
}

/// Application-specific proof data including circuit ID, headers, and commitment.
pub(crate) struct ApplicationProof<C: Cycle, R: Rank> {
    pub(crate) circuit_id: CircuitIndex,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,
    pub(crate) rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) blind: C::CircuitField,
    pub(crate) commitment: C::HostCurve,
}

/// Preamble stage proof with native and nested layer commitments.
pub(crate) struct PreambleProof<C: Cycle, R: Rank> {
    pub(crate) native_preamble_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_preamble_blind: C::CircuitField,
    /// This can be computed using native_preamble_rx / native_preamble_blind
    pub(crate) native_preamble_commitment: C::HostCurve,

    pub(crate) nested_preamble_blind: C::ScalarField,
    /// This can be computed using native_preamble_commitment
    pub(crate) nested_preamble_rx: structured::Polynomial<C::ScalarField, R>,
    /// This can be computed using nested_preamble_rx / nested_preamble_blind
    pub(crate) nested_preamble_commitment: C::NestedCurve,
}

/// Fiat-Shamir challenges and C/V/hash/ky circuit polynomials.
pub(crate) struct InternalCircuits<C: Cycle, R: Rank> {
    pub(crate) w: C::CircuitField,
    pub(crate) y: C::CircuitField,
    pub(crate) z: C::CircuitField,
    pub(crate) c: C::CircuitField,
    pub(crate) c_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) c_rx_blind: C::CircuitField,
    pub(crate) c_rx_commitment: C::HostCurve,
    pub(crate) v: C::CircuitField,
    pub(crate) v_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) v_rx_blind: C::CircuitField,
    pub(crate) v_rx_commitment: C::HostCurve,
    pub(crate) hashes_1_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) hashes_1_rx_blind: C::CircuitField,
    pub(crate) hashes_1_rx_commitment: C::HostCurve,
    pub(crate) hashes_2_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) hashes_2_rx_blind: C::CircuitField,
    pub(crate) hashes_2_rx_commitment: C::HostCurve,
    pub(crate) ky_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) ky_rx_blind: C::CircuitField,
    pub(crate) ky_rx_commitment: C::HostCurve,
    pub(crate) mu: C::CircuitField,
    pub(crate) nu: C::CircuitField,
    pub(crate) mu_prime: C::CircuitField,
    pub(crate) nu_prime: C::CircuitField,
    pub(crate) x: C::CircuitField,
    pub(crate) alpha: C::CircuitField,
    pub(crate) u: C::CircuitField,
    pub(crate) beta: C::CircuitField,
}

/// Query stage proof with native and nested layer commitments.
pub(crate) struct QueryProof<C: Cycle, R: Rank> {
    pub(crate) native_query_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_query_blind: C::CircuitField,
    pub(crate) native_query_commitment: C::HostCurve,

    pub(crate) nested_query_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_query_blind: C::ScalarField,
    pub(crate) nested_query_commitment: C::NestedCurve,
}

/// F polynomial proof with native and nested layer commitments.
///
/// The F polynomial is an unstructured polynomial that batches quotient polynomials
/// `(p(X) - p(a)) / (X - a)` using the alpha challenge.
pub(crate) struct FProof<C: Cycle, R: Rank> {
    pub(crate) native_f_rx: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) native_f_blind: C::CircuitField,
    pub(crate) native_f_commitment: C::HostCurve,

    pub(crate) nested_f_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_f_blind: C::ScalarField,
    pub(crate) nested_f_commitment: C::NestedCurve,
}

/// P polynomial proof for accumulation.
///
/// The P polynomial batches F with all queried polynomials using the beta challenge.
/// The expected evaluation `v = P(u)` is checked in the decision procedure.
pub(crate) struct PProof<C: Cycle, R: Rank> {
    pub(crate) p: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) p_blind: C::CircuitField,
    pub(crate) p_commitment: C::HostCurve,
}

/// Evaluation stage proof with native and nested layer commitments.
pub(crate) struct EvalProof<C: Cycle, R: Rank> {
    pub(crate) native_eval_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_eval_blind: C::CircuitField,
    pub(crate) native_eval_commitment: C::HostCurve,

    pub(crate) nested_eval_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_eval_blind: C::ScalarField,
    pub(crate) nested_eval_commitment: C::NestedCurve,
}

/// Error stage proof with native and nested layer commitments for both layers.
pub(crate) struct ErrorProof<C: Cycle, R: Rank> {
    // Layer 1 (error_m): N instances of M-sized reductions
    pub(crate) native_error_m_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_error_m_blind: C::CircuitField,
    pub(crate) native_error_m_commitment: C::HostCurve,

    pub(crate) nested_error_m_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_error_m_blind: C::ScalarField,
    pub(crate) nested_error_m_commitment: C::NestedCurve,

    // Layer 2 (error_n): Single N-sized reduction
    pub(crate) native_error_n_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_error_n_blind: C::CircuitField,
    pub(crate) native_error_n_commitment: C::HostCurve,

    pub(crate) nested_error_n_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_error_n_blind: C::ScalarField,
    pub(crate) nested_error_n_commitment: C::NestedCurve,
}

/// A/B polynomial proof for folding. A and B depend on (mu, nu).
pub(crate) struct ABProof<C: Cycle, R: Rank> {
    pub(crate) a: structured::Polynomial<C::CircuitField, R>,
    pub(crate) a_blind: C::CircuitField,
    pub(crate) a_commitment: C::HostCurve,

    pub(crate) b: structured::Polynomial<C::CircuitField, R>,
    pub(crate) b_blind: C::CircuitField,
    pub(crate) b_commitment: C::HostCurve,

    pub(crate) nested_ab_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_ab_blind: C::ScalarField,
    pub(crate) nested_ab_commitment: C::NestedCurve,
}

/// S' stage proof: m(w, x_i, Y) and nested commitment.
pub(crate) struct SPrimeProof<C: Cycle, R: Rank> {
    pub(crate) mesh_wx0: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_wx0_blind: C::CircuitField,
    pub(crate) mesh_wx0_commitment: C::HostCurve,

    pub(crate) mesh_wx1: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_wx1_blind: C::CircuitField,
    pub(crate) mesh_wx1_commitment: C::HostCurve,

    pub(crate) nested_s_prime_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_s_prime_blind: C::ScalarField,
    pub(crate) nested_s_prime_commitment: C::NestedCurve,
}

/// S'' stage proof: m(w, X, y).
pub(crate) struct MeshWyProof<C: Cycle, R: Rank> {
    pub(crate) mesh_wy: structured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_wy_blind: C::CircuitField,
    pub(crate) mesh_wy_commitment: C::HostCurve,
}

/// Mesh m(x, y) commitment (included in nested query stage).
pub(crate) struct MeshXyProof<C: Cycle, R: Rank> {
    pub(crate) mesh_xy: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_xy_blind: C::CircuitField,
    pub(crate) mesh_xy_commitment: C::HostCurve,
}

impl<C: Cycle, R: Rank> Clone for Proof<C, R> {
    fn clone(&self) -> Self {
        Proof {
            preamble: self.preamble.clone(),
            s_prime: self.s_prime.clone(),
            mesh_wy: self.mesh_wy.clone(),
            error: self.error.clone(),
            ab: self.ab.clone(),
            mesh_xy: self.mesh_xy.clone(),
            query: self.query.clone(),
            f: self.f.clone(),
            p: self.p.clone(),
            eval: self.eval.clone(),
            internal_circuits: self.internal_circuits.clone(),
            application: self.application.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ApplicationProof<C, R> {
    fn clone(&self) -> Self {
        ApplicationProof {
            circuit_id: self.circuit_id,
            left_header: self.left_header.clone(),
            right_header: self.right_header.clone(),
            rx: self.rx.clone(),
            blind: self.blind,
            commitment: self.commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for PreambleProof<C, R> {
    fn clone(&self) -> Self {
        PreambleProof {
            native_preamble_rx: self.native_preamble_rx.clone(),
            native_preamble_commitment: self.native_preamble_commitment,
            native_preamble_blind: self.native_preamble_blind,
            nested_preamble_rx: self.nested_preamble_rx.clone(),
            nested_preamble_commitment: self.nested_preamble_commitment,
            nested_preamble_blind: self.nested_preamble_blind,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for SPrimeProof<C, R> {
    fn clone(&self) -> Self {
        SPrimeProof {
            mesh_wx0: self.mesh_wx0.clone(),
            mesh_wx0_blind: self.mesh_wx0_blind,
            mesh_wx0_commitment: self.mesh_wx0_commitment,
            mesh_wx1: self.mesh_wx1.clone(),
            mesh_wx1_blind: self.mesh_wx1_blind,
            mesh_wx1_commitment: self.mesh_wx1_commitment,
            nested_s_prime_rx: self.nested_s_prime_rx.clone(),
            nested_s_prime_blind: self.nested_s_prime_blind,
            nested_s_prime_commitment: self.nested_s_prime_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for MeshWyProof<C, R> {
    fn clone(&self) -> Self {
        MeshWyProof {
            mesh_wy: self.mesh_wy.clone(),
            mesh_wy_blind: self.mesh_wy_blind,
            mesh_wy_commitment: self.mesh_wy_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for MeshXyProof<C, R> {
    fn clone(&self) -> Self {
        MeshXyProof {
            mesh_xy: self.mesh_xy.clone(),
            mesh_xy_blind: self.mesh_xy_blind,
            mesh_xy_commitment: self.mesh_xy_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ErrorProof<C, R> {
    fn clone(&self) -> Self {
        ErrorProof {
            native_error_m_rx: self.native_error_m_rx.clone(),
            native_error_m_blind: self.native_error_m_blind,
            native_error_m_commitment: self.native_error_m_commitment,
            nested_error_m_rx: self.nested_error_m_rx.clone(),
            nested_error_m_blind: self.nested_error_m_blind,
            nested_error_m_commitment: self.nested_error_m_commitment,
            native_error_n_rx: self.native_error_n_rx.clone(),
            native_error_n_blind: self.native_error_n_blind,
            native_error_n_commitment: self.native_error_n_commitment,
            nested_error_n_rx: self.nested_error_n_rx.clone(),
            nested_error_n_blind: self.nested_error_n_blind,
            nested_error_n_commitment: self.nested_error_n_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ABProof<C, R> {
    fn clone(&self) -> Self {
        ABProof {
            a: self.a.clone(),
            a_blind: self.a_blind,
            a_commitment: self.a_commitment,
            b: self.b.clone(),
            b_blind: self.b_blind,
            b_commitment: self.b_commitment,
            nested_ab_rx: self.nested_ab_rx.clone(),
            nested_ab_blind: self.nested_ab_blind,
            nested_ab_commitment: self.nested_ab_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for InternalCircuits<C, R> {
    fn clone(&self) -> Self {
        InternalCircuits {
            w: self.w,
            y: self.y,
            z: self.z,
            c: self.c,
            c_rx: self.c_rx.clone(),
            c_rx_blind: self.c_rx_blind,
            c_rx_commitment: self.c_rx_commitment,
            v_rx: self.v_rx.clone(),
            v_rx_blind: self.v_rx_blind,
            v_rx_commitment: self.v_rx_commitment,
            hashes_1_rx: self.hashes_1_rx.clone(),
            hashes_1_rx_blind: self.hashes_1_rx_blind,
            hashes_1_rx_commitment: self.hashes_1_rx_commitment,
            hashes_2_rx: self.hashes_2_rx.clone(),
            hashes_2_rx_blind: self.hashes_2_rx_blind,
            hashes_2_rx_commitment: self.hashes_2_rx_commitment,
            ky_rx: self.ky_rx.clone(),
            ky_rx_blind: self.ky_rx_blind,
            ky_rx_commitment: self.ky_rx_commitment,
            mu: self.mu,
            nu: self.nu,
            mu_prime: self.mu_prime,
            nu_prime: self.nu_prime,
            x: self.x,
            alpha: self.alpha,
            u: self.u,
            beta: self.beta,
            v: self.v,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for QueryProof<C, R> {
    fn clone(&self) -> Self {
        QueryProof {
            native_query_rx: self.native_query_rx.clone(),
            native_query_blind: self.native_query_blind,
            native_query_commitment: self.native_query_commitment,
            nested_query_rx: self.nested_query_rx.clone(),
            nested_query_blind: self.nested_query_blind,
            nested_query_commitment: self.nested_query_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for FProof<C, R> {
    fn clone(&self) -> Self {
        FProof {
            native_f_rx: self.native_f_rx.clone(),
            native_f_blind: self.native_f_blind,
            native_f_commitment: self.native_f_commitment,
            nested_f_rx: self.nested_f_rx.clone(),
            nested_f_blind: self.nested_f_blind,
            nested_f_commitment: self.nested_f_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for PProof<C, R> {
    fn clone(&self) -> Self {
        PProof {
            p: self.p.clone(),
            p_blind: self.p_blind,
            p_commitment: self.p_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for EvalProof<C, R> {
    fn clone(&self) -> Self {
        EvalProof {
            native_eval_rx: self.native_eval_rx.clone(),
            native_eval_blind: self.native_eval_blind,
            native_eval_commitment: self.native_eval_commitment,
            nested_eval_rx: self.nested_eval_rx.clone(),
            nested_eval_blind: self.nested_eval_blind,
            nested_eval_commitment: self.nested_eval_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data<'_>) -> Pcd<'_, C, R, H> {
        Pcd { proof: self, data }
    }
}

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    /// The recursive proof for the accompanying data.
    pub proof: Proof<C, R>,

    /// Arbitrary data encoded into a [`Header`].
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

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
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

        // Generator points
        let host_g = self.params.host_generators().g()[0];
        let nested_g = self.params.nested_generators().g()[0];

        // Zero polynomials
        let zero_structured_host = structured::Polynomial::<C::CircuitField, R>::new();
        let zero_structured_nested = structured::Polynomial::<C::ScalarField, R>::new();
        let zero_unstructured = unstructured::Polynomial::<C::CircuitField, R>::new();

        // Dummy circuit rx for application field
        let dummy_rx = dummy::Circuit
            .rx((), self.circuit_mesh.get_key())
            .expect("dummy circuit rx should not fail")
            .0;
        let dummy_commitment = dummy_rx.commit(self.params.host_generators(), host_blind);
        let dummy_circuit_id = dummy::CIRCUIT_ID.circuit_index(self.num_application_steps);

        Proof {
            preamble: PreambleProof {
                native_preamble_rx: zero_structured_host.clone(),
                native_preamble_blind: host_blind,
                native_preamble_commitment: host_g,
                nested_preamble_rx: zero_structured_nested.clone(),
                nested_preamble_blind: nested_blind,
                nested_preamble_commitment: nested_g,
            },
            s_prime: SPrimeProof {
                mesh_wx0: zero_unstructured.clone(),
                mesh_wx0_blind: host_blind,
                mesh_wx0_commitment: host_g,
                mesh_wx1: zero_unstructured.clone(),
                mesh_wx1_blind: host_blind,
                mesh_wx1_commitment: host_g,
                nested_s_prime_rx: zero_structured_nested.clone(),
                nested_s_prime_blind: nested_blind,
                nested_s_prime_commitment: nested_g,
            },
            mesh_wy: MeshWyProof {
                mesh_wy: zero_structured_host.clone(),
                mesh_wy_blind: host_blind,
                mesh_wy_commitment: host_g,
            },
            error: ErrorProof {
                native_error_m_rx: zero_structured_host.clone(),
                native_error_m_blind: host_blind,
                native_error_m_commitment: host_g,
                nested_error_m_rx: zero_structured_nested.clone(),
                nested_error_m_blind: nested_blind,
                nested_error_m_commitment: nested_g,
                native_error_n_rx: zero_structured_host.clone(),
                native_error_n_blind: host_blind,
                native_error_n_commitment: host_g,
                nested_error_n_rx: zero_structured_nested.clone(),
                nested_error_n_blind: nested_blind,
                nested_error_n_commitment: nested_g,
            },
            ab: ABProof {
                a: zero_structured_host.clone(),
                a_blind: host_blind,
                a_commitment: host_g,
                b: zero_structured_host.clone(),
                b_blind: host_blind,
                b_commitment: host_g,
                nested_ab_rx: zero_structured_nested.clone(),
                nested_ab_blind: nested_blind,
                nested_ab_commitment: nested_g,
            },
            mesh_xy: MeshXyProof {
                mesh_xy: zero_unstructured.clone(),
                mesh_xy_blind: host_blind,
                mesh_xy_commitment: host_g,
            },
            query: QueryProof {
                native_query_rx: zero_structured_host.clone(),
                native_query_blind: host_blind,
                native_query_commitment: host_g,
                nested_query_rx: zero_structured_nested.clone(),
                nested_query_blind: nested_blind,
                nested_query_commitment: nested_g,
            },
            f: FProof {
                native_f_rx: zero_unstructured.clone(),
                native_f_blind: host_blind,
                native_f_commitment: host_g,
                nested_f_rx: zero_structured_nested.clone(),
                nested_f_blind: nested_blind,
                nested_f_commitment: nested_g,
            },
            p: PProof {
                p: zero_unstructured.clone(),
                p_blind: host_blind,
                p_commitment: host_g,
            },
            eval: EvalProof {
                native_eval_rx: zero_structured_host.clone(),
                native_eval_blind: host_blind,
                native_eval_commitment: host_g,
                nested_eval_rx: zero_structured_nested.clone(),
                nested_eval_blind: nested_blind,
                nested_eval_commitment: nested_g,
            },
            internal_circuits: InternalCircuits {
                w: C::CircuitField::ZERO,
                y: C::CircuitField::ZERO,
                z: C::CircuitField::ZERO,
                c: C::CircuitField::ZERO,
                c_rx: dummy_rx.clone(),
                c_rx_blind: host_blind,
                c_rx_commitment: dummy_commitment,
                v: C::CircuitField::ZERO,
                v_rx: dummy_rx.clone(),
                v_rx_blind: host_blind,
                v_rx_commitment: dummy_commitment,
                hashes_1_rx: dummy_rx.clone(),
                hashes_1_rx_blind: host_blind,
                hashes_1_rx_commitment: dummy_commitment,
                hashes_2_rx: dummy_rx.clone(),
                hashes_2_rx_blind: host_blind,
                hashes_2_rx_commitment: dummy_commitment,
                ky_rx: dummy_rx.clone(),
                ky_rx_blind: host_blind,
                ky_rx_commitment: dummy_commitment,
                mu: C::CircuitField::ZERO,
                nu: C::CircuitField::ZERO,
                mu_prime: C::CircuitField::ZERO,
                nu_prime: C::CircuitField::ZERO,
                x: C::CircuitField::ZERO,
                alpha: C::CircuitField::ZERO,
                u: C::CircuitField::ZERO,
                beta: C::CircuitField::ZERO,
            },
            application: ApplicationProof {
                circuit_id: dummy_circuit_id,
                left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                rx: dummy_rx,
                blind: host_blind,
                commitment: dummy_commitment,
            },
        }
    }
}
