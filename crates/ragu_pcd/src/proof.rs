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

/// A committed polynomial with its blinding factor and commitment.
pub(crate) struct CommittedPolynomial<P, F, G> {
    pub(crate) poly: P,
    pub(crate) blind: F,
    pub(crate) commitment: G,
}

impl<P: Clone, F: Copy, G: Copy> Clone for CommittedPolynomial<P, F, G> {
    fn clone(&self) -> Self {
        CommittedPolynomial {
            poly: self.poly.clone(),
            blind: self.blind,
            commitment: self.commitment,
        }
    }
}

/// Native: Stage: Structured polynomials over C::CircuitField,
/// committed to C::HostCurve.
pub(crate) type NativeStructured<C, R> = CommittedPolynomial<
    structured::Polynomial<<C as Cycle>::CircuitField, R>,
    <C as Cycle>::CircuitField,
    <C as Cycle>::HostCurve,
>;

/// Native: Stage: Unstructured polynomials over C::CircuitField,
/// committed to C::HostCurve.
pub(crate) type NativeUnstructured<C, R> = CommittedPolynomial<
    unstructured::Polynomial<<C as Cycle>::CircuitField, R>,
    <C as Cycle>::CircuitField,
    <C as Cycle>::HostCurve,
>;

/// Nested Stage: Structured polynomial over C::ScalarField, committed
/// to C::NestedCurve.
pub(crate) type NestedStructured<C, R> = CommittedPolynomial<
    structured::Polynomial<<C as Cycle>::ScalarField, R>,
    <C as Cycle>::ScalarField,
    <C as Cycle>::NestedCurve,
>;

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
    pub(crate) native: NativeStructured<C, R>,
    pub(crate) nested: NestedStructured<C, R>,
}

/// Fiat-Shamir challenges and C/V/hash/ky circuit polynomials.
pub(crate) struct InternalCircuits<C: Cycle, R: Rank> {
    // Fiat-Shamir challenges
    pub(crate) w: C::CircuitField,
    pub(crate) y: C::CircuitField,
    pub(crate) z: C::CircuitField,
    pub(crate) c: C::CircuitField,
    pub(crate) mu: C::CircuitField,
    pub(crate) nu: C::CircuitField,
    pub(crate) mu_prime: C::CircuitField,
    pub(crate) nu_prime: C::CircuitField,
    pub(crate) x: C::CircuitField,
    pub(crate) alpha: C::CircuitField,
    pub(crate) u: C::CircuitField,
    pub(crate) beta: C::CircuitField,

    // Circuit polynomials
    pub(crate) c_rx: NativeStructured<C, R>,
    pub(crate) v_rx: NativeStructured<C, R>,
    pub(crate) hashes_1_rx: NativeStructured<C, R>,
    pub(crate) hashes_2_rx: NativeStructured<C, R>,
    pub(crate) ky_rx: NativeStructured<C, R>,
}

/// Query stage proof with native and nested layer commitments.
pub(crate) struct QueryProof<C: Cycle, R: Rank> {
    pub(crate) native: NativeStructured<C, R>,
    pub(crate) nested: NestedStructured<C, R>,
}

/// F polynomial proof with native and nested layer commitments.
pub(crate) struct FProof<C: Cycle, R: Rank> {
    pub(crate) native: NativeStructured<C, R>,
    pub(crate) nested: NestedStructured<C, R>,
}

/// Evaluation stage proof with native and nested layer commitments.
pub(crate) struct EvalProof<C: Cycle, R: Rank> {
    pub(crate) native: NativeStructured<C, R>,
    pub(crate) nested: NestedStructured<C, R>,
}

/// Error stage proof with native and nested layer commitments for both layers.
pub(crate) struct ErrorProof<C: Cycle, R: Rank> {
    /// Layer 1 (error_m): N instances of M-sized reductions.
    pub(crate) native_m: NativeStructured<C, R>,
    pub(crate) nested_m: NestedStructured<C, R>,

    /// Layer 2 (error_n): Single N-sized reduction.
    pub(crate) native_n: NativeStructured<C, R>,
    pub(crate) nested_n: NestedStructured<C, R>,
}

/// A/B polynomial proof for folding. A and B depend on (mu, nu).
pub(crate) struct ABProof<C: Cycle, R: Rank> {
    pub(crate) a: NativeStructured<C, R>,
    pub(crate) b: NativeStructured<C, R>,
    pub(crate) nested: NestedStructured<C, R>,
}

/// S' stage proof: m(w, x_i, Y) and nested commitment.
pub(crate) struct SPrimeProof<C: Cycle, R: Rank> {
    pub(crate) mesh_wx0: NativeUnstructured<C, R>,
    pub(crate) mesh_wx1: NativeUnstructured<C, R>,
    pub(crate) nested: NestedStructured<C, R>,
}

/// S'' stage proof: m(w, X, y).
pub(crate) struct MeshWyProof<C: Cycle, R: Rank> {
    pub(crate) mesh_wy: NativeStructured<C, R>,
}

/// Mesh m(x, y) commitment (included in nested query stage).
pub(crate) struct MeshXyProof<C: Cycle, R: Rank> {
    pub(crate) mesh_xy: NativeUnstructured<C, R>,
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
            native: self.native.clone(),
            nested: self.nested.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for SPrimeProof<C, R> {
    fn clone(&self) -> Self {
        SPrimeProof {
            mesh_wx0: self.mesh_wx0.clone(),
            mesh_wx1: self.mesh_wx1.clone(),
            nested: self.nested.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for MeshWyProof<C, R> {
    fn clone(&self) -> Self {
        MeshWyProof {
            mesh_wy: self.mesh_wy.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for MeshXyProof<C, R> {
    fn clone(&self) -> Self {
        MeshXyProof {
            mesh_xy: self.mesh_xy.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ErrorProof<C, R> {
    fn clone(&self) -> Self {
        ErrorProof {
            native_m: self.native_m.clone(),
            nested_m: self.nested_m.clone(),
            native_n: self.native_n.clone(),
            nested_n: self.nested_n.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ABProof<C, R> {
    fn clone(&self) -> Self {
        ABProof {
            a: self.a.clone(),
            b: self.b.clone(),
            nested: self.nested.clone(),
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
            mu: self.mu,
            nu: self.nu,
            mu_prime: self.mu_prime,
            nu_prime: self.nu_prime,
            x: self.x,
            alpha: self.alpha,
            u: self.u,
            beta: self.beta,
            c_rx: self.c_rx.clone(),
            v_rx: self.v_rx.clone(),
            hashes_1_rx: self.hashes_1_rx.clone(),
            hashes_2_rx: self.hashes_2_rx.clone(),
            ky_rx: self.ky_rx.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for QueryProof<C, R> {
    fn clone(&self) -> Self {
        QueryProof {
            native: self.native.clone(),
            nested: self.nested.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for FProof<C, R> {
    fn clone(&self) -> Self {
        FProof {
            native: self.native.clone(),
            nested: self.nested.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for EvalProof<C, R> {
    fn clone(&self) -> Self {
        EvalProof {
            native: self.native.clone(),
            nested: self.nested.clone(),
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

        // Zero committed polynomials
        let zero_native_structured = || CommittedPolynomial {
            poly: zero_structured_host.clone(),
            blind: host_blind,
            commitment: host_g,
        };
        let zero_nested_structured = || CommittedPolynomial {
            poly: zero_structured_nested.clone(),
            blind: nested_blind,
            commitment: nested_g,
        };
        let zero_native_unstructured = || CommittedPolynomial {
            poly: zero_unstructured.clone(),
            blind: host_blind,
            commitment: host_g,
        };

        // Dummy circuit rx for application field
        let dummy_rx = dummy::Circuit
            .rx((), self.circuit_mesh.get_key())
            .expect("dummy circuit rx should not fail")
            .0;
        let dummy_commitment = dummy_rx.commit(self.params.host_generators(), host_blind);
        let dummy_circuit_id = dummy::CIRCUIT_ID.circuit_index(self.num_application_steps);

        let dummy_native_structured = || CommittedPolynomial {
            poly: dummy_rx.clone(),
            blind: host_blind,
            commitment: dummy_commitment,
        };

        Proof {
            preamble: PreambleProof {
                native: zero_native_structured(),
                nested: zero_nested_structured(),
            },
            s_prime: SPrimeProof {
                mesh_wx0: zero_native_unstructured(),
                mesh_wx1: zero_native_unstructured(),
                nested: zero_nested_structured(),
            },
            mesh_wy: MeshWyProof {
                mesh_wy: zero_native_structured(),
            },
            error: ErrorProof {
                native_m: zero_native_structured(),
                nested_m: zero_nested_structured(),
                native_n: zero_native_structured(),
                nested_n: zero_nested_structured(),
            },
            ab: ABProof {
                a: zero_native_structured(),
                b: zero_native_structured(),
                nested: zero_nested_structured(),
            },
            mesh_xy: MeshXyProof {
                mesh_xy: zero_native_unstructured(),
            },
            query: QueryProof {
                native: zero_native_structured(),
                nested: zero_nested_structured(),
            },
            f: FProof {
                native: zero_native_structured(),
                nested: zero_nested_structured(),
            },
            eval: EvalProof {
                native: zero_native_structured(),
                nested: zero_nested_structured(),
            },
            internal_circuits: InternalCircuits {
                w: C::CircuitField::ZERO,
                y: C::CircuitField::ZERO,
                z: C::CircuitField::ZERO,
                c: C::CircuitField::ZERO,
                mu: C::CircuitField::ZERO,
                nu: C::CircuitField::ZERO,
                mu_prime: C::CircuitField::ZERO,
                nu_prime: C::CircuitField::ZERO,
                x: C::CircuitField::ZERO,
                alpha: C::CircuitField::ZERO,
                u: C::CircuitField::ZERO,
                beta: C::CircuitField::ZERO,
                c_rx: dummy_native_structured(),
                v_rx: dummy_native_structured(),
                hashes_1_rx: dummy_native_structured(),
                hashes_2_rx: dummy_native_structured(),
                ky_rx: dummy_native_structured(),
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
