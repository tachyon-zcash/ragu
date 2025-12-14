use arithmetic::{Cycle, FixedGenerators};
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    mesh::CircuitIndex,
    polynomials::{Rank, structured, unstructured},
    staging::StageExt,
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{
    Element, Point,
    vec::{CollectFixed, Len},
};
use rand::{Rng, rngs::OsRng};

use alloc::{vec, vec::Vec};

use crate::{
    Application, circuit_counts,
    components::{
        fold_revdot::{self, ErrorTermsLen},
        transcript::TranscriptEmulator,
    },
    header::Header,
    internal_circuits::{self, NUM_NATIVE_REVDOT_CLAIMS, dummy, stages},
};

/// Represents a recursive proof for the correctness of some computation.
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) preamble: PreambleProof<C, R>,
    pub(crate) s_prime: SPrimeProof<C, R>,
    pub(crate) s_doubleprime: SDoublePrimeProof<C, R>,
    pub(crate) error: ErrorProof<C, R>,
    pub(crate) ab: ABProof<C, R>,
    pub(crate) s: SProof<C, R>,
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

/// Fiat-Shamir challenges and C/V circuit polynomials.
pub(crate) struct InternalCircuits<C: Cycle, R: Rank> {
    pub(crate) w: C::CircuitField,
    pub(crate) y: C::CircuitField,
    pub(crate) z: C::CircuitField,
    pub(crate) c: C::CircuitField,
    pub(crate) c_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) c_rx_blind: C::CircuitField,
    pub(crate) c_rx_commitment: C::HostCurve,
    pub(crate) v_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) v_rx_blind: C::CircuitField,
    pub(crate) v_rx_commitment: C::HostCurve,
    pub(crate) mu: C::CircuitField,
    pub(crate) nu: C::CircuitField,
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
pub(crate) struct FProof<C: Cycle, R: Rank> {
    pub(crate) native_f_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_f_blind: C::CircuitField,
    pub(crate) native_f_commitment: C::HostCurve,

    pub(crate) nested_f_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_f_blind: C::ScalarField,
    pub(crate) nested_f_commitment: C::NestedCurve,
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

/// Error stage proof with native and nested layer commitments.
pub(crate) struct ErrorProof<C: Cycle, R: Rank> {
    pub(crate) native_error_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_error_blind: C::CircuitField,
    pub(crate) native_error_commitment: C::HostCurve,

    pub(crate) nested_error_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_error_blind: C::ScalarField,
    pub(crate) nested_error_commitment: C::NestedCurve,
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

/// S'' stage proof: m(w, X, y) and nested commitment.
pub(crate) struct SDoublePrimeProof<C: Cycle, R: Rank> {
    pub(crate) mesh_wy: structured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_wy_blind: C::CircuitField,
    pub(crate) mesh_wy_commitment: C::HostCurve,

    pub(crate) nested_s_doubleprime_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_s_doubleprime_blind: C::ScalarField,
    pub(crate) nested_s_doubleprime_commitment: C::NestedCurve,
}

/// S stage proof: m(x, y) and nested commitment.
pub(crate) struct SProof<C: Cycle, R: Rank> {
    pub(crate) mesh_xy: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_xy_blind: C::CircuitField,
    pub(crate) mesh_xy_commitment: C::HostCurve,

    pub(crate) nested_s_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_s_blind: C::ScalarField,
    pub(crate) nested_s_commitment: C::NestedCurve,
}

impl<C: Cycle, R: Rank> Clone for Proof<C, R> {
    fn clone(&self) -> Self {
        Proof {
            preamble: self.preamble.clone(),
            s_prime: self.s_prime.clone(),
            s_doubleprime: self.s_doubleprime.clone(),
            error: self.error.clone(),
            ab: self.ab.clone(),
            s: self.s.clone(),
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

impl<C: Cycle, R: Rank> Clone for SDoublePrimeProof<C, R> {
    fn clone(&self) -> Self {
        SDoublePrimeProof {
            mesh_wy: self.mesh_wy.clone(),
            mesh_wy_blind: self.mesh_wy_blind,
            mesh_wy_commitment: self.mesh_wy_commitment,
            nested_s_doubleprime_rx: self.nested_s_doubleprime_rx.clone(),
            nested_s_doubleprime_blind: self.nested_s_doubleprime_blind,
            nested_s_doubleprime_commitment: self.nested_s_doubleprime_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for SProof<C, R> {
    fn clone(&self) -> Self {
        SProof {
            mesh_xy: self.mesh_xy.clone(),
            mesh_xy_blind: self.mesh_xy_blind,
            mesh_xy_commitment: self.mesh_xy_commitment,
            nested_s_rx: self.nested_s_rx.clone(),
            nested_s_blind: self.nested_s_blind,
            nested_s_commitment: self.nested_s_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ErrorProof<C, R> {
    fn clone(&self) -> Self {
        ErrorProof {
            native_error_rx: self.native_error_rx.clone(),
            native_error_blind: self.native_error_blind,
            native_error_commitment: self.native_error_commitment,
            nested_error_rx: self.nested_error_rx.clone(),
            nested_error_blind: self.nested_error_blind,
            nested_error_commitment: self.nested_error_commitment,
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
            mu: self.mu,
            nu: self.nu,
            x: self.x,
            alpha: self.alpha,
            u: self.u,
            beta: self.beta,
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
    /// Creates a trivial proof for the empty [`Header`] implementation `()`.
    /// This may or may not be identical to any previously constructed (trivial)
    /// proof, and so is not guaranteed to be freshly randomized.
    pub fn trivial(&self) -> Proof<C, R> {
        self.try_trivial(&mut OsRng)
            .expect("trivial proof generation should not fail")
    }

    fn try_trivial<RNG: Rng>(&self, rng: &mut RNG) -> Result<Proof<C, R>> {
        // Create a long-lived emulator and transcript for Fiat-Shamir challenge derivation.
        // All challenges are derived from this single transcript, ensuring proper binding.
        let mut em = Emulator::execute();
        let mut transcript = TranscriptEmulator::<_, C>::new(&mut em, self.params);

        // Dummy application rx commitment
        let application_rx = dummy::Circuit
            .rx((), self.circuit_mesh.get_key())
            .expect("should not fail")
            .0;
        let application_blind = C::CircuitField::random(&mut *rng);
        let application_commitment =
            application_rx.commit(self.params.host_generators(), application_blind);

        // Dummy c_rx commitment
        let c_rx_dummy_rx = dummy::Circuit
            .rx((), self.circuit_mesh.get_key())
            .expect("should not fail")
            .0;
        let c_rx_dummy_blind = C::CircuitField::random(&mut *rng);
        let c_rx_dummy_commitment =
            c_rx_dummy_rx.commit(self.params.host_generators(), c_rx_dummy_blind);

        // Dummy v_rx commitment
        let v_rx_dummy_rx = dummy::Circuit
            .rx((), self.circuit_mesh.get_key())
            .expect("should not fail")
            .0;
        let v_rx_dummy_blind = C::CircuitField::random(&mut *rng);
        let v_rx_dummy_commitment =
            v_rx_dummy_rx.commit(self.params.host_generators(), v_rx_dummy_blind);

        // Create a dummy proof to use for preamble witness.
        // The preamble witness needs proof references, but we're creating a trivial proof
        // from scratch, so we construct a dummy with placeholder values.
        let dummy_circuit_id = dummy::CIRCUIT_ID.circuit_index(self.num_application_steps);

        let dummy_proof = Proof {
            preamble: PreambleProof {
                native_preamble_rx: application_rx.clone(),
                native_preamble_blind: C::CircuitField::random(&mut *rng),
                native_preamble_commitment: application_commitment,
                nested_preamble_rx: structured::Polynomial::new(),
                nested_preamble_blind: C::ScalarField::random(&mut *rng),
                nested_preamble_commitment: self.params.nested_generators().g()[0],
            },
            s_prime: SPrimeProof {
                mesh_wx0: unstructured::Polynomial::new(),
                mesh_wx0_blind: C::CircuitField::random(&mut *rng),
                mesh_wx0_commitment: self.params.host_generators().g()[0],
                mesh_wx1: unstructured::Polynomial::new(),
                mesh_wx1_blind: C::CircuitField::random(&mut *rng),
                mesh_wx1_commitment: self.params.host_generators().g()[0],
                nested_s_prime_rx: structured::Polynomial::new(),
                nested_s_prime_blind: C::ScalarField::random(&mut *rng),
                nested_s_prime_commitment: self.params.nested_generators().g()[0],
            },
            s_doubleprime: SDoublePrimeProof {
                mesh_wy: structured::Polynomial::new(),
                mesh_wy_blind: C::CircuitField::random(&mut *rng),
                mesh_wy_commitment: self.params.host_generators().g()[0],
                nested_s_doubleprime_rx: structured::Polynomial::new(),
                nested_s_doubleprime_blind: C::ScalarField::random(&mut *rng),
                nested_s_doubleprime_commitment: self.params.nested_generators().g()[0],
            },
            error: ErrorProof {
                native_error_rx: structured::Polynomial::new(),
                native_error_blind: C::CircuitField::random(&mut *rng),
                native_error_commitment: self.params.host_generators().g()[0],
                nested_error_rx: structured::Polynomial::new(),
                nested_error_blind: C::ScalarField::random(&mut *rng),
                nested_error_commitment: self.params.nested_generators().g()[0],
            },
            ab: ABProof {
                a: structured::Polynomial::new(),
                a_blind: C::CircuitField::random(&mut *rng),
                a_commitment: self.params.host_generators().g()[0],
                b: structured::Polynomial::new(),
                b_blind: C::CircuitField::random(&mut *rng),
                b_commitment: self.params.host_generators().g()[0],
                nested_ab_rx: structured::Polynomial::new(),
                nested_ab_blind: C::ScalarField::random(&mut *rng),
                nested_ab_commitment: self.params.nested_generators().g()[0],
            },
            s: SProof {
                mesh_xy: unstructured::Polynomial::new(),
                mesh_xy_blind: C::CircuitField::random(&mut *rng),
                mesh_xy_commitment: self.params.host_generators().g()[0],
                nested_s_rx: structured::Polynomial::new(),
                nested_s_blind: C::ScalarField::random(&mut *rng),
                nested_s_commitment: self.params.nested_generators().g()[0],
            },
            internal_circuits: InternalCircuits {
                w: C::CircuitField::random(&mut *rng),
                y: C::CircuitField::random(&mut *rng),
                z: C::CircuitField::random(&mut *rng),
                c: C::CircuitField::random(&mut *rng),
                c_rx: c_rx_dummy_rx.clone(),
                c_rx_blind: c_rx_dummy_blind,
                c_rx_commitment: c_rx_dummy_commitment,
                v_rx: v_rx_dummy_rx.clone(),
                v_rx_blind: v_rx_dummy_blind,
                v_rx_commitment: v_rx_dummy_commitment,
                mu: C::CircuitField::random(&mut *rng),
                nu: C::CircuitField::random(&mut *rng),
                x: C::CircuitField::random(&mut *rng),
                alpha: C::CircuitField::random(&mut *rng),
                u: C::CircuitField::random(&mut *rng),
                beta: C::CircuitField::random(&mut *rng),
            },
            application: ApplicationProof {
                circuit_id: dummy_circuit_id,
                left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                rx: application_rx.clone(),
                blind: C::CircuitField::random(&mut *rng),
                commitment: application_commitment,
            },
            query: QueryProof {
                native_query_rx: structured::Polynomial::new(),
                native_query_blind: C::CircuitField::random(&mut *rng),
                native_query_commitment: self.params.host_generators().g()[0],
                nested_query_rx: structured::Polynomial::new(),
                nested_query_blind: C::ScalarField::random(&mut *rng),
                nested_query_commitment: self.params.nested_generators().g()[0],
            },
            f: FProof {
                native_f_rx: structured::Polynomial::new(),
                native_f_blind: C::CircuitField::random(&mut *rng),
                native_f_commitment: self.params.host_generators().g()[0],
                nested_f_rx: structured::Polynomial::new(),
                nested_f_blind: C::ScalarField::random(&mut *rng),
                nested_f_commitment: self.params.nested_generators().g()[0],
            },
            eval: EvalProof {
                native_eval_rx: structured::Polynomial::new(),
                native_eval_blind: C::CircuitField::random(&mut *rng),
                native_eval_commitment: self.params.host_generators().g()[0],
                nested_eval_rx: structured::Polynomial::new(),
                nested_eval_blind: C::ScalarField::random(&mut *rng),
                nested_eval_commitment: self.params.nested_generators().g()[0],
            },
        };

        // Preamble witness with zero output headers and dummy proof references.
        let preamble_witness = stages::native::preamble::Witness::new(
            &dummy_proof,
            &dummy_proof,
            [C::CircuitField::ZERO; HEADER_SIZE],
            [C::CircuitField::ZERO; HEADER_SIZE],
        );

        let native_preamble_rx =
            stages::native::preamble::Stage::<C, R, HEADER_SIZE>::rx(&preamble_witness)
                .expect("preamble rx should not fail");
        let native_preamble_blind = C::CircuitField::random(&mut *rng);
        let native_preamble_commitment =
            native_preamble_rx.commit(self.params.host_generators(), native_preamble_blind);

        let nested_preamble_points: [C::HostCurve; 7] = [
            native_preamble_commitment,
            application_commitment,
            application_commitment,
            // placeholder for left.c_rx_commitment and right.c_rx_commitment
            c_rx_dummy_commitment,
            c_rx_dummy_commitment,
            // placeholder for left.v_rx_commitment and right.v_rx_commitment
            v_rx_dummy_commitment,
            v_rx_dummy_commitment,
        ];

        // Nested preamble rx polynomial
        let nested_preamble_rx =
            stages::nested::preamble::Stage::<C::HostCurve, R, 7>::rx(&nested_preamble_points)?;
        let nested_preamble_blind = C::ScalarField::random(&mut *rng);
        let nested_preamble_commitment =
            nested_preamble_rx.commit(self.params.nested_generators(), nested_preamble_blind);

        // Compute w = H(nested_preamble_commitment)
        let nested_preamble_point = Point::constant(&mut em, nested_preamble_commitment)?;
        let w = *transcript
            .derive_w(&mut em, &nested_preamble_point)?
            .value()
            .take();

        // We compute a nested commitment to s' = m(w, x_i, Y).
        let mesh_wx0 = unstructured::Polynomial::new();
        let mesh_wx0_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx0_commitment = self.params.host_generators().g()[0];
        let mesh_wx1 = unstructured::Polynomial::new();
        let mesh_wx1_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx1_commitment = self.params.host_generators().g()[0];
        let nested_s_prime_rx = stages::nested::s_prime::Stage::<C::HostCurve, R, 2>::rx(&[
            mesh_wx0_commitment,
            mesh_wx1_commitment,
        ])?;
        let nested_s_prime_blind = C::ScalarField::random(&mut *rng);
        let nested_s_prime_commitment =
            nested_s_prime_rx.commit(self.params.nested_generators(), nested_s_prime_blind);

        // Derive (y, z) = H(w, nested_s_prime_commitment).
        let nested_s_prime_point = Point::constant(&mut em, nested_s_prime_commitment)?;
        let (y_elem, z_elem) = transcript.derive_y_z(&mut em, &nested_s_prime_point)?;
        let y = *y_elem.value().take();
        let z = *z_elem.value().take();

        // We compute a nested commitment to S'' = m(w, X, y).
        let mesh_wy = structured::Polynomial::new();
        let mesh_wy_blind = C::CircuitField::random(&mut *rng);
        let mesh_wy_commitment = self.params.host_generators().g()[0];
        let nested_s_doubleprime_rx =
            stages::nested::s_doubleprime::Stage::<C::HostCurve, R>::rx(mesh_wy_commitment)?;
        let nested_s_doubleprime_blind = C::ScalarField::random(&mut *rng);
        let nested_s_doubleprime_commitment = nested_s_doubleprime_rx
            .commit(self.params.nested_generators(), nested_s_doubleprime_blind);

        // Compute error stage first so we can derive mu/nu from nested_error_commitment.
        // Create error witness with dummy z and error terms.
        let error_witness = stages::native::error::Witness::<C, NUM_NATIVE_REVDOT_CLAIMS> {
            z,
            nested_s_doubleprime_commitment,
            error_terms: ErrorTermsLen::<NUM_NATIVE_REVDOT_CLAIMS>::range()
                .map(|_| C::CircuitField::ZERO)
                .collect_fixed()?,
        };
        let native_error_rx =
            stages::native::error::Stage::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::rx(
                &error_witness,
            )?;
        let native_error_blind = C::CircuitField::random(&mut *rng);
        let native_error_commitment =
            native_error_rx.commit(self.params.host_generators(), native_error_blind);

        // Stubbed nested error rx polynomial
        let nested_error_rx =
            stages::nested::error::Stage::<C::HostCurve, R>::rx(native_error_commitment)?;
        let nested_error_blind = C::ScalarField::random(&mut *rng);
        let nested_error_commitment =
            nested_error_rx.commit(self.params.nested_generators(), nested_error_blind);

        // Derive (mu, nu) = H(nested_error_commitment)
        let nested_error_point = Point::constant(&mut em, nested_error_commitment)?;
        let (mu_elem, nu_elem) = transcript.derive_mu_nu(&mut em, &nested_error_point)?;
        let mu = *mu_elem.value().take();
        let nu = *nu_elem.value().take();

        // Compute c, the folded revdot product claim, by invoking the routine within a wireless emulator.
        let c = Emulator::emulate_wireless((mu, nu, &error_witness.error_terms), |dr, witness| {
            let (mu, nu, error_terms) = witness.cast();

            let mu = Element::alloc(dr, mu)?;
            let nu = Element::alloc(dr, nu)?;

            let error_terms = ErrorTermsLen::<NUM_NATIVE_REVDOT_CLAIMS>::range()
                .map(|i| Element::alloc(dr, error_terms.view().map(|et| et[i])))
                .try_collect_fixed()?;

            // TODO: Use zeros for ky_values for now.
            let ky_values = (0..NUM_NATIVE_REVDOT_CLAIMS)
                .map(|_| Element::zero(dr))
                .collect_fixed()?;

            Ok(*fold_revdot::compute_c::<_, NUM_NATIVE_REVDOT_CLAIMS>(
                dr,
                &mu,
                &nu,
                &error_terms,
                &ky_values,
            )?
            .value()
            .take())
        })?;

        // Compute the A/B polynomials (depend on mu, nu).
        // TODO: For now, stub out fake A and B polynomials.
        let a = ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
        let b = ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();

        // Commit to A and B, then create the nested commitment.
        let a_blind = C::CircuitField::random(&mut *rng);
        let a_commitment = a.commit(self.params.host_generators(), a_blind);
        let b_blind = C::CircuitField::random(&mut *rng);
        let b_commitment = b.commit(self.params.host_generators(), b_blind);

        let nested_ab_rx =
            stages::nested::ab::Stage::<C::HostCurve, R, 2>::rx(&[a_commitment, b_commitment])?;
        let nested_ab_blind = C::ScalarField::random(&mut *rng);
        let nested_ab_commitment =
            nested_ab_rx.commit(self.params.nested_generators(), nested_ab_blind);

        // Derive x = H(nu, nested_ab_commitment).
        let nested_ab_point = Point::constant(&mut em, nested_ab_commitment)?;
        let x = *transcript
            .derive_x(&mut em, &nested_ab_point)?
            .value()
            .take();

        // Compute commitment to mesh polynomial at (x, y).
        let mesh_xy = unstructured::Polynomial::new();
        let mesh_xy_blind = C::CircuitField::random(&mut *rng);
        let mesh_xy_commitment = self.params.host_generators().g()[0];

        let nested_s_rx = stages::nested::s::Stage::<C::HostCurve, R>::rx(mesh_xy_commitment)?;
        let nested_s_blind = C::ScalarField::random(&mut *rng);
        let nested_s_commitment =
            nested_s_rx.commit(self.params.nested_generators(), nested_s_blind);

        // Compute query witness (stubbed for now).
        let query_witness = internal_circuits::stages::native::query::Witness {
            x,
            nested_s_commitment,
            queries: internal_circuits::stages::native::query::Queries::range()
                .map(|_| C::CircuitField::ZERO)
                .collect_fixed()?,
        };

        let native_query_rx =
            internal_circuits::stages::native::query::Stage::<C, R, HEADER_SIZE>::rx(
                &query_witness,
            )?;
        let native_query_blind = C::CircuitField::random(&mut *rng);
        let native_query_commitment =
            native_query_rx.commit(self.params.host_generators(), native_query_blind);

        let nested_query_rx =
            internal_circuits::stages::nested::query::Stage::<C::HostCurve, R>::rx(
                native_query_commitment,
            )?;
        let nested_query_blind = C::ScalarField::random(&mut *rng);
        let nested_query_commitment =
            nested_query_rx.commit(self.params.nested_generators(), nested_query_blind);

        // Derive challenge alpha = H(nested_query_commitment).
        let nested_query_point = Point::constant(&mut em, nested_query_commitment)?;
        let alpha = *transcript
            .derive_alpha(&mut em, &nested_query_point)?
            .value()
            .take();

        // Compute the F polynomial commitment (stubbed for now).
        let native_f_rx =
            ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
        let native_f_blind = C::CircuitField::random(&mut *rng);
        let native_f_commitment = native_f_rx.commit(self.params.host_generators(), native_f_blind);

        let nested_f_rx = internal_circuits::stages::nested::f::Stage::<C::HostCurve, R>::rx(
            native_f_commitment,
        )?;
        let nested_f_blind = C::ScalarField::random(&mut *rng);
        let nested_f_commitment =
            nested_f_rx.commit(self.params.nested_generators(), nested_f_blind);

        // Derive u = H(alpha, nested_f_commitment).
        let nested_f_point = Point::constant(&mut em, nested_f_commitment)?;
        let u = *transcript
            .derive_u(&mut em, &nested_f_point)?
            .value()
            .take();

        // Compute eval witness (stubbed for now).
        let eval_witness = internal_circuits::stages::native::eval::Witness {
            u,
            evals: internal_circuits::stages::native::eval::Evals::range()
                .map(|_| C::CircuitField::ZERO)
                .collect_fixed()?,
        };
        let native_eval_rx =
            internal_circuits::stages::native::eval::Stage::<C, R, HEADER_SIZE>::rx(&eval_witness)?;
        let native_eval_blind = C::CircuitField::random(&mut *rng);
        let native_eval_commitment =
            native_eval_rx.commit(self.params.host_generators(), native_eval_blind);

        let nested_eval_rx = internal_circuits::stages::nested::eval::Stage::<C::HostCurve, R>::rx(
            native_eval_commitment,
        )?;
        let nested_eval_blind = C::ScalarField::random(&mut *rng);
        let nested_eval_commitment =
            nested_eval_rx.commit(self.params.nested_generators(), nested_eval_blind);

        // Derive beta = H(nested_eval_commitment).
        let nested_eval_point = Point::constant(&mut em, nested_eval_commitment)?;
        let beta = *transcript
            .derive_beta(&mut em, &nested_eval_point)?
            .value()
            .take();

        // Create unified instance and compute c_rx
        let unified_instance = internal_circuits::unified::Instance {
            nested_preamble_commitment,
            w,
            nested_s_prime_commitment,
            y,
            z,
            nested_s_doubleprime_commitment,
            nested_error_commitment,
            mu,
            nu,
            c,
            nested_ab_commitment,
            x,
            nested_s_commitment,
            nested_query_commitment,
            alpha,
            nested_f_commitment,
            u,
            nested_eval_commitment,
            beta,
        };
        let internal_circuit_c =
            internal_circuits::c::Circuit::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::new(
                self.params,
                circuit_counts(self.num_application_steps).1,
            );
        let internal_circuit_c_witness = internal_circuits::c::Witness {
            unified_instance: &unified_instance,
            preamble_witness: &preamble_witness,
            error_witness: &error_witness,
        };

        // Compute c_rx using the C-staged circuit
        let (c_rx, _) =
            internal_circuit_c.rx::<R>(internal_circuit_c_witness, self.circuit_mesh.get_key())?;
        let c_rx_blind = C::CircuitField::random(&mut *rng);
        let c_rx_commitment = c_rx.commit(self.params.host_generators(), c_rx_blind);

        // Compute v_rx using the V-staged circuit
        let internal_circuit_v =
            internal_circuits::v::Circuit::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::new(
                self.params,
            );
        let internal_circuit_v_witness = internal_circuits::v::Witness {
            unified_instance: &unified_instance,
            query_witness: &query_witness,
            eval_witness: &eval_witness,
        };
        let (v_rx, _) =
            internal_circuit_v.rx::<R>(internal_circuit_v_witness, self.circuit_mesh.get_key())?;
        let v_rx_blind = C::CircuitField::random(&mut *rng);
        let v_rx_commitment = v_rx.commit(self.params.host_generators(), v_rx_blind);

        Ok(Proof {
            preamble: PreambleProof {
                native_preamble_rx,
                native_preamble_commitment,
                native_preamble_blind,
                nested_preamble_rx,
                nested_preamble_commitment,
                nested_preamble_blind,
            },
            s_prime: SPrimeProof {
                mesh_wx0,
                mesh_wx0_blind,
                mesh_wx0_commitment,
                mesh_wx1,
                mesh_wx1_blind,
                mesh_wx1_commitment,
                nested_s_prime_rx,
                nested_s_prime_blind,
                nested_s_prime_commitment,
            },
            s_doubleprime: SDoublePrimeProof {
                mesh_wy,
                mesh_wy_blind,
                mesh_wy_commitment,
                nested_s_doubleprime_rx,
                nested_s_doubleprime_blind,
                nested_s_doubleprime_commitment,
            },
            error: ErrorProof {
                native_error_rx,
                native_error_blind,
                native_error_commitment,
                nested_error_rx,
                nested_error_blind,
                nested_error_commitment,
            },
            ab: ABProof {
                a,
                a_blind,
                a_commitment,
                b,
                b_blind,
                b_commitment,
                nested_ab_rx,
                nested_ab_blind,
                nested_ab_commitment,
            },
            s: SProof {
                mesh_xy,
                mesh_xy_blind,
                mesh_xy_commitment,
                nested_s_rx,
                nested_s_blind,
                nested_s_commitment,
            },
            internal_circuits: InternalCircuits {
                w,
                y,
                z,
                c,
                c_rx,
                c_rx_blind,
                c_rx_commitment,
                v_rx,
                v_rx_blind,
                v_rx_commitment,
                mu,
                nu,
                x,
                alpha,
                u,
                beta,
            },
            application: ApplicationProof {
                rx: application_rx,
                circuit_id: dummy::CIRCUIT_ID.circuit_index(self.num_application_steps),
                left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                blind: application_blind,
                commitment: application_commitment,
            },
            query: QueryProof {
                native_query_rx,
                native_query_blind,
                native_query_commitment,
                nested_query_rx,
                nested_query_blind,
                nested_query_commitment,
            },
            f: FProof {
                native_f_rx,
                native_f_blind,
                native_f_commitment,
                nested_f_rx,
                nested_f_blind,
                nested_f_commitment,
            },
            eval: EvalProof {
                native_eval_rx,
                native_eval_blind,
                native_eval_commitment,
                nested_eval_rx,
                nested_eval_blind,
                nested_eval_commitment,
            },
        })
    }
}
