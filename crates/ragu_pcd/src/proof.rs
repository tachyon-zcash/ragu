use arithmetic::{Cycle, FixedGenerators};
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    mesh::CircuitIndex,
    polynomials::{Rank, structured},
    staging::StageExt,
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, Len},
};
use rand::{Rng, rngs::OsRng};

use alloc::{vec, vec::Vec};

use crate::{
    Application,
    components::fold_revdot::{self, ErrorTermsLen},
    header::Header,
    internal_circuits::{self, NUM_NATIVE_REVDOT_CLAIMS, dummy, stages},
};

/// Represents a recursive proof for the correctness of some computation.
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) preamble: PreambleProof<C, R>,
    pub(crate) query: QueryProof<C, R>,
    pub(crate) f: FProof<C, R>,
    pub(crate) eval: EvalProof<C, R>,
    pub(crate) internal_circuits: InternalCircuits<C, R>,
    pub(crate) application: ApplicationProof<C, R>,
}

pub(crate) struct ApplicationProof<C: Cycle, R: Rank> {
    pub(crate) circuit_id: CircuitIndex,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,
    pub(crate) rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) blind: C::CircuitField,
    pub(crate) commitment: C::HostCurve,
}

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

pub(crate) struct InternalCircuits<C: Cycle, R: Rank> {
    pub(crate) w: C::CircuitField,
    pub(crate) c: C::CircuitField,
    pub(crate) c_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) c_rx_blind: C::CircuitField,
    pub(crate) c_rx_commitment: C::HostCurve,
    pub(crate) v_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) v_rx_blind: C::CircuitField,
    pub(crate) v_rx_commitment: C::HostCurve,
    pub(crate) mu: C::CircuitField,
    pub(crate) nu: C::CircuitField,
    pub(crate) alpha: C::CircuitField,
    pub(crate) u: C::CircuitField,
}

pub(crate) struct QueryProof<C: Cycle, R: Rank> {
    pub(crate) native_query_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_query_blind: C::CircuitField,
    pub(crate) native_query_commitment: C::HostCurve,

    pub(crate) nested_query_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_query_blind: C::ScalarField,
    pub(crate) nested_query_commitment: C::NestedCurve,
}

pub(crate) struct FProof<C: Cycle, R: Rank> {
    pub(crate) native_f_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_f_blind: C::CircuitField,
    pub(crate) native_f_commitment: C::HostCurve,

    pub(crate) nested_f_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_f_blind: C::ScalarField,
    pub(crate) nested_f_commitment: C::NestedCurve,
}

pub(crate) struct EvalProof<C: Cycle, R: Rank> {
    pub(crate) native_eval_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_eval_blind: C::CircuitField,
    pub(crate) native_eval_commitment: C::HostCurve,

    pub(crate) nested_eval_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_eval_blind: C::ScalarField,
    pub(crate) nested_eval_commitment: C::NestedCurve,
}

impl<C: Cycle, R: Rank> Clone for Proof<C, R> {
    fn clone(&self) -> Self {
        Proof {
            preamble: self.preamble.clone(),
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

impl<C: Cycle, R: Rank> Clone for InternalCircuits<C, R> {
    fn clone(&self) -> Self {
        InternalCircuits {
            w: self.w,
            c: self.c,
            c_rx: self.c_rx.clone(),
            c_rx_blind: self.c_rx_blind,
            c_rx_commitment: self.c_rx_commitment,
            v_rx: self.v_rx.clone(),
            v_rx_blind: self.v_rx_blind,
            v_rx_commitment: self.v_rx_commitment,
            mu: self.mu,
            nu: self.nu,
            alpha: self.alpha,
            u: self.u,
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
            internal_circuits: InternalCircuits {
                w: C::CircuitField::random(&mut *rng),
                c: C::CircuitField::random(&mut *rng),
                c_rx: c_rx_dummy_rx.clone(),
                c_rx_blind: c_rx_dummy_blind,
                c_rx_commitment: c_rx_dummy_commitment,
                v_rx: v_rx_dummy_rx.clone(),
                v_rx_blind: v_rx_dummy_blind,
                v_rx_commitment: v_rx_dummy_commitment,
                mu: C::CircuitField::random(&mut *rng),
                nu: C::CircuitField::random(&mut *rng),
                alpha: C::CircuitField::random(&mut *rng),
                u: C::CircuitField::random(&mut *rng),
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
        let w =
            crate::components::transcript::emulate_w::<C>(nested_preamble_commitment, self.params)?;

        // Generate dummy values for mu, nu, and error_terms (for now – these will be derived challenges)
        let mu = C::CircuitField::random(&mut *rng);
        let nu = C::CircuitField::random(&mut *rng);
        let error_terms = ErrorTermsLen::<NUM_NATIVE_REVDOT_CLAIMS>::range()
            .map(|_| C::CircuitField::random(&mut *rng))
            .collect_fixed()?;

        // Compute c, the folded revdot product claim, by invoking the routine within a wireless emulator.
        let c = Emulator::emulate_wireless((mu, nu, &error_terms), |dr, witness| {
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

        // Compute query witness (stubbed for now).
        let query_witness = internal_circuits::stages::native::query::Witness {
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
        let alpha = crate::components::transcript::emulate_alpha::<C>(
            nested_query_commitment,
            self.params,
        )?;

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
        let u =
            crate::components::transcript::emulate_u::<C>(alpha, nested_f_commitment, self.params)?;

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

        // Create unified instance and compute c_rx
        let unified_instance = internal_circuits::unified::Instance {
            nested_preamble_commitment,
            w,
            c,
            mu,
            nu,
            nested_query_commitment,
            alpha,
            nested_f_commitment,
            u,
            nested_eval_commitment,
        };
        let internal_circuit_c =
            internal_circuits::c::Circuit::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::new(
                self.params,
                self.log2_domain_size(),
            );
        let internal_circuit_c_witness = internal_circuits::c::Witness {
            unified_instance: &unified_instance,
            preamble_witness: &preamble_witness,
            error_terms,
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
            internal_circuits: InternalCircuits {
                w,
                c,
                c_rx,
                c_rx_blind,
                c_rx_commitment,
                v_rx,
                v_rx_blind,
                v_rx_commitment,
                mu,
                nu,
                alpha,
                u,
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
