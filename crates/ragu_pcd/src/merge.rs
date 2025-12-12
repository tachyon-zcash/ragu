use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{CircuitExt, polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, Len},
};
use rand::Rng;

use crate::{
    Application,
    components::fold_revdot::{self, ErrorTermsLen},
    internal_circuits::{self, NUM_NATIVE_REVDOT_CLAIMS, stages, unified},
    proof::{
        ApplicationProof, EvalProof, FProof, InternalCircuits, Pcd, PreambleProof, Proof,
        QueryProof,
    },
    step::{Step, adapter::Adapter},
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Merge two PCD into one using a provided [`Step`].
    ///
    /// ## Parameters
    ///
    /// * `rng`: a random number generator used to sample randomness during
    ///   proof generation. The fact that this method takes a random number
    ///   generator is not an indication that the resulting proof-carrying data
    ///   is zero-knowledge; that must be ensured by performing
    ///   [`Application::rerandomize`] at a later point.
    /// * `step`: the [`Step`] instance that has been registered in this
    ///   [`Application`].
    /// * `witness`: the witness data for the [`Step`]
    /// * `left`: the left PCD to merge in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right PCD to merge in this step; must correspond to the
    ///   [`Step::Right`] header.
    pub fn merge<'source, RNG: Rng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        let host_generators = self.params.host_generators();
        let nested_generators = self.params.nested_generators();

        // Create preamble witness from PCDs.
        let preamble_witness = stages::native::preamble::Witness::from_pcds(&left, &right)?;

        // Compute native preamble
        let native_preamble_rx =
            stages::native::preamble::Stage::<C, R, HEADER_SIZE>::rx(&preamble_witness)?;
        let native_preamble_blind = C::CircuitField::random(&mut *rng);
        let native_preamble_commitment =
            native_preamble_rx.commit(host_generators, native_preamble_blind);

        let nested_preamble_points: [C::HostCurve; 7] = [
            native_preamble_commitment,
            left.proof.application.commitment,
            right.proof.application.commitment,
            left.proof.internal_circuits.c_rx_commitment,
            right.proof.internal_circuits.c_rx_commitment,
            left.proof.internal_circuits.v_rx_commitment,
            right.proof.internal_circuits.v_rx_commitment,
        ];

        // Compute nested preamble
        let nested_preamble_rx =
            stages::nested::preamble::Stage::<C::HostCurve, R, 7>::rx(&nested_preamble_points)?;
        let nested_preamble_blind: <C as Cycle>::ScalarField = C::ScalarField::random(&mut *rng);
        let nested_preamble_commitment =
            nested_preamble_rx.commit(nested_generators, nested_preamble_blind);

        // Compute w = H(nested_preamble_commitment)
        let w =
            crate::components::transcript::emulate_w::<C>(nested_preamble_commitment, self.params)?;

        // TODO: Generate error terms and nested commitment.
        let error_terms = ErrorTermsLen::<NUM_NATIVE_REVDOT_CLAIMS>::range()
            .map(|_| C::CircuitField::random(&mut *rng))
            .collect_fixed()?;

        // TODO: dummy challenge (stubbed for now).
        let mu = C::CircuitField::random(&mut *rng);
        let nu = C::CircuitField::random(&mut *rng);

        // Compute c by running the routine in a wireless emulator
        let c: C::CircuitField =
            Emulator::emulate_wireless((mu, nu, &error_terms), |dr, witness| {
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
        let native_query_commitment = native_query_rx.commit(host_generators, native_query_blind);

        let nested_query_rx =
            internal_circuits::stages::nested::query::Stage::<C::HostCurve, R>::rx(
                native_query_commitment,
            )?;
        let nested_query_blind = C::ScalarField::random(&mut *rng);
        let nested_query_commitment = nested_query_rx.commit(nested_generators, nested_query_blind);

        // Derive challenge alpha = H(nested_query_commitment).
        let alpha = crate::components::transcript::emulate_alpha::<C>(
            nested_query_commitment,
            self.params,
        )?;

        // Compute the F polynomial commitment (stubbed for now).
        let native_f_rx =
            ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
        let native_f_blind = C::CircuitField::random(&mut *rng);
        let native_f_commitment = native_f_rx.commit(host_generators, native_f_blind);

        let nested_f_rx = internal_circuits::stages::nested::f::Stage::<C::HostCurve, R>::rx(
            native_f_commitment,
        )?;
        let nested_f_blind = C::ScalarField::random(&mut *rng);
        let nested_f_commitment = nested_f_rx.commit(nested_generators, nested_f_blind);

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
        let native_eval_commitment = native_eval_rx.commit(host_generators, native_eval_blind);

        let nested_eval_rx = internal_circuits::stages::nested::eval::Stage::<C::HostCurve, R>::rx(
            native_eval_commitment,
        )?;
        let nested_eval_blind = C::ScalarField::random(&mut *rng);
        let nested_eval_commitment = nested_eval_rx.commit(nested_generators, nested_eval_blind);

        // Create the unified instance.
        let unified_instance = &unified::Instance {
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

        // C staged circuit.
        let (c_rx, _) =
            internal_circuits::c::Circuit::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::new(
                self.params,
                self.log2_domain_size(),
            )
            .rx::<R>(
                internal_circuits::c::Witness {
                    unified_instance,
                    preamble_witness: &preamble_witness,
                    error_terms,
                },
                self.circuit_mesh.get_key(),
            )?;
        let c_rx_blind = C::CircuitField::random(&mut *rng);
        let c_rx_commitment = c_rx.commit(host_generators, c_rx_blind);

        // V staged circuit.
        let (v_rx, _) =
            internal_circuits::v::Circuit::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::new(
                self.params,
            )
            .rx::<R>(
                internal_circuits::v::Witness {
                    unified_instance,
                    query_witness: &query_witness,
                    eval_witness: &eval_witness,
                },
                self.circuit_mesh.get_key(),
            )?;
        let v_rx_blind = C::CircuitField::random(&mut *rng);
        let v_rx_commitment = v_rx.commit(host_generators, v_rx_blind);

        // Application
        let application_circuit_id = S::INDEX.circuit_index(self.num_application_steps)?;
        let (application_rx, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step).rx::<R>(
            (left.data, right.data, witness),
            self.circuit_mesh.get_key(),
        )?;
        let application_rx_blind = C::CircuitField::random(&mut *rng);
        let application_rx_commitment =
            application_rx.commit(host_generators, application_rx_blind);

        let ((left_header, right_header), aux) = aux;

        Ok((
            Proof {
                preamble: PreambleProof {
                    native_preamble_rx,
                    native_preamble_commitment,
                    native_preamble_blind,
                    nested_preamble_rx,
                    nested_preamble_commitment,
                    nested_preamble_blind,
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
                internal_circuits: InternalCircuits {
                    w,
                    c,
                    c_rx,
                    c_rx_commitment,
                    c_rx_blind,
                    v_rx,
                    v_rx_commitment,
                    v_rx_blind,
                    mu,
                    nu,
                    alpha,
                    u,
                },
                application: ApplicationProof {
                    circuit_id: application_circuit_id,
                    left_header: left_header.into_inner(),
                    right_header: right_header.into_inner(),
                    rx: application_rx,
                    blind: application_rx_blind,
                    commitment: application_rx_commitment,
                },
            },
            aux,
        ))
    }
}
