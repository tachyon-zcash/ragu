use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{CircuitExt, polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{
    Element, Point,
    vec::{CollectFixed, Len},
};
use rand::Rng;

use crate::{
    Application, circuit_counts,
    components::{
        fold_revdot::{self, ErrorTermsLen},
        transcript::TranscriptEmulator,
    },
    internal_circuits::{self, NUM_NATIVE_REVDOT_CLAIMS, stages, unified},
    proof::{
        ABProof, ApplicationProof, ErrorProof, EvalProof, FProof, InternalCircuits, Pcd,
        PreambleProof, Proof, QueryProof, SDoublePrimeProof, SPrimeProof, SProof,
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

        // Create a long-lived emulator and transcript for Fiat-Shamir challenge derivation.
        // All challenges are derived from this single transcript, ensuring proper binding.
        let mut em = Emulator::execute();
        let mut transcript = TranscriptEmulator::<_, C>::new(&mut em, self.params);

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

        // Derive w = H(nested_preamble_commitment)
        let nested_preamble_point = Point::constant(&mut em, nested_preamble_commitment)?;
        let w = *transcript
            .derive_w(&mut em, &nested_preamble_point)?
            .value()
            .take();

        // Rekey transcript with w for v.rs challenge derivations.
        // v.rs rekeys with w to continue the transcript without re-deriving from preamble.
        let w_elem = Element::constant(&mut em, w);
        let mut transcript = TranscriptEmulator::<_, C>::rekey(&mut em, self.params, &w_elem)?;

        // We compute a nested commitment to s' = m(w, x_i, Y).
        let x0 = left.proof.internal_circuits.x;
        let x1 = right.proof.internal_circuits.x;
        let mesh_wx0 = self.circuit_mesh.wx(w, x0);
        let mesh_wx0_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx0_commitment = mesh_wx0.commit(host_generators, mesh_wx0_blind);
        let mesh_wx1 = self.circuit_mesh.wx(w, x1);
        let mesh_wx1_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx1_commitment = mesh_wx1.commit(host_generators, mesh_wx1_blind);

        // We compute a nested commitment to s' = m(w, x_i, Y).
        let nested_s_prime_rx = stages::nested::s_prime::Stage::<C::HostCurve, R, 2>::rx(&[
            mesh_wx0_commitment,
            mesh_wx1_commitment,
        ])?;
        let nested_s_prime_blind = C::ScalarField::random(&mut *rng);
        let nested_s_prime_commitment =
            nested_s_prime_rx.commit(nested_generators, nested_s_prime_blind);

        // Derive (y, z) = H(w, nested_s_prime_commitment).
        let nested_s_prime_point = Point::constant(&mut em, nested_s_prime_commitment)?;
        let (y_elem, z_elem) = transcript.derive_y_z(&mut em, &nested_s_prime_point)?;
        let y = *y_elem.value().take();
        let z = *z_elem.value().take();

        // Given (w, y), we can compute m(w, X, y) and commit to it.
        let mesh_wy = self.circuit_mesh.wy(w, y);
        let mesh_wy_blind = C::CircuitField::random(&mut *rng);
        let mesh_wy_commitment = mesh_wy.commit(host_generators, mesh_wy_blind);

        // We compute a nested commitment to S'' = m(w, X, y).
        let nested_s_doubleprime_rx =
            stages::nested::s_doubleprime::Stage::<C::HostCurve, R>::rx(mesh_wy_commitment)?;
        let nested_s_doubleprime_blind = C::ScalarField::random(&mut *rng);
        let nested_s_doubleprime_commitment =
            nested_s_doubleprime_rx.commit(nested_generators, nested_s_doubleprime_blind);

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
        let native_error_commitment = native_error_rx.commit(host_generators, native_error_blind);

        // Stubbed nested error rx polynomial
        let nested_error_rx =
            stages::nested::error::Stage::<C::HostCurve, R>::rx(native_error_commitment)?;
        let nested_error_blind = C::ScalarField::random(&mut *rng);
        let nested_error_commitment = nested_error_rx.commit(nested_generators, nested_error_blind);

        // Derive (mu, nu) = H(nested_error_commitment)
        let nested_error_point = Point::constant(&mut em, nested_error_commitment)?;
        let (mu_elem, nu_elem) = transcript.derive_mu_nu(&mut em, &nested_error_point)?;
        let mu = *mu_elem.value().take();
        let nu = *nu_elem.value().take();

        // Compute c by running the routine in a wireless emulator
        let c: C::CircuitField =
            Emulator::emulate_wireless((mu, nu, &error_witness.error_terms), |dr, witness| {
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
        let a_commitment = a.commit(host_generators, a_blind);
        let b_blind = C::CircuitField::random(&mut *rng);
        let b_commitment = b.commit(host_generators, b_blind);

        let nested_ab_rx =
            stages::nested::ab::Stage::<C::HostCurve, R, 2>::rx(&[a_commitment, b_commitment])?;
        let nested_ab_blind = C::ScalarField::random(&mut *rng);
        let nested_ab_commitment = nested_ab_rx.commit(nested_generators, nested_ab_blind);

        // Derive x = H(nu, nested_ab_commitment).
        let nested_ab_point = Point::constant(&mut em, nested_ab_commitment)?;
        let x = *transcript
            .derive_x(&mut em, &nested_ab_point)?
            .value()
            .take();

        // Compute commitment to mesh polynomial at (x, y).
        let mesh_xy = self.circuit_mesh.xy(x, y);
        let mesh_xy_blind = C::CircuitField::random(&mut *rng);
        let mesh_xy_commitment = mesh_xy.commit(host_generators, mesh_xy_blind);

        let nested_s_rx = stages::nested::s::Stage::<C::HostCurve, R>::rx(mesh_xy_commitment)?;
        let nested_s_blind = C::ScalarField::random(&mut *rng);
        let nested_s_commitment = nested_s_rx.commit(nested_generators, nested_s_blind);

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
        let native_query_commitment = native_query_rx.commit(host_generators, native_query_blind);

        let nested_query_rx =
            internal_circuits::stages::nested::query::Stage::<C::HostCurve, R>::rx(
                native_query_commitment,
            )?;
        let nested_query_blind = C::ScalarField::random(&mut *rng);
        let nested_query_commitment = nested_query_rx.commit(nested_generators, nested_query_blind);

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
        let native_f_commitment = native_f_rx.commit(host_generators, native_f_blind);

        let nested_f_rx = internal_circuits::stages::nested::f::Stage::<C::HostCurve, R>::rx(
            native_f_commitment,
        )?;
        let nested_f_blind = C::ScalarField::random(&mut *rng);
        let nested_f_commitment = nested_f_rx.commit(nested_generators, nested_f_blind);

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
        let native_eval_commitment = native_eval_rx.commit(host_generators, native_eval_blind);

        let nested_eval_rx = internal_circuits::stages::nested::eval::Stage::<C::HostCurve, R>::rx(
            native_eval_commitment,
        )?;
        let nested_eval_blind = C::ScalarField::random(&mut *rng);
        let nested_eval_commitment = nested_eval_rx.commit(nested_generators, nested_eval_blind);

        // Derive beta = H(nested_eval_commitment).
        let nested_eval_point = Point::constant(&mut em, nested_eval_commitment)?;
        let beta = *transcript
            .derive_beta(&mut em, &nested_eval_point)?
            .value()
            .take();

        // Create the unified instance.
        let unified_instance = &unified::Instance {
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

        // C staged circuit.
        let (c_rx, _) =
            internal_circuits::c::Circuit::<C, R, HEADER_SIZE, NUM_NATIVE_REVDOT_CLAIMS>::new(
                self.params,
                circuit_counts(self.num_application_steps).1,
            )
            .rx::<R>(
                internal_circuits::c::Witness {
                    unified_instance,
                    preamble_witness: &preamble_witness,
                    error_witness: &error_witness,
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
                    y,
                    z,
                    c,
                    c_rx,
                    c_rx_commitment,
                    c_rx_blind,
                    v_rx,
                    v_rx_commitment,
                    v_rx_blind,
                    mu,
                    nu,
                    x,
                    alpha,
                    u,
                    beta,
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
