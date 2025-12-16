use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{CircuitExt, polynomials::Rank, staging::StageExt};
use ragu_core::{Error, Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, FixedVec, Len},
};
use rand::Rng;

use alloc::vec;
use alloc::vec::Vec;

use crate::{
    Application, circuit_counts,
    components::{
        fold_revdot::{self, ErrorTermsLen, NativeParameters, Parameters},
        ky,
    },
    internal_circuits::{self, stages, unified},
    proof::{
        ABProof, ApplicationProof, ErrorProof, EvalProof, FProof, InternalCircuits, MeshWyProof,
        MeshXyProof, Pcd, PreambleProof, Proof, QueryProof, SPrimeProof,
    },
    step::{Step, adapter::Adapter},
    verify::{stub_step::StubStep, stub_unified::StubUnified},
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

        // The preamble stage commits to all of the C::CircuitField elements
        // used as public inputs to the circuits being merged together. This
        // includes the unified instance values for both proofs, but also their
        // circuit IDs (the omega^j value that corresponds to each element of
        // the mesh domain that corresponds to the Step circuit being checked).
        //
        // Let's assemble the witness needed to generate the preamble stage.
        let preamble_witness = stages::native::preamble::Witness::from_pcds(&left, &right)?;

        // Now, compute the partial witness polynomial (stage polynomial) for
        // the preamble.
        let native_preamble_rx =
            stages::native::preamble::Stage::<C, R, HEADER_SIZE>::rx(&preamble_witness)?;
        // ... and commit to it, with a random blinding factor.
        let native_preamble_blind = C::CircuitField::random(&mut *rng);
        let native_preamble_commitment =
            native_preamble_rx.commit(host_generators, native_preamble_blind);

        // In order to circle back to C::CircuitField, because our
        // `native_preamble_commitment` has base points in C::ScalarField, we
        // need to commit to a stage polynomial over the C::NestedCurve that
        // contains all of the `C::HostCurve` points. This includes the
        // native_preamble_commitment we just computed, but also contains
        // commitments to circuit and stage polynomials that were created in the
        // merge operations that produced each of the two input proofs.
        let nested_preamble_witness = stages::nested::preamble::Witness {
            native_preamble: native_preamble_commitment,
            left_application: left.proof.application.commitment,
            right_application: right.proof.application.commitment,
            left_c: left.proof.internal_circuits.c_rx_commitment,
            right_c: right.proof.internal_circuits.c_rx_commitment,
            left_v: left.proof.internal_circuits.v_rx_commitment,
            right_v: right.proof.internal_circuits.v_rx_commitment,
        };

        // Compute the stage polynomial that commits to the `C::HostCurve`
        // points.
        let nested_preamble_rx =
            stages::nested::preamble::Stage::<C::HostCurve, R>::rx(&nested_preamble_witness)?;
        // ... and again commit to it, this time producing a point that is
        // represented using base field elements in `C::CircuitField` that we
        // can manipulate as the "native" field.
        let nested_preamble_blind: <C as Cycle>::ScalarField = C::ScalarField::random(&mut *rng);
        let nested_preamble_commitment =
            nested_preamble_rx.commit(nested_generators, nested_preamble_blind);

        // We now simulate the computation of `w`, the first challenge of the
        // protocol. The challenges we compute in this manner are produced so as
        // to simulate the verification of the two proofs simultaneously.
        //
        // Derive w = H(nested_preamble_commitment)
        let w =
            crate::components::transcript::emulate_w::<C>(nested_preamble_commitment, self.params)?;

        // In order to check that the two proofs' commitments to s (the mesh polynomial
        // evaluated at (x_0, y_0) and (x_1, y_1)) are correct, we need to
        // compute s' = m(w, x_i, Y) for both proofs.
        let x0 = left.proof.internal_circuits.x;
        let x1 = right.proof.internal_circuits.x;

        // ... commit to both...
        let mesh_wx0 = self.circuit_mesh.wx(w, x0);
        let mesh_wx0_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx0_commitment = mesh_wx0.commit(host_generators, mesh_wx0_blind);
        let mesh_wx1 = self.circuit_mesh.wx(w, x1);
        let mesh_wx1_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx1_commitment = mesh_wx1.commit(host_generators, mesh_wx1_blind);
        // ... and then compute the nested commitment S' that contains them.
        let nested_s_prime_witness = stages::nested::s_prime::Witness {
            mesh_wx0: mesh_wx0_commitment,
            mesh_wx1: mesh_wx1_commitment,
        };
        let nested_s_prime_rx =
            stages::nested::s_prime::Stage::<C::HostCurve, R>::rx(&nested_s_prime_witness)?;
        let nested_s_prime_blind = C::ScalarField::random(&mut *rng);
        let nested_s_prime_commitment =
            nested_s_prime_rx.commit(nested_generators, nested_s_prime_blind);

        // Once S' is committed, we can compute the challenges (y, z).
        //
        // Derive (y, z) = H(w, nested_s_prime_commitment).
        let (y, z) = crate::components::transcript::emulate_y_z::<C>(
            w,
            nested_s_prime_commitment,
            self.params,
        )?;

        // Compute k(y) for the left and right application circuits.
        let left_app_ky = {
            let adapter = Adapter::<C, StubStep<S::Left>, R, HEADER_SIZE>::new(StubStep::new());
            let left_header = FixedVec::try_from(left.proof.application.left_header.clone())
                .map_err(|_| Error::MalformedEncoding("left header size".into()))?;
            let right_header = FixedVec::try_from(left.proof.application.right_header.clone())
                .map_err(|_| Error::MalformedEncoding("right header size".into()))?;
            ky::emulate(&adapter, (left_header, right_header, left.data.clone()), y)?
        };

        let right_app_ky = {
            let adapter = Adapter::<C, StubStep<S::Right>, R, HEADER_SIZE>::new(StubStep::new());
            let left_header = FixedVec::try_from(right.proof.application.left_header.clone())
                .map_err(|_| Error::MalformedEncoding("left header size".into()))?;
            let right_header = FixedVec::try_from(right.proof.application.right_header.clone())
                .map_err(|_| Error::MalformedEncoding("right header size".into()))?;
            ky::emulate(&adapter, (left_header, right_header, right.data.clone()), y)?
        };

        // Compute k(y) for the left and right unified (C/V) circuits.
        let left_unified_ky = {
            let stub = StubUnified::<C>::new();
            let left_unified_instance = unified::Instance {
                nested_preamble_commitment: left.proof.preamble.nested_preamble_commitment,
                w: left.proof.internal_circuits.w,
                nested_s_prime_commitment: left.proof.s_prime.nested_s_prime_commitment,
                y: left.proof.internal_circuits.y,
                z: left.proof.internal_circuits.z,
                nested_s_doubleprime_commitment: left
                    .proof
                    .s_doubleprime
                    .nested_s_doubleprime_commitment,
                nested_error_m_commitment: left.proof.error.nested_error_m_commitment,
                mu: left.proof.internal_circuits.mu,
                nu: left.proof.internal_circuits.nu,
                nested_error_n_commitment: left.proof.error.nested_error_n_commitment,
                mu_prime: left.proof.internal_circuits.mu_prime,
                nu_prime: left.proof.internal_circuits.nu_prime,
                c: left.proof.internal_circuits.c,
                nested_ab_commitment: left.proof.ab.nested_ab_commitment,
                x: left.proof.internal_circuits.x,
                nested_s_commitment: left.proof.s.nested_s_commitment,
                nested_query_commitment: left.proof.query.nested_query_commitment,
                alpha: left.proof.internal_circuits.alpha,
                nested_f_commitment: left.proof.f.nested_f_commitment,
                u: left.proof.internal_circuits.u,
                nested_eval_commitment: left.proof.eval.nested_eval_commitment,
                beta: left.proof.internal_circuits.beta,
            };
            ky::emulate(&stub, &left_unified_instance, y)?
        };

        let right_unified_ky = {
            let stub = StubUnified::<C>::new();
            let right_unified_instance = unified::Instance {
                nested_preamble_commitment: right.proof.preamble.nested_preamble_commitment,
                w: right.proof.internal_circuits.w,
                nested_s_prime_commitment: right.proof.s_prime.nested_s_prime_commitment,
                y: right.proof.internal_circuits.y,
                z: right.proof.internal_circuits.z,
                nested_s_doubleprime_commitment: right
                    .proof
                    .s_doubleprime
                    .nested_s_doubleprime_commitment,
                nested_error_m_commitment: right.proof.error.nested_error_m_commitment,
                mu: right.proof.internal_circuits.mu,
                nu: right.proof.internal_circuits.nu,
                nested_error_n_commitment: right.proof.error.nested_error_n_commitment,
                mu_prime: right.proof.internal_circuits.mu_prime,
                nu_prime: right.proof.internal_circuits.nu_prime,
                c: right.proof.internal_circuits.c,
                nested_ab_commitment: right.proof.ab.nested_ab_commitment,
                x: right.proof.internal_circuits.x,
                nested_s_commitment: right.proof.s.nested_s_commitment,
                nested_query_commitment: right.proof.query.nested_query_commitment,
                alpha: right.proof.internal_circuits.alpha,
                nested_f_commitment: right.proof.f.nested_f_commitment,
                u: right.proof.internal_circuits.u,
                nested_eval_commitment: right.proof.eval.nested_eval_commitment,
                beta: right.proof.internal_circuits.beta,
            };
            ky::emulate(&stub, &right_unified_instance, y)?
        };

        // Get the accumulated c values from the input PCDs.
        let left_acc_c = left.proof.internal_circuits.c;
        let right_acc_c = right.proof.internal_circuits.c;

        // Collect all k(y) values from the left and right PCDs.
        let _ky_values: Vec<C::CircuitField> = vec![
            left_unified_ky,
            left_acc_c,
            left_app_ky,
            right_unified_ky,
            right_acc_c,
            right_app_ky,
        ];

        // Given (w, y), we can compute m(w, X, y) and commit to it.
        let mesh_wy = self.circuit_mesh.wy(w, y);
        let mesh_wy_blind = C::CircuitField::random(&mut *rng);
        let mesh_wy_commitment = mesh_wy.commit(host_generators, mesh_wy_blind);

        // Compute error_m stage (Layer 1: N instances of M-sized reductions).
        // The inclusion of z binds the error stage to the earlier "transcript".
        let error_m_witness = stages::native::error_m::Witness::<C, NativeParameters> {
            z,
            error_terms: <<NativeParameters as Parameters>::N>::range()
                .map(|_| {
                    ErrorTermsLen::<<NativeParameters as Parameters>::M>::range()
                        .map(|_| C::CircuitField::ZERO)
                        .collect_fixed()
                })
                .try_collect_fixed()?,
        };
        let native_error_m_rx =
            stages::native::error_m::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
                &error_m_witness,
            )?;
        let native_error_m_blind = C::CircuitField::random(&mut *rng);
        let native_error_m_commitment =
            native_error_m_rx.commit(host_generators, native_error_m_blind);

        // Nested error_m commitment (includes both native_error_m_commitment and mesh_wy_commitment)
        let nested_error_m_witness = stages::nested::error_m::Witness {
            native_error_m: native_error_m_commitment,
            mesh_wy: mesh_wy_commitment,
        };
        let nested_error_m_rx =
            stages::nested::error_m::Stage::<C::HostCurve, R>::rx(&nested_error_m_witness)?;
        let nested_error_m_blind = C::ScalarField::random(&mut *rng);
        let nested_error_m_commitment =
            nested_error_m_rx.commit(nested_generators, nested_error_m_blind);

        // Derive (mu, nu) = H(nested_error_m_commitment)
        let (mu, nu) = crate::components::transcript::emulate_mu_nu::<C>(
            nested_error_m_commitment,
            self.params,
        )?;

        // Compute error_n stage (Layer 2: Single N-sized reduction).
        // error_n includes nu as a binding challenge.
        let error_n_witness = stages::native::error_n::Witness::<C, NativeParameters> {
            nu,
            error_terms: ErrorTermsLen::<<NativeParameters as Parameters>::N>::range()
                .map(|_| C::CircuitField::ZERO)
                .collect_fixed()?,
        };
        let native_error_n_rx =
            stages::native::error_n::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
                &error_n_witness,
            )?;
        let native_error_n_blind = C::CircuitField::random(&mut *rng);
        let native_error_n_commitment =
            native_error_n_rx.commit(host_generators, native_error_n_blind);

        // Nested error_n commitment
        let nested_error_n_witness = stages::nested::error_n::Witness {
            native_error_n: native_error_n_commitment,
        };
        let nested_error_n_rx =
            stages::nested::error_n::Stage::<C::HostCurve, R>::rx(&nested_error_n_witness)?;
        let nested_error_n_blind = C::ScalarField::random(&mut *rng);
        let nested_error_n_commitment =
            nested_error_n_rx.commit(nested_generators, nested_error_n_blind);

        // Derive (mu', nu') = H(nested_error_n_commitment)
        let (mu_prime, nu_prime) = crate::components::transcript::emulate_mu_nu::<C>(
            nested_error_n_commitment,
            self.params,
        )?;

        // Compute c, the folded revdot product claim using two-layer reduction.
        let c: C::CircuitField = Emulator::emulate_wireless(
            (
                mu,
                nu,
                mu_prime,
                nu_prime,
                &error_m_witness.error_terms,
                &error_n_witness.error_terms,
            ),
            |dr, witness| {
                let (mu, nu, mu_prime, nu_prime, error_terms_m, error_terms_n) = witness.cast();

                let mu = Element::alloc(dr, mu)?;
                let nu = Element::alloc(dr, nu)?;
                let mu_prime = Element::alloc(dr, mu_prime)?;
                let nu_prime = Element::alloc(dr, nu_prime)?;

                // Allocate error_m error terms (nested structure)
                let error_terms_m: FixedVec<
                    FixedVec<Element<'_, _>, ErrorTermsLen<<NativeParameters as Parameters>::M>>,
                    <NativeParameters as Parameters>::N,
                > = <<NativeParameters as Parameters>::N>::range()
                    .map(|i| {
                        ErrorTermsLen::<<NativeParameters as Parameters>::M>::range()
                            .map(|j| Element::alloc(dr, error_terms_m.view().map(|et| et[i][j])))
                            .try_collect_fixed()
                    })
                    .try_collect_fixed()?;

                // Allocate error_n error terms
                let error_terms_n: FixedVec<
                    Element<'_, _>,
                    ErrorTermsLen<<NativeParameters as Parameters>::N>,
                > = ErrorTermsLen::<<NativeParameters as Parameters>::N>::range()
                    .map(|i| Element::alloc(dr, error_terms_n.view().map(|et| et[i])))
                    .try_collect_fixed()?;

                // Layer 1: N instances of M-sized reductions
                // ky_values stay as zeros for now
                let ky_values_m: FixedVec<_, <NativeParameters as Parameters>::M> =
                    <<NativeParameters as Parameters>::M>::range()
                        .map(|_| Element::zero(dr))
                        .collect_fixed()?;

                let mut collapsed = vec![];
                for error_terms_i in error_terms_m.iter() {
                    let v = fold_revdot::compute_c_m::<_, NativeParameters>(
                        dr,
                        &mu,
                        &nu,
                        error_terms_i,
                        &ky_values_m,
                    )?;
                    collapsed.push(v);
                }
                let collapsed: FixedVec<_, <NativeParameters as Parameters>::N> =
                    FixedVec::new(collapsed)?;

                // Layer 2: Single N-sized reduction using collapsed as ky_values
                let c = fold_revdot::compute_c_n::<_, NativeParameters>(
                    dr,
                    &mu_prime,
                    &nu_prime,
                    &error_terms_n,
                    &collapsed,
                )?;

                Ok(*c.value().take())
            },
        )?;

        // Compute the A/B polynomials (depend on mu, nu).
        // TODO: For now, stub out fake A and B polynomials.
        let a = ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
        let b = ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();

        // Commit to A and B, then create the nested commitment.
        let a_blind = C::CircuitField::random(&mut *rng);
        let a_commitment = a.commit(host_generators, a_blind);
        let b_blind = C::CircuitField::random(&mut *rng);
        let b_commitment = b.commit(host_generators, b_blind);

        let nested_ab_witness = stages::nested::ab::Witness {
            a: a_commitment,
            b: b_commitment,
        };
        let nested_ab_rx = stages::nested::ab::Stage::<C::HostCurve, R>::rx(&nested_ab_witness)?;
        let nested_ab_blind = C::ScalarField::random(&mut *rng);
        let nested_ab_commitment = nested_ab_rx.commit(nested_generators, nested_ab_blind);

        // Derive x = H(nu', nested_ab_commitment).
        let x = crate::components::transcript::emulate_x::<C>(
            nu_prime,
            nested_ab_commitment,
            self.params,
        )?;

        // Compute commitment to mesh polynomial at (x, y).
        let mesh_xy = self.circuit_mesh.xy(x, y);
        let mesh_xy_blind = C::CircuitField::random(&mut *rng);
        let mesh_xy_commitment = mesh_xy.commit(host_generators, mesh_xy_blind);

        // Compute query witness (stubbed for now).
        let query_witness = internal_circuits::stages::native::query::Witness {
            x,
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

        // Nested query commitment (includes both native_query_commitment and mesh_xy_commitment)
        let nested_query_witness = stages::nested::query::Witness {
            native_query: native_query_commitment,
            mesh_xy: mesh_xy_commitment,
        };
        let nested_query_rx =
            stages::nested::query::Stage::<C::HostCurve, R>::rx(&nested_query_witness)?;
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

        let nested_f_witness = internal_circuits::stages::nested::f::Witness {
            native_f: native_f_commitment,
        };
        let nested_f_rx =
            internal_circuits::stages::nested::f::Stage::<C::HostCurve, R>::rx(&nested_f_witness)?;
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

        let nested_eval_witness = internal_circuits::stages::nested::eval::Witness {
            native_eval: native_eval_commitment,
        };
        let nested_eval_rx = internal_circuits::stages::nested::eval::Stage::<C::HostCurve, R>::rx(
            &nested_eval_witness,
        )?;
        let nested_eval_blind = C::ScalarField::random(&mut *rng);
        let nested_eval_commitment = nested_eval_rx.commit(nested_generators, nested_eval_blind);

        // Derive beta = H(nested_eval_commitment).
        let beta =
            crate::components::transcript::emulate_beta::<C>(nested_eval_commitment, self.params)?;

        // Create the unified instance.
        let unified_instance = &unified::Instance {
            nested_preamble_commitment,
            w,
            nested_s_prime_commitment,
            y,
            z,
            nested_error_m_commitment,
            mu,
            nu,
            nested_error_n_commitment,
            mu_prime,
            nu_prime,
            c,
            nested_ab_commitment,
            x,
            nested_query_commitment,
            alpha,
            nested_f_commitment,
            u,
            nested_eval_commitment,
            beta,
        };

        // C staged circuit.
        let (c_rx, _) = internal_circuits::c::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(
            self.params,
            circuit_counts(self.num_application_steps).1,
        )
        .rx::<R>(
            internal_circuits::c::Witness {
                unified_instance,
                preamble_witness: &preamble_witness,
                error_m_witness: &error_m_witness,
                error_n_witness: &error_n_witness,
            },
            self.circuit_mesh.get_key(),
        )?;
        let c_rx_blind = C::CircuitField::random(&mut *rng);
        let c_rx_commitment = c_rx.commit(host_generators, c_rx_blind);

        // V staged circuit.
        let (v_rx, _) =
            internal_circuits::v::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(self.params)
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
                mesh_wy: MeshWyProof {
                    mesh_wy,
                    mesh_wy_blind,
                    mesh_wy_commitment,
                },
                error: ErrorProof {
                    native_error_m_rx,
                    native_error_m_blind,
                    native_error_m_commitment,
                    nested_error_m_rx,
                    nested_error_m_blind,
                    nested_error_m_commitment,
                    native_error_n_rx,
                    native_error_n_blind,
                    native_error_n_commitment,
                    nested_error_n_rx,
                    nested_error_n_blind,
                    nested_error_n_commitment,
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
                mesh_xy: MeshXyProof {
                    mesh_xy,
                    mesh_xy_blind,
                    mesh_xy_commitment,
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
                    mu_prime,
                    nu_prime,
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
