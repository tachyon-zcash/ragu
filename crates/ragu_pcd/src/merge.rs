use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{CircuitExt, polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{
    Element, GadgetExt, Point,
    poseidon::Sponge,
    vec::{CollectFixed, FixedVec},
};
use rand::Rng;

use crate::{
    Application, circuit_counts,
    components::fold_revdot::{self, NativeParameters},
    internal_circuits::{self, stages, unified},
    proof::{
        ABProof, ApplicationProof, ErrorProof, EvalProof, FProof, InternalCircuits, MeshWyProof,
        MeshXyProof, Pcd, PreambleProof, Proof, QueryProof, SPrimeProof,
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
            left_ky: left.proof.internal_circuits.ky_rx_commitment,
            right_ky: right.proof.internal_circuits.ky_rx_commitment,
            left_c: left.proof.internal_circuits.c_rx_commitment,
            right_c: right.proof.internal_circuits.c_rx_commitment,
            left_v: left.proof.internal_circuits.v_rx_commitment,
            right_v: right.proof.internal_circuits.v_rx_commitment,
            left_hashes_1: left.proof.internal_circuits.hashes_1_rx_commitment,
            right_hashes_1: right.proof.internal_circuits.hashes_1_rx_commitment,
            left_hashes_2: left.proof.internal_circuits.hashes_2_rx_commitment,
            right_hashes_2: right.proof.internal_circuits.hashes_2_rx_commitment,
        };

        // Compute the stage polynomial that commits to the `C::HostCurve`
        // points.
        let nested_preamble_rx =
            stages::nested::preamble::Stage::<C::HostCurve, R>::rx(&nested_preamble_witness)?;
        // ... and again commit to it, this time producing a point that is
        // represented using base field elements in `C::CircuitField` that we
        // can manipulate as the "native" field.
        let nested_preamble_blind = C::ScalarField::random(&mut *rng);
        let nested_preamble_commitment =
            nested_preamble_rx.commit(nested_generators, nested_preamble_blind);

        // We now simulate the computation of `w`, the first challenge of the
        // protocol. The challenges we compute in this manner are produced so as
        // to simulate the verification of the two proofs simultaneously.
        //
        // Create a long-lived emulator and sponge for all challenge derivations
        let mut dr = Emulator::execute();
        let mut sponge = Sponge::new(&mut dr, self.params.circuit_poseidon());

        // Derive w = H(nested_preamble_commitment)
        Point::constant(&mut dr, nested_preamble_commitment)?.write(&mut dr, &mut sponge)?;
        let w = *sponge.squeeze(&mut dr)?.value().take();

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
        // Derive (y, z) = H(nested_s_prime_commitment).
        Point::constant(&mut dr, nested_s_prime_commitment)?.write(&mut dr, &mut sponge)?;
        let y = *sponge.squeeze(&mut dr)?.value().take();
        let z = *sponge.squeeze(&mut dr)?.value().take();

        // Given (w, y), we can compute m(w, X, y) and commit to it.
        let mesh_wy = self.circuit_mesh.wy(w, y);
        let mesh_wy_blind = C::CircuitField::random(&mut *rng);
        let mesh_wy_commitment = mesh_wy.commit(host_generators, mesh_wy_blind);

        // Compute error_m stage (Layer 1: N instances of M-sized reductions).
        let error_m_witness = stages::native::error_m::Witness::<C, NativeParameters> {
            error_terms: FixedVec::from_fn(|_| FixedVec::from_fn(|_| C::CircuitField::ZERO)),
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

        // Absorb nested_error_m_commitment, then save sponge state for bridging
        Point::constant(&mut dr, nested_error_m_commitment)?.write(&mut dr, &mut sponge)?;

        // Save sponge state for bridging transcript between hashes_1 and hashes_2
        let saved_sponge_state = sponge
            .save_state(&mut dr)
            .expect("save_state should succeed after absorbing");
        // Extract raw field values for the error_n witness
        let sponge_state_elements = saved_sponge_state
            .clone()
            .into_elements()
            .into_iter()
            .map(|e| *e.value().take())
            .collect_fixed()?;

        // Resume sponge to derive (mu, nu) = H(nested_error_m_commitment)
        let (mu, mut sponge) = Sponge::resume_and_squeeze(
            &mut dr,
            saved_sponge_state,
            self.params.circuit_poseidon(),
        )?;
        let mu = *mu.value().take();
        let nu = *sponge.squeeze(&mut dr)?.value().take();

        // Compute collapsed values (layer 1 folding) now that mu, nu are known.
        let collapsed =
            Emulator::emulate_wireless((mu, nu, &error_m_witness.error_terms), |dr, witness| {
                let (mu, nu, error_terms_m) = witness.cast();
                let mu = Element::alloc(dr, mu)?;
                let nu = Element::alloc(dr, nu)?;
                let ky_values = FixedVec::from_fn(|_| {
                    // TODO
                    Element::zero(dr)
                });

                FixedVec::try_from_fn(|i| {
                    let errors = FixedVec::try_from_fn(|j| {
                        Element::alloc(dr, error_terms_m.view().map(|et| et[i][j]))
                    })?;
                    let v = fold_revdot::compute_c_m::<_, NativeParameters>(
                        dr, &mu, &nu, &errors, &ky_values,
                    )?;
                    Ok(*v.value().take())
                })
            })?;

        // Compute error_n stage (Layer 2: Single N-sized reduction).
        let error_n_witness = stages::native::error_n::Witness::<C, NativeParameters> {
            error_terms: FixedVec::from_fn(|_| C::CircuitField::ZERO),
            collapsed,
            sponge_state_elements,
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
        Point::constant(&mut dr, nested_error_n_commitment)?.write(&mut dr, &mut sponge)?;
        let mu_prime = *sponge.squeeze(&mut dr)?.value().take();
        let nu_prime = *sponge.squeeze(&mut dr)?.value().take();

        // Compute c, the folded revdot product claim (layer 2 only).
        // Layer 1 was already computed above to produce the collapsed values.
        let c: C::CircuitField = Emulator::emulate_wireless(
            (
                mu_prime,
                nu_prime,
                &error_n_witness.error_terms,
                &error_n_witness.collapsed,
            ),
            |dr, witness| {
                let (mu_prime, nu_prime, error_terms_n, collapsed) = witness.cast();

                let mu_prime = Element::alloc(dr, mu_prime)?;
                let nu_prime = Element::alloc(dr, nu_prime)?;

                let error_terms_n = FixedVec::try_from_fn(|i| {
                    Element::alloc(dr, error_terms_n.view().map(|et| et[i]))
                })?;

                let collapsed =
                    FixedVec::try_from_fn(|i| Element::alloc(dr, collapsed.view().map(|c| c[i])))?;

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

        // Continue using the same sponge transcript (bridged from hashes_1)
        // Derive x = H(nested_ab_commitment).
        Point::constant(&mut dr, nested_ab_commitment)?.write(&mut dr, &mut sponge)?;
        let x = *sponge.squeeze(&mut dr)?.value().take();

        // Compute commitment to mesh polynomial at (x, y).
        let mesh_xy = self.circuit_mesh.xy(x, y);
        let mesh_xy_blind = C::CircuitField::random(&mut *rng);
        let mesh_xy_commitment = mesh_xy.commit(host_generators, mesh_xy_blind);

        // Compute query witness (stubbed for now).
        let query_witness = internal_circuits::stages::native::query::Witness {
            queries: FixedVec::from_fn(|_| C::CircuitField::ZERO),
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
        Point::constant(&mut dr, nested_query_commitment)?.write(&mut dr, &mut sponge)?;
        let alpha = *sponge.squeeze(&mut dr)?.value().take();

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

        // Derive u = H(nested_f_commitment).
        Point::constant(&mut dr, nested_f_commitment)?.write(&mut dr, &mut sponge)?;
        let u = *sponge.squeeze(&mut dr)?.value().take();

        // Compute eval witness (stubbed for now).
        let eval_witness = internal_circuits::stages::native::eval::Witness {
            evals: FixedVec::from_fn(|_| C::CircuitField::ZERO),
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
        Point::constant(&mut dr, nested_eval_commitment)?.write(&mut dr, &mut sponge)?;
        let beta = *sponge.squeeze(&mut dr)?.value().take();

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
            circuit_counts(self.num_application_steps).1,
        )
        .rx::<R>(
            internal_circuits::c::Witness {
                unified_instance,
                preamble_witness: &preamble_witness,
                error_n_witness: &error_n_witness,
            },
            self.circuit_mesh.get_key(),
        )?;
        let c_rx_blind = C::CircuitField::random(&mut *rng);
        let c_rx_commitment = c_rx.commit(host_generators, c_rx_blind);

        // V staged circuit.
        let (v_rx, _) = internal_circuits::v::Circuit::<C, R, HEADER_SIZE>::new().rx::<R>(
            internal_circuits::v::Witness { unified_instance },
            self.circuit_mesh.get_key(),
        )?;
        let v_rx_blind = C::CircuitField::random(&mut *rng);
        let v_rx_commitment = v_rx.commit(host_generators, v_rx_blind);

        // Hashes_1 staged circuit.
        let (hashes_1_rx, _) =
            internal_circuits::hashes_1::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(
                self.params,
            )
            .rx::<R>(
                internal_circuits::hashes_1::Witness {
                    unified_instance,
                    error_n_witness: &error_n_witness,
                },
                self.circuit_mesh.get_key(),
            )?;
        let hashes_1_rx_blind = C::CircuitField::random(&mut *rng);
        let hashes_1_rx_commitment = hashes_1_rx.commit(host_generators, hashes_1_rx_blind);

        // Hashes_2 staged circuit.
        let (hashes_2_rx, _) =
            internal_circuits::hashes_2::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(
                self.params,
            )
            .rx::<R>(
                internal_circuits::hashes_2::Witness {
                    unified_instance,
                    error_n_witness: &error_n_witness,
                },
                self.circuit_mesh.get_key(),
            )?;
        let hashes_2_rx_blind = C::CircuitField::random(&mut *rng);
        let hashes_2_rx_commitment = hashes_2_rx.commit(host_generators, hashes_2_rx_blind);

        // Ky staged circuit (layer 1 folding verification).
        let (ky_rx, _) =
            internal_circuits::ky::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(
                circuit_counts(self.num_application_steps).1,
            )
            .rx::<R>(
                internal_circuits::ky::Witness {
                    unified_instance,
                    preamble_witness: &preamble_witness,
                    error_m_witness: &error_m_witness,
                    error_n_witness: &error_n_witness,
                },
                self.circuit_mesh.get_key(),
            )?;
        let ky_rx_blind = C::CircuitField::random(&mut *rng);
        let ky_rx_commitment = ky_rx.commit(host_generators, ky_rx_blind);

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
                    hashes_1_rx,
                    hashes_1_rx_blind,
                    hashes_1_rx_commitment,
                    hashes_2_rx,
                    hashes_2_rx_blind,
                    hashes_2_rx_commitment,
                    ky_rx,
                    ky_rx_blind,
                    ky_rx_commitment,
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
