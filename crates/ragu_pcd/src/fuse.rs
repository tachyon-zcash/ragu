use arithmetic::{Cycle, PrimeFieldExt};
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    polynomials::Rank,
    staging::{Stage, StageExt},
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{
    Element, GadgetExt, Point,
    poseidon::Sponge,
    vec::{CollectFixed, FixedVec},
};
use rand::Rng;

use alloc::vec;

use crate::{
    Application,
    components::fold_revdot::{self, NativeParameters},
    internal_circuits::{
        self,
        stages::{self, native::error_n::KyValues},
        total_circuit_counts, unified,
    },
    proof::{
        ABProof, ApplicationProof, ErrorMProof, ErrorNProof, EvalProof, FProof, InternalCircuits,
        MeshWyProof, MeshXyProof, Pcd, PreambleProof, Proof, QueryProof, SPrimeProof,
    },
    step::{Step, adapter::Adapter},
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Fuse two [`Pcd`] into one using a provided [`Step`].
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
    /// * `left`: the left [`Pcd`] to fuse in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right [`Pcd`] to fuse in this step; must correspond to
    ///   the [`Step::Right`] header.
    pub fn fuse<'source, RNG: Rng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        // The two proofs being fused are checked simultaneously as part of the
        // same transcript. We simulate this transcript with an `Emulator` in
        // order to construct valid witnesses for the circuits that certify the
        // fuse operation.
        let mut dr = Emulator::execute();
        let mut transcript = Sponge::new(&mut dr, self.params.circuit_poseidon());

        // Phase 1: Application circuit.
        let (left, right, application_proof, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right)?;

        // Phase 2: Preamble.
        let (preamble, preamble_witness) = self.compute_preamble(
            rng,
            &left,
            &right,
            &application_proof.left_header,
            &application_proof.right_header,
        )?;
        Point::constant(&mut dr, preamble.nested_preamble_commitment)?
            .write(&mut dr, &mut transcript)?;
        let w = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 3: S' commitment to m(w, x_i, Y).
        let s_prime = self.compute_s_prime(rng, w, &left, &right)?;
        Point::constant(&mut dr, s_prime.nested_s_prime_commitment)?
            .write(&mut dr, &mut transcript)?;
        let y = *transcript.squeeze(&mut dr)?.value().take();
        let z = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 4: Compute m(w, X, y).
        let mesh_wy = self.compute_mesh_wy(rng, w, y);

        // Phase 5: Error M (Layer 1: N instances of M-sized reductions).
        let (error_m, error_m_witness) = self.compute_error_m(rng, mesh_wy.mesh_wy_commitment)?;
        Point::constant(&mut dr, error_m.nested_commitment)?.write(&mut dr, &mut transcript)?;

        // Save a copy of the transcript state. This is used as part of the
        // witness for the error_n stage, so that the hashes_2 circuit can
        // resume the sponge state from the end of hashes_1.
        let saved_transcript_state = transcript
            .clone()
            .save_state(&mut dr)
            .expect("save_state should succeed after absorbing")
            .into_elements()
            .into_iter()
            .map(|e| *e.value().take())
            .collect_fixed()?;

        let mu = *transcript.squeeze(&mut dr)?.value().take();
        let nu = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 6: Error N (k(y) computation, layer 1 folding, and N-sized reduction).
        let (error_n, error_n_witness) = self.compute_error_n(
            rng,
            &preamble_witness,
            &error_m_witness,
            y,
            mu,
            nu,
            saved_transcript_state,
        )?;

        // Derive (mu', nu') = H(nested_error_n_commitment).
        Point::constant(&mut dr, error_n.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let mu_prime = *transcript.squeeze(&mut dr)?.value().take();
        let nu_prime = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 7: Compute C, the folded revdot product claim.
        let c = self.compute_c(mu_prime, nu_prime, &error_n_witness)?;

        // Phase 8: A/B polynomials.
        let ab = self.compute_ab(rng)?;

        // Derive x = H(nested_ab_commitment).
        Point::constant(&mut dr, ab.nested_ab_commitment)?.write(&mut dr, &mut transcript)?;
        let x = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 9: Mesh XY.
        let mesh_xy = self.compute_mesh_xy(rng, x, y);

        // Phase 10: Query.
        let query = self.compute_query(rng, mesh_xy.mesh_xy_commitment)?;

        // Derive alpha = H(nested_query_commitment).
        Point::constant(&mut dr, query.nested_query_commitment)?.write(&mut dr, &mut transcript)?;
        let alpha = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 11: F polynomial.
        let f = self.compute_f(rng)?;

        // Derive u = H(nested_f_commitment).
        Point::constant(&mut dr, f.nested_f_commitment)?.write(&mut dr, &mut transcript)?;
        let u = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 12: Eval.
        let eval = self.compute_eval(rng)?;

        // Derive beta = H(nested_eval_commitment).
        Point::constant(&mut dr, eval.nested_eval_commitment)?.write(&mut dr, &mut transcript)?;
        let beta = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 13: Unified instance.
        let unified_instance = &unified::Instance {
            nested_preamble_commitment: preamble.nested_preamble_commitment,
            w,
            nested_s_prime_commitment: s_prime.nested_s_prime_commitment,
            y,
            z,
            nested_error_m_commitment: error_m.nested_commitment,
            mu,
            nu,
            nested_error_n_commitment: error_n.nested_commitment,
            mu_prime,
            nu_prime,
            c,
            nested_ab_commitment: ab.nested_ab_commitment,
            x,
            nested_query_commitment: query.nested_query_commitment,
            alpha,
            nested_f_commitment: f.nested_f_commitment,
            u,
            nested_eval_commitment: eval.nested_eval_commitment,
            beta,
        };

        // Phase 14: Internal circuits.
        let internal_circuits = self.compute_internal_circuits(
            rng,
            unified_instance,
            &preamble_witness,
            &error_m_witness,
            &error_n_witness,
            w,
            y,
            z,
            c,
            mu,
            nu,
            mu_prime,
            nu_prime,
            x,
            alpha,
            u,
            beta,
        )?;

        Ok((
            Proof {
                preamble,
                s_prime,
                mesh_wy,
                error_m,
                error_n,
                ab,
                mesh_xy,
                query,
                f,
                eval,
                internal_circuits,
                application: application_proof,
            },
            // We return the application auxillary data for potential use by the
            // caller.
            application_aux,
        ))
    }

    /// Compute the application circuit proof.
    ///
    /// We process the application circuit first because it consumes the
    /// `Pcd`'s `data` fields inside of the `Step` circuit. The adaptor
    /// handles encoding for us, so that we can use the resulting (encoded)
    /// headers to construct the proof. We can also then use the encoded
    /// headers later to construct witnesses for other internal circuits
    /// constructed during the fuse operation.
    ///
    /// Returns the enclosed left/right `Proof` structures along with the
    /// application proof and auxiliary data.
    fn compute_application_proof<'source, RNG: Rng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(
        Proof<C, R>,
        Proof<C, R>,
        ApplicationProof<C, R>,
        S::Aux<'source>,
    )> {
        let circuit_id = S::INDEX.circuit_index(self.num_application_steps)?;
        let (rx, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step).rx::<R>(
            (left.data, right.data, witness),
            self.circuit_mesh.get_key(),
        )?;
        let blind = C::CircuitField::random(&mut *rng);
        let commitment = rx.commit(self.params.host_generators(), blind);

        let ((left_header, right_header), aux) = aux;

        Ok((
            left.proof,
            right.proof,
            ApplicationProof {
                circuit_id,
                left_header: left_header.into_inner(),
                right_header: right_header.into_inner(),
                rx,
                blind,
                commitment,
            },
            aux,
        ))
    }

    /// Compute the preamble proof.
    ///
    /// The preamble stage commits to all of the `C::CircuitField` elements used
    /// as public inputs to the circuits being fused together. This includes the
    /// unified instance values for both proofs, but also their circuit IDs (the
    /// ω^j value that corresponds to each element of the mesh domain that
    /// corresponds to the Step circuit being checked).
    fn compute_preamble<'a, RNG: Rng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        left_header: &'a [C::CircuitField],
        right_header: &'a [C::CircuitField],
    ) -> Result<(
        PreambleProof<C, R>,
        stages::native::preamble::Witness<'a, C, R, HEADER_SIZE>,
    )> {
        // Let's assemble the witness needed to generate the preamble stage.
        let preamble_witness =
            stages::native::preamble::Witness::new(left, right, left_header, right_header)?;

        // Now, compute the partial witness polynomial (stage polynomial) for
        // the preamble.
        let native_preamble_rx =
            stages::native::preamble::Stage::<C, R, HEADER_SIZE>::rx(&preamble_witness)?;
        // ... and commit to it, with a random blinding factor.
        let native_preamble_blind = C::CircuitField::random(&mut *rng);
        let native_preamble_commitment =
            native_preamble_rx.commit(self.params.host_generators(), native_preamble_blind);

        // In order to circle back to C::CircuitField, because our
        // `native_preamble_commitment` has base points in C::ScalarField, we
        // need to commit to a stage polynomial over the C::NestedCurve that
        // contains all of the `C::HostCurve` points. This includes the
        // native_preamble_commitment we just computed, but also contains
        // commitments to circuit and stage polynomials that were created in the
        // fuse operations that produced each of the two input proofs.
        let nested_preamble_witness = stages::nested::preamble::Witness {
            native_preamble: native_preamble_commitment,
            left_application: left.application.commitment,
            right_application: right.application.commitment,
            left_ky: left.internal_circuits.ky_rx_commitment,
            right_ky: right.internal_circuits.ky_rx_commitment,
            left_c: left.internal_circuits.c_rx_commitment,
            right_c: right.internal_circuits.c_rx_commitment,
            left_v: left.internal_circuits.v_rx_commitment,
            right_v: right.internal_circuits.v_rx_commitment,
            left_hashes_1: left.internal_circuits.hashes_1_rx_commitment,
            right_hashes_1: right.internal_circuits.hashes_1_rx_commitment,
            left_hashes_2: left.internal_circuits.hashes_2_rx_commitment,
            right_hashes_2: right.internal_circuits.hashes_2_rx_commitment,
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
            nested_preamble_rx.commit(self.params.nested_generators(), nested_preamble_blind);

        Ok((
            PreambleProof {
                native_preamble_rx,
                native_preamble_commitment,
                native_preamble_blind,
                nested_preamble_rx,
                nested_preamble_commitment,
                nested_preamble_blind,
            },
            preamble_witness,
        ))
    }

    /// Compute the S' proof.
    ///
    /// In order to check that the two proofs' commitments to s (the mesh
    /// polynomial evaluated at (x_0, y_0) and (x_1, y_1)) are correct, we need
    /// to compute s' = m(w, x_i, Y) for both proofs.
    fn compute_s_prime<RNG: Rng>(
        &self,
        rng: &mut RNG,
        w: C::CircuitField,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<SPrimeProof<C, R>> {
        let x0 = left.internal_circuits.x;
        let x1 = right.internal_circuits.x;

        // ... commit to both...
        let mesh_wx0 = self.circuit_mesh.wx(w, x0);
        let mesh_wx0_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx0_commitment = mesh_wx0.commit(self.params.host_generators(), mesh_wx0_blind);
        let mesh_wx1 = self.circuit_mesh.wx(w, x1);
        let mesh_wx1_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx1_commitment = mesh_wx1.commit(self.params.host_generators(), mesh_wx1_blind);
        // ... and then compute the nested commitment S' that contains them.
        let nested_s_prime_witness = stages::nested::s_prime::Witness {
            mesh_wx0: mesh_wx0_commitment,
            mesh_wx1: mesh_wx1_commitment,
        };
        let nested_s_prime_rx =
            stages::nested::s_prime::Stage::<C::HostCurve, R>::rx(&nested_s_prime_witness)?;
        let nested_s_prime_blind = C::ScalarField::random(&mut *rng);
        let nested_s_prime_commitment =
            nested_s_prime_rx.commit(self.params.nested_generators(), nested_s_prime_blind);

        Ok(SPrimeProof {
            mesh_wx0,
            mesh_wx0_blind,
            mesh_wx0_commitment,
            mesh_wx1,
            mesh_wx1_blind,
            mesh_wx1_commitment,
            nested_s_prime_rx,
            nested_s_prime_blind,
            nested_s_prime_commitment,
        })
    }

    /// Given (w, y), we can compute m(w, X, y) and commit to it.
    fn compute_mesh_wy<RNG: Rng>(
        &self,
        rng: &mut RNG,
        w: C::CircuitField,
        y: C::CircuitField,
    ) -> MeshWyProof<C, R> {
        let mesh_wy = self.circuit_mesh.wy(w, y);
        let mesh_wy_blind = C::CircuitField::random(&mut *rng);
        let mesh_wy_commitment = mesh_wy.commit(self.params.host_generators(), mesh_wy_blind);

        MeshWyProof {
            mesh_wy,
            mesh_wy_blind,
            mesh_wy_commitment,
        }
    }

    /// Compute error_m stage (Layer 1: N instances of M-sized reductions).
    fn compute_error_m<RNG: Rng>(
        &self,
        rng: &mut RNG,
        mesh_wy_commitment: C::HostCurve,
    ) -> Result<(
        ErrorMProof<C, R>,
        stages::native::error_m::Witness<C, NativeParameters>,
    )> {
        let error_m_witness = stages::native::error_m::Witness::<C, NativeParameters> {
            error_terms: FixedVec::from_fn(|_| FixedVec::from_fn(|_| C::CircuitField::todo())),
        };
        let native_rx = stages::native::error_m::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
            &error_m_witness,
        )?;
        let native_blind = C::CircuitField::random(&mut *rng);
        let native_commitment = native_rx.commit(self.params.host_generators(), native_blind);

        // Nested error_m commitment (includes both native_commitment and mesh_wy_commitment)
        let nested_error_m_witness = stages::nested::error_m::Witness {
            native_error_m: native_commitment,
            mesh_wy: mesh_wy_commitment,
        };
        let nested_rx =
            stages::nested::error_m::Stage::<C::HostCurve, R>::rx(&nested_error_m_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(self.params.nested_generators(), nested_blind);

        Ok((
            ErrorMProof {
                native_rx,
                native_blind,
                native_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            error_m_witness,
        ))
    }

    /// Compute error_n stage (Layer 2: Single N-sized reduction).
    ///
    /// Computes k(y) values from the preamble witness, performs layer 1 folding
    /// to get collapsed values, then builds the error_n stage witness and
    /// commitments.
    fn compute_error_n<RNG: Rng>(
        &self,
        rng: &mut RNG,
        preamble_witness: &stages::native::preamble::Witness<'_, C, R, HEADER_SIZE>,
        error_m_witness: &stages::native::error_m::Witness<C, NativeParameters>,
        y: C::CircuitField,
        mu: C::CircuitField,
        nu: C::CircuitField,
        sponge_state_elements: FixedVec<
            C::CircuitField,
            ragu_primitives::poseidon::PoseidonStateLen<C::CircuitField, C::CircuitPoseidon>,
        >,
    ) -> Result<(
        ErrorNProof<C, R>,
        stages::native::error_n::Witness<C, NativeParameters>,
    )> {
        let (ky, collapsed) = Emulator::emulate_wireless(
            (preamble_witness, &error_m_witness.error_terms, y, mu, nu),
            |dr, witness| {
                let (preamble_witness, error_terms_m, y, mu, nu) = witness.cast();

                // Run preamble stage to get proof inputs.
                let preamble = stages::native::preamble::Stage::<C, R, HEADER_SIZE>::default()
                    .witness(dr, preamble_witness.view().map(|w| *w))?;

                // Compute k(y) values.
                let y = Element::alloc(dr, y)?;
                let left_application_ky = preamble.left.application_ky(dr, &y)?;
                let right_application_ky = preamble.right.application_ky(dr, &y)?;
                let (left_unified_ky, left_unified_bridge_ky) =
                    preamble.left.unified_ky_values(dr, &y)?;
                let (right_unified_ky, right_unified_bridge_ky) =
                    preamble.right.unified_ky_values(dr, &y)?;

                // Compute collapsed values using the k(y) elements directly.
                let mu = Element::alloc(dr, mu)?;
                let nu = Element::alloc(dr, nu)?;

                let mut ky_elements = vec![
                    left_application_ky.clone(),
                    right_application_ky.clone(),
                    left_unified_ky.clone(),
                    right_unified_ky.clone(),
                    left_unified_bridge_ky.clone(),
                    right_unified_bridge_ky.clone(),
                ]
                .into_iter();

                let fold_c = fold_revdot::FoldC::new(dr, &mu, &nu)?;

                let collapsed = FixedVec::try_from_fn(|i| {
                    let errors = FixedVec::try_from_fn(|j| {
                        Element::alloc(dr, error_terms_m.view().map(|et| et[i][j]))
                    })?;
                    let ky_values = FixedVec::from_fn(|_| {
                        ky_elements.next().unwrap_or_else(|| Element::zero(dr))
                    });

                    let v = fold_c.compute_m::<NativeParameters>(dr, &errors, &ky_values)?;
                    Ok(*v.value().take())
                })?;

                // Extract k(y) scalar values.
                let ky = KyValues {
                    left_application: *left_application_ky.value().take(),
                    right_application: *right_application_ky.value().take(),
                    left_unified: *left_unified_ky.value().take(),
                    right_unified: *right_unified_ky.value().take(),
                    left_unified_bridge: *left_unified_bridge_ky.value().take(),
                    right_unified_bridge: *right_unified_bridge_ky.value().take(),
                };

                Ok((ky, collapsed))
            },
        )?;

        let error_n_witness = stages::native::error_n::Witness::<C, NativeParameters> {
            error_terms: FixedVec::from_fn(|_| C::CircuitField::todo()),
            collapsed,
            ky,
            sponge_state_elements,
        };
        let native_rx = stages::native::error_n::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
            &error_n_witness,
        )?;
        let native_blind = C::CircuitField::random(&mut *rng);
        let native_commitment = native_rx.commit(self.params.host_generators(), native_blind);

        // Nested error_n commitment
        let nested_error_n_witness = stages::nested::error_n::Witness {
            native_error_n: native_commitment,
        };
        let nested_rx =
            stages::nested::error_n::Stage::<C::HostCurve, R>::rx(&nested_error_n_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(self.params.nested_generators(), nested_blind);

        Ok((
            ErrorNProof {
                native_rx,
                native_blind,
                native_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            error_n_witness,
        ))
    }

    /// Compute c, the folded revdot product claim (layer 2 only).
    ///
    /// Performs a single N-sized reduction using the collapsed values from
    /// layer 1 as the k(y) values.
    fn compute_c(
        &self,
        mu_prime: C::CircuitField,
        nu_prime: C::CircuitField,
        error_n_witness: &stages::native::error_n::Witness<C, NativeParameters>,
    ) -> Result<C::CircuitField> {
        Emulator::emulate_wireless(
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
                let fold_c = fold_revdot::FoldC::new(dr, &mu_prime, &nu_prime)?;
                let c = fold_c.compute_n::<NativeParameters>(dr, &error_terms_n, &collapsed)?;

                Ok(*c.value().take())
            },
        )
    }

    /// Compute the A/B polynomials proof.
    ///
    /// Commits to A and B polynomials, then creates the nested commitment.
    fn compute_ab<RNG: Rng>(&self, rng: &mut RNG) -> Result<ABProof<C, R>> {
        // TODO: For now, stub out fake A and B polynomials.
        let a = ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
        let b = ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();

        // Commit to A and B, then create the nested commitment.
        let a_blind = C::CircuitField::random(&mut *rng);
        let a_commitment = a.commit(self.params.host_generators(), a_blind);
        let b_blind = C::CircuitField::random(&mut *rng);
        let b_commitment = b.commit(self.params.host_generators(), b_blind);

        let nested_ab_witness = stages::nested::ab::Witness {
            a: a_commitment,
            b: b_commitment,
        };
        let nested_ab_rx = stages::nested::ab::Stage::<C::HostCurve, R>::rx(&nested_ab_witness)?;
        let nested_ab_blind = C::ScalarField::random(&mut *rng);
        let nested_ab_commitment =
            nested_ab_rx.commit(self.params.nested_generators(), nested_ab_blind);

        Ok(ABProof {
            a,
            a_blind,
            a_commitment,
            b,
            b_blind,
            b_commitment,
            nested_ab_rx,
            nested_ab_blind,
            nested_ab_commitment,
        })
    }

    /// Compute mesh_xy proof.
    ///
    /// Computes commitment to mesh polynomial m(x, y) at the challenge points.
    fn compute_mesh_xy<RNG: Rng>(
        &self,
        rng: &mut RNG,
        x: C::CircuitField,
        y: C::CircuitField,
    ) -> MeshXyProof<C, R> {
        let mesh_xy = self.circuit_mesh.xy(x, y);
        let mesh_xy_blind = C::CircuitField::random(&mut *rng);
        let mesh_xy_commitment = mesh_xy.commit(self.params.host_generators(), mesh_xy_blind);

        MeshXyProof {
            mesh_xy,
            mesh_xy_blind,
            mesh_xy_commitment,
        }
    }

    /// Compute query proof.
    ///
    /// Creates native and nested query commitments.
    fn compute_query<RNG: Rng>(
        &self,
        rng: &mut RNG,
        mesh_xy_commitment: C::HostCurve,
    ) -> Result<QueryProof<C, R>> {
        let query_witness = internal_circuits::stages::native::query::Witness {
            queries: FixedVec::from_fn(|_| C::CircuitField::todo()),
        };

        let native_query_rx =
            internal_circuits::stages::native::query::Stage::<C, R, HEADER_SIZE>::rx(
                &query_witness,
            )?;
        let native_query_blind = C::CircuitField::random(&mut *rng);
        let native_query_commitment =
            native_query_rx.commit(self.params.host_generators(), native_query_blind);

        // Nested query commitment (includes both native_query_commitment and mesh_xy_commitment)
        let nested_query_witness = stages::nested::query::Witness {
            native_query: native_query_commitment,
            mesh_xy: mesh_xy_commitment,
        };
        let nested_query_rx =
            stages::nested::query::Stage::<C::HostCurve, R>::rx(&nested_query_witness)?;
        let nested_query_blind = C::ScalarField::random(&mut *rng);
        let nested_query_commitment =
            nested_query_rx.commit(self.params.nested_generators(), nested_query_blind);

        Ok(QueryProof {
            native_query_rx,
            native_query_blind,
            native_query_commitment,
            nested_query_rx,
            nested_query_blind,
            nested_query_commitment,
        })
    }

    /// Compute the F polynomial proof.
    fn compute_f<RNG: Rng>(&self, rng: &mut RNG) -> Result<FProof<C, R>> {
        let native_f_rx =
            ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
        let native_f_blind = C::CircuitField::random(&mut *rng);
        let native_f_commitment = native_f_rx.commit(self.params.host_generators(), native_f_blind);

        let nested_f_witness = internal_circuits::stages::nested::f::Witness {
            native_f: native_f_commitment,
        };
        let nested_f_rx =
            internal_circuits::stages::nested::f::Stage::<C::HostCurve, R>::rx(&nested_f_witness)?;
        let nested_f_blind = C::ScalarField::random(&mut *rng);
        let nested_f_commitment =
            nested_f_rx.commit(self.params.nested_generators(), nested_f_blind);

        Ok(FProof {
            native_f_rx,
            native_f_blind,
            native_f_commitment,
            nested_f_rx,
            nested_f_blind,
            nested_f_commitment,
        })
    }

    /// Compute the eval proof.
    fn compute_eval<RNG: Rng>(&self, rng: &mut RNG) -> Result<EvalProof<C, R>> {
        let eval_witness = internal_circuits::stages::native::eval::Witness {
            evals: FixedVec::from_fn(|_| C::CircuitField::todo()),
        };
        let native_eval_rx =
            internal_circuits::stages::native::eval::Stage::<C, R, HEADER_SIZE>::rx(&eval_witness)?;
        let native_eval_blind = C::CircuitField::random(&mut *rng);
        let native_eval_commitment =
            native_eval_rx.commit(self.params.host_generators(), native_eval_blind);

        let nested_eval_witness = internal_circuits::stages::nested::eval::Witness {
            native_eval: native_eval_commitment,
        };
        let nested_eval_rx = internal_circuits::stages::nested::eval::Stage::<C::HostCurve, R>::rx(
            &nested_eval_witness,
        )?;
        let nested_eval_blind = C::ScalarField::random(&mut *rng);
        let nested_eval_commitment =
            nested_eval_rx.commit(self.params.nested_generators(), nested_eval_blind);

        Ok(EvalProof {
            native_eval_rx,
            native_eval_blind,
            native_eval_commitment,
            nested_eval_rx,
            nested_eval_blind,
            nested_eval_commitment,
        })
    }

    /// Compute internal circuits.
    fn compute_internal_circuits<RNG: Rng>(
        &self,
        rng: &mut RNG,
        unified_instance: &unified::Instance<C>,
        preamble_witness: &stages::native::preamble::Witness<'_, C, R, HEADER_SIZE>,
        error_m_witness: &stages::native::error_m::Witness<C, NativeParameters>,
        error_n_witness: &stages::native::error_n::Witness<C, NativeParameters>,
        w: C::CircuitField,
        y: C::CircuitField,
        z: C::CircuitField,
        c: C::CircuitField,
        mu: C::CircuitField,
        nu: C::CircuitField,
        mu_prime: C::CircuitField,
        nu_prime: C::CircuitField,
        x: C::CircuitField,
        alpha: C::CircuitField,
        u: C::CircuitField,
        beta: C::CircuitField,
    ) -> Result<InternalCircuits<C, R>> {
        // compute_c staged circuit.
        let (c_rx, _) =
            internal_circuits::compute_c::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new()
                .rx::<R>(
                    internal_circuits::compute_c::Witness {
                        unified_instance,
                        preamble_witness,
                        error_m_witness,
                        error_n_witness,
                    },
                    self.circuit_mesh.get_key(),
                )?;
        let c_rx_blind = C::CircuitField::random(&mut *rng);
        let c_rx_commitment = c_rx.commit(self.params.host_generators(), c_rx_blind);

        // compute_v staged circuit.
        let (v_rx, _) = internal_circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new().rx::<R>(
            internal_circuits::compute_v::Witness { unified_instance },
            self.circuit_mesh.get_key(),
        )?;
        let v_rx_blind = C::CircuitField::random(&mut *rng);
        let v_rx_commitment = v_rx.commit(self.params.host_generators(), v_rx_blind);

        // Hashes_1 staged circuit.
        let (hashes_1_rx, _) =
            internal_circuits::hashes_1::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(
                self.params,
                total_circuit_counts(self.num_application_steps).1,
            )
            .rx::<R>(
                internal_circuits::hashes_1::Witness {
                    unified_instance,
                    preamble_witness,
                    error_n_witness,
                },
                self.circuit_mesh.get_key(),
            )?;
        let hashes_1_rx_blind = C::CircuitField::random(&mut *rng);
        let hashes_1_rx_commitment =
            hashes_1_rx.commit(self.params.host_generators(), hashes_1_rx_blind);

        // Hashes_2 staged circuit.
        let (hashes_2_rx, _) =
            internal_circuits::hashes_2::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(
                self.params,
            )
            .rx::<R>(
                internal_circuits::hashes_2::Witness {
                    unified_instance,
                    error_n_witness,
                },
                self.circuit_mesh.get_key(),
            )?;
        let hashes_2_rx_blind = C::CircuitField::random(&mut *rng);
        let hashes_2_rx_commitment =
            hashes_2_rx.commit(self.params.host_generators(), hashes_2_rx_blind);

        // fold staged circuit (layer 1 folding verification).
        let (ky_rx, _) =
            internal_circuits::fold::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new()
                .rx::<R>(
                    internal_circuits::fold::Witness {
                        unified_instance,
                        error_m_witness,
                        error_n_witness,
                    },
                    self.circuit_mesh.get_key(),
                )?;
        let ky_rx_blind = C::CircuitField::random(&mut *rng);
        let ky_rx_commitment = ky_rx.commit(self.params.host_generators(), ky_rx_blind);

        Ok(InternalCircuits {
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
        })
    }
}
