use arithmetic::Cycle;
use ff::{Field, PrimeField};
use ragu_circuits::{
    CircuitExt,
    mesh::{CircuitIndex, Mesh},
    polynomials::{Rank, structured, unstructured},
    staging::{Stage, StageExt},
};
use ragu_core::{
    Result,
    drivers::{Driver, emulator::Emulator},
    maybe::{Always, Maybe},
};
use ragu_primitives::{
    Element, GadgetExt, Point,
    poseidon::Sponge,
    vec::{CollectFixed, FixedVec},
};
use rand::Rng;

use alloc::{borrow::Cow, vec::Vec};
use core::iter::{once, repeat_n};

use crate::{
    Application, Pcd, Proof,
    components::fold_revdot::{self, NativeParameters},
    internal_circuits::{
        self, InternalCircuitIndex,
        stages::{
            self,
            native::error_n::{ChildKyValues, KyValues},
        },
        total_circuit_counts, unified,
    },
    proof,
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
        // Compute the application circuit's witness first, since it processes
        // the data fields of the two proofs being fused.
        let (left, right, application, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right)?;

        // The two proofs being fused are checked simultaneously as part of the
        // same transcript. We simulate this transcript with an `Emulator` in
        // order to construct valid witnesses for the circuits that certify the
        // fuse operation.
        let mut dr = Emulator::execute();
        let mut transcript = Sponge::new(&mut dr, C::circuit_poseidon(self.params));

        // Compute the preamble, the first prover messages in the transcript
        // that bind to the common inputs of the protocol.
        let (preamble, preamble_witness) =
            self.compute_preamble(rng, &left, &right, &application)?;
        Point::constant(&mut dr, preamble.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let w = transcript.squeeze(&mut dr)?;

        // After the `w` challenge is selected, we can evaluate m(w, x_i, Y) for
        // both x_i (child proof challenges) and commit to them, to later
        // reduce/fold their consistency checks together.
        let s_prime = self.compute_s_prime(rng, &w, &left, &right)?;
        Point::constant(&mut dr, s_prime.nested_s_prime_commitment)?
            .write(&mut dr, &mut transcript)?;
        let y = transcript.squeeze(&mut dr)?;
        let z = transcript.squeeze(&mut dr)?;

        // After the `y` and `z` challenges are selected, we can evaluate the
        // `error_m` stage which commits to:
        // 1. m(w, X, y) (mesh_wy)
        // 2. The first layer of the error terms for revdot products
        //
        // Crucially, by now every component of every revdot product claim being
        // folded has been committed to the transcript. Each proof's circuits
        // (via commitments) have been committed in the preamble stage (as part
        // of the `nested_preamble_commitment`). Each proof's remaining nested
        // commitments (stage commitments, interstitial polynomials like
        // s_prime and f(X)) are witnessed from their unified instances and
        // committed via the preamble stage.
        let (error_m, error_m_witness, prover_context) =
            self.compute_errors_m(rng, &w, &y, &z, &left, &right)?;
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

        let mu = transcript.squeeze(&mut dr)?;
        let nu = transcript.squeeze(&mut dr)?;

        // Once we have `mu` and `nu`, we can perform the next layer of the
        // revdot product reduction. This requires the prover to commit to a new
        // set of error terms.
        let (error_n, error_n_witness, a, b) = self.compute_errors_n(
            rng,
            &preamble_witness,
            &error_m_witness,
            prover_context,
            &y,
            &mu,
            &nu,
            saved_transcript_state,
        )?;
        Point::constant(&mut dr, error_n.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.squeeze(&mut dr)?;
        let nu_prime = transcript.squeeze(&mut dr)?;

        // The final revdot claim can now be computed, folding everything into a
        // single claim of the form << a, b >> = c. We can now construct the A/B
        // polynomials and commit to their revdot product; the circuits will
        // later impose the necessary constraints on the value of `c` when not
        // in the base case.
        let ab = self.compute_ab(rng, a, b, &mu_prime, &nu_prime)?;
        Point::constant(&mut dr, ab.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let x = transcript.squeeze(&mut dr)?;

        // We can now commit to m(W, x, y), and the evaluations at x, xz, etc.
        // that are needed to recompute the expected evaluation of the claimed
        // A/B polynomials.
        let (query, query_witness) =
            self.compute_query(rng, &w, &x, &y, &z, &error_m, &left, &right)?;
        Point::constant(&mut dr, query.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let alpha = transcript.squeeze(&mut dr)?;

        // The `alpha` challenge is used to keep the query (quotient)
        // polynomials linearly independent. We can now commit to f(X).
        let f = self.compute_f(
            rng, &w, &y, &z, &x, &alpha, &s_prime, &error_m, &ab, &query, &left, &right,
        )?;
        Point::constant(&mut dr, f.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let u = transcript.squeeze(&mut dr)?;

        // We can now commit to the `eval` stage containing the claimed
        // evaluations of every polynomial at `u`, used to enforce the query
        // stage claimed evaluations, derived evaluations, or reductions of
        // claims by the child proofs.
        let (eval, eval_witness) =
            self.compute_eval(rng, &u, &left, &right, &s_prime, &error_m, &ab, &query)?;
        Point::constant(&mut dr, eval.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let beta = transcript.squeeze(&mut dr)?;

        // We can now compute the expected value of p(X) and the claimed
        // evaluation at u; the circuit imposes the expected evaluation.
        let p = self.compute_p(
            rng, &beta, &u, &left, &right, &s_prime, &error_m, &ab, &query, &f,
        )?;

        // These values are needed by the circuits in the next (parent) fuse
        // step in order to assemble the unified instance, and because they
        // encode details about accumulators.
        let challenges = proof::Challenges::new(
            &w, &y, &z, &mu, &nu, &mu_prime, &nu_prime, &x, &alpha, &u, &beta,
        );

        // Compute the internal circuits that certify the correctness of the
        // transcript simulated thus far.
        let circuits = self.compute_internal_circuits(
            rng,
            &preamble,
            &s_prime,
            &error_m,
            &error_n,
            &ab,
            &query,
            &f,
            &eval,
            &p,
            &preamble_witness,
            &error_m_witness,
            &error_n_witness,
            &query_witness,
            &eval_witness,
            &challenges,
        )?;

        Ok((
            Proof {
                application,
                preamble,
                s_prime,
                error_m,
                error_n,
                ab,
                query,
                f,
                eval,
                p,
                challenges,
                circuits,
            },
            // We return the application auxiliary data for potential use by the
            // caller.
            application_aux,
        ))
    }

    /// Compute the application circuit proof.
    ///
    /// We process the application circuit first because it consumes the
    /// `Pcd`'s `data` fields inside of the `Step` circuit. The adapter
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
        proof::Application<C, R>,
        S::Aux<'source>,
    )> {
        let circuit_id = S::INDEX.circuit_index(self.num_application_steps)?;
        let (rx, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step).rx::<R>(
            (left.data, right.data, witness),
            self.circuit_mesh.get_key(),
        )?;
        let blind = C::CircuitField::random(&mut *rng);
        let commitment = rx.commit(C::host_generators(self.params), blind);

        let ((left_header, right_header), aux) = aux;

        Ok((
            left.proof,
            right.proof,
            proof::Application {
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
        application: &proof::Application<C, R>,
    ) -> Result<(
        proof::Preamble<C, R>,
        stages::native::preamble::Witness<'a, C, R, HEADER_SIZE>,
    )> {
        // Let's assemble the witness needed to generate the preamble stage.
        let preamble_witness = stages::native::preamble::Witness::new(
            left,
            right,
            &application.left_header,
            &application.right_header,
        )?;

        // Now, compute the partial witness polynomial (stage polynomial) for
        // the preamble.
        let stage_rx = stages::native::preamble::Stage::<C, R, HEADER_SIZE>::rx(&preamble_witness)?;
        // ... and commit to it, with a random blinding factor.
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        // In order to circle back to C::CircuitField, because our
        // `stage_commitment` has base points in C::ScalarField, we
        // need to commit to a stage polynomial over the C::NestedCurve that
        // contains all of the `C::HostCurve` points. This includes the
        // stage_commitment we just computed, but also contains
        // commitments to circuit and stage polynomials that were created in the
        // fuse operations that produced each of the two input proofs.
        let nested_preamble_witness = stages::nested::preamble::Witness {
            native_preamble: stage_commitment,
            left_application: left.application.commitment,
            right_application: right.application.commitment,
            left_hashes_1: left.circuits.hashes_1_commitment,
            right_hashes_1: right.circuits.hashes_1_commitment,
            left_hashes_2: left.circuits.hashes_2_commitment,
            right_hashes_2: right.circuits.hashes_2_commitment,
            left_partial_collapse: left.circuits.partial_collapse_commitment,
            right_partial_collapse: right.circuits.partial_collapse_commitment,
            left_full_collapse: left.circuits.full_collapse_commitment,
            right_full_collapse: right.circuits.full_collapse_commitment,
            left_compute_v: left.circuits.compute_v_commitment,
            right_compute_v: right.circuits.compute_v_commitment,
        };

        // Compute the stage polynomial that commits to the `C::HostCurve`
        // points.
        let nested_rx =
            stages::nested::preamble::Stage::<C::HostCurve, R>::rx(&nested_preamble_witness)?;
        // ... and again commit to it, this time producing a point that is
        // represented using base field elements in `C::CircuitField` that we
        // can manipulate as the "native" field.
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::Preamble {
                stage_rx,
                stage_blind,
                stage_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            preamble_witness,
        ))
    }

    /// Compute the S' proof.
    ///
    /// In order to check that the two proofs' commitments to s (the mesh
    /// polynomial evaluated at (x_0, y_0) and (x_1, y_1)) are correct, we need
    /// to compute s' = m(w, x_i, Y) for both proofs.
    fn compute_s_prime<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<proof::SPrime<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let w = *w.value().take();
        let x0 = left.challenges.x;
        let x1 = right.challenges.x;

        // ... commit to both...
        let mesh_wx0_poly = self.circuit_mesh.wx(w, x0);
        let mesh_wx0_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx0_commitment =
            mesh_wx0_poly.commit(C::host_generators(self.params), mesh_wx0_blind);
        let mesh_wx1_poly = self.circuit_mesh.wx(w, x1);
        let mesh_wx1_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx1_commitment =
            mesh_wx1_poly.commit(C::host_generators(self.params), mesh_wx1_blind);
        // ... and then compute the nested commitment S' that contains them.
        let nested_s_prime_witness = stages::nested::s_prime::Witness {
            mesh_wx0: mesh_wx0_commitment,
            mesh_wx1: mesh_wx1_commitment,
        };
        let nested_s_prime_rx =
            stages::nested::s_prime::Stage::<C::HostCurve, R>::rx(&nested_s_prime_witness)?;
        let nested_s_prime_blind = C::ScalarField::random(&mut *rng);
        let nested_s_prime_commitment =
            nested_s_prime_rx.commit(C::nested_generators(self.params), nested_s_prime_blind);

        Ok(proof::SPrime {
            mesh_wx0_poly,
            mesh_wx0_blind,
            mesh_wx0_commitment,
            mesh_wx1_poly,
            mesh_wx1_blind,
            mesh_wx1_commitment,
            nested_s_prime_rx,
            nested_s_prime_blind,
            nested_s_prime_commitment,
        })
    }

    /// Compute errors_m stage with mesh_wy bundled (Layer 1: N instances of M-sized reductions).
    ///
    /// Given (w, y, z), computes m(w, X, y), commits to it, then creates the error_m
    /// stage with the mesh_wy commitment bundled into the nested layer.
    ///
    /// Also assembles the a/b polynomial vectors from both proofs for error term
    /// computation, returning a `ProverContext` so the caller can fold polynomials
    /// after mu/nu are derived from the transcript.
    fn compute_errors_m<'dr, 'rx, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        left: &'rx Proof<C, R>,
        right: &'rx Proof<C, R>,
    ) -> Result<(
        proof::ErrorM<C, R>,
        stages::native::error_m::Witness<C, NativeParameters>,
        ProverContext<'_, 'rx, C::CircuitField, R>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let w = *w.value().take();
        let y = *y.value().take();
        let z = *z.value().take();

        // Compute mesh_wy components
        let mesh_wy_poly = self.circuit_mesh.wy(w, y);
        let mesh_wy_blind = C::CircuitField::random(&mut *rng);
        let mesh_wy_commitment =
            mesh_wy_poly.commit(C::host_generators(self.params), mesh_wy_blind);

        // Assemble a/b polynomials from both proofs for error term computation.
        let mut ctx = ProverContext::new(&self.circuit_mesh, self.num_application_steps, y, z);
        for proof in [left, right] {
            // Child proof::AB claim (k(y) = child's c)
            ctx.raw_claim(&proof.ab.a_poly, &proof.ab.b_poly);

            // Application circuit (uses application k(y))
            ctx.circuit(proof.application.circuit_id, &proof.application.rx);

            // hashes_1 circuit (uses unified_bridge k(y))
            ctx.internal_circuit(
                internal_circuits::hashes_1::CIRCUIT_ID,
                &[
                    &proof.circuits.hashes_1_rx,
                    &proof.preamble.stage_rx,
                    &proof.error_n.stage_rx,
                ],
            );

            // Unified internal circuits (uses unified k(y))
            ctx.internal_circuit(
                internal_circuits::hashes_2::CIRCUIT_ID,
                &[&proof.circuits.hashes_2_rx, &proof.error_n.stage_rx],
            );
            ctx.internal_circuit(
                internal_circuits::partial_collapse::CIRCUIT_ID,
                &[
                    &proof.circuits.partial_collapse_rx,
                    &proof.preamble.stage_rx,
                    &proof.error_m.stage_rx,
                    &proof.error_n.stage_rx,
                ],
            );
            ctx.internal_circuit(
                internal_circuits::full_collapse::CIRCUIT_ID,
                &[
                    &proof.circuits.full_collapse_rx,
                    &proof.preamble.stage_rx,
                    &proof.error_m.stage_rx,
                    &proof.error_n.stage_rx,
                ],
            );
            ctx.internal_circuit(
                internal_circuits::compute_v::CIRCUIT_ID,
                &[
                    &proof.circuits.compute_v_rx,
                    &proof.preamble.stage_rx,
                    &proof.query.stage_rx,
                    &proof.eval.stage_rx,
                ],
            );
        }

        // Stages (all k(y)=0, batched across both proofs)
        ctx.stage(
            InternalCircuitIndex::ErrorNFinalStaged,
            &[
                &left.circuits.hashes_1_rx,
                &left.circuits.hashes_2_rx,
                &left.circuits.partial_collapse_rx,
                &left.circuits.full_collapse_rx,
                &right.circuits.hashes_1_rx,
                &right.circuits.hashes_2_rx,
                &right.circuits.partial_collapse_rx,
                &right.circuits.full_collapse_rx,
            ],
        );
        ctx.stage(
            InternalCircuitIndex::EvalFinalStaged,
            &[&left.circuits.compute_v_rx, &right.circuits.compute_v_rx],
        );
        ctx.stage(
            internal_circuits::stages::native::preamble::STAGING_ID,
            &[&left.preamble.stage_rx, &right.preamble.stage_rx],
        );
        ctx.stage(
            internal_circuits::stages::native::error_m::STAGING_ID,
            &[&left.error_m.stage_rx, &right.error_m.stage_rx],
        );
        ctx.stage(
            internal_circuits::stages::native::error_n::STAGING_ID,
            &[&left.error_n.stage_rx, &right.error_n.stage_rx],
        );
        ctx.stage(
            internal_circuits::stages::native::query::STAGING_ID,
            &[&left.query.stage_rx, &right.query.stage_rx],
        );
        ctx.stage(
            internal_circuits::stages::native::eval::STAGING_ID,
            &[&left.eval.stage_rx, &right.eval.stage_rx],
        );

        // Compute real error terms from the assembled polynomial pairs
        let error_terms = fold_revdot::compute_errors_m::<_, R, NativeParameters>(&ctx.a, &ctx.b);

        // Error M stage commitment
        let error_m_witness =
            stages::native::error_m::Witness::<C, NativeParameters> { error_terms };
        let stage_rx = stages::native::error_m::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
            &error_m_witness,
        )?;
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        // Nested error_m commitment (bundles mesh_wy_commitment + stage_commitment)
        let nested_error_m_witness = stages::nested::error_m::Witness {
            native_error_m: stage_commitment,
            mesh_wy: mesh_wy_commitment,
        };
        let nested_rx =
            stages::nested::error_m::Stage::<C::HostCurve, R>::rx(&nested_error_m_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::ErrorM {
                mesh_wy_poly,
                mesh_wy_blind,
                mesh_wy_commitment,
                stage_rx,
                stage_blind,
                stage_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            error_m_witness,
            ctx,
        ))
    }

    /// Compute errors_n stage (Layer 2: Single N-sized reduction).
    ///
    /// Takes ownership of the ProverContext, folds the layer-1 polynomials using
    /// mu/nu, computes k(y) values from the preamble witness, performs layer 1
    /// folding to get collapsed values, then builds the error_n stage witness
    /// and commitments. Returns the folded `a` and `b` polynomials for use by
    /// compute_ab.
    fn compute_errors_n<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        preamble_witness: &stages::native::preamble::Witness<'_, C, R, HEADER_SIZE>,
        error_m_witness: &stages::native::error_m::Witness<C, NativeParameters>,
        prover_context: ProverContext<'_, '_, C::CircuitField, R>,
        y: &Element<'dr, D>,
        mu: &Element<'dr, D>,
        nu: &Element<'dr, D>,
        sponge_state_elements: FixedVec<
            C::CircuitField,
            ragu_primitives::poseidon::PoseidonStateLen<C::CircuitField, C::CircuitPoseidon>,
        >,
    ) -> Result<(
        proof::ErrorN<C, R>,
        stages::native::error_n::Witness<C, NativeParameters>,
        FixedVec<
            structured::Polynomial<C::CircuitField, R>,
            <NativeParameters as fold_revdot::Parameters>::N,
        >,
        FixedVec<
            structured::Polynomial<C::CircuitField, R>,
            <NativeParameters as fold_revdot::Parameters>::N,
        >,
    )>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let y = *y.value().take();
        let mu = *mu.value().take();
        let nu = *nu.value().take();
        let mu_inv = mu.invert().expect("mu must be non-zero");
        let munu = mu * nu;
        let a = fold_revdot::fold_polys_m::<_, R, NativeParameters>(&prover_context.a, mu_inv);
        let b = fold_revdot::fold_polys_m::<_, R, NativeParameters>(&prover_context.b, munu);
        drop(prover_context);

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

                // k(y) values in order matching the partial_collapse circuit
                let mut ky_elements = once(preamble.left.unified.c.clone())
                    .chain(once(left_application_ky.clone()))
                    .chain(once(left_unified_bridge_ky.clone()))
                    .chain(repeat_n(
                        left_unified_ky.clone(),
                        crate::internal_circuits::partial_collapse::NUM_UNIFIED_CIRCUITS,
                    ))
                    .chain(once(preamble.right.unified.c.clone()))
                    .chain(once(right_application_ky.clone()))
                    .chain(once(right_unified_bridge_ky.clone()))
                    .chain(repeat_n(
                        right_unified_ky.clone(),
                        crate::internal_circuits::partial_collapse::NUM_UNIFIED_CIRCUITS,
                    ));

                let fold_products = fold_revdot::FoldProducts::new(dr, &mu, &nu)?;

                let collapsed = FixedVec::try_from_fn(|i| {
                    let errors = FixedVec::try_from_fn(|j| {
                        Element::alloc(dr, error_terms_m.view().map(|et| et[i][j]))
                    })?;
                    let ky_values = FixedVec::from_fn(|_| {
                        ky_elements.next().unwrap_or_else(|| Element::zero(dr))
                    });

                    let v = fold_products
                        .fold_products_m::<NativeParameters>(dr, &errors, &ky_values)?;
                    Ok(*v.value().take())
                })?;

                // Extract k(y) scalar values.
                let ky = KyValues {
                    left: ChildKyValues {
                        application: *left_application_ky.value().take(),
                        unified: *left_unified_ky.value().take(),
                        unified_bridge: *left_unified_bridge_ky.value().take(),
                    },
                    right: ChildKyValues {
                        application: *right_application_ky.value().take(),
                        unified: *right_unified_ky.value().take(),
                        unified_bridge: *right_unified_bridge_ky.value().take(),
                    },
                };

                Ok((ky, collapsed))
            },
        )?;

        // Compute real error_n terms from the layer-1 folded polynomials.
        let error_terms = fold_revdot::compute_errors_n::<_, R, NativeParameters>(&a, &b);

        let error_n_witness = stages::native::error_n::Witness::<C, NativeParameters> {
            error_terms,
            collapsed,
            ky,
            sponge_state_elements,
        };
        let stage_rx = stages::native::error_n::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
            &error_n_witness,
        )?;
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        // Nested error_n commitment
        let nested_error_n_witness = stages::nested::error_n::Witness {
            native_error_n: stage_commitment,
        };
        let nested_rx =
            stages::nested::error_n::Stage::<C::HostCurve, R>::rx(&nested_error_n_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::ErrorN {
                stage_rx,
                stage_blind,
                stage_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            error_n_witness,
            a,
            b,
        ))
    }

    /// Compute the A/B polynomials proof.
    ///
    /// Folds the layer-1 polynomial pairs into final A and B polynomials using
    /// mu_prime and nu_prime, then commits and creates the nested commitment.
    fn compute_ab<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        a: FixedVec<
            structured::Polynomial<C::CircuitField, R>,
            <NativeParameters as fold_revdot::Parameters>::N,
        >,
        b: FixedVec<
            structured::Polynomial<C::CircuitField, R>,
            <NativeParameters as fold_revdot::Parameters>::N,
        >,
        mu_prime: &Element<'dr, D>,
        nu_prime: &Element<'dr, D>,
    ) -> Result<proof::AB<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        // Compute final folded polynomials from layer 1 pairs.
        let mu_prime = *mu_prime.value().take();
        let nu_prime = *nu_prime.value().take();
        let mu_prime_inv = mu_prime.invert().expect("mu_prime must be non-zero");
        let mu_prime_nu_prime = mu_prime * nu_prime;

        // A polynomial
        let a_poly = fold_revdot::fold_polys_n::<_, R, NativeParameters>(a, mu_prime_inv);
        let a_blind = C::CircuitField::random(&mut *rng);
        let a_commitment = a_poly.commit(C::host_generators(self.params), a_blind);

        // B polynomial
        let b_poly = fold_revdot::fold_polys_n::<_, R, NativeParameters>(b, mu_prime_nu_prime);
        let b_blind = C::CircuitField::random(&mut *rng);
        let b_commitment = b_poly.commit(C::host_generators(self.params), b_blind);

        // Compute the revdot product of a and b
        let c = a_poly.revdot(&b_poly);

        let nested_ab_witness = stages::nested::ab::Witness {
            a: a_commitment,
            b: b_commitment,
        };
        let nested_rx = stages::nested::ab::Stage::<C::HostCurve, R>::rx(&nested_ab_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok(proof::AB {
            a_poly,
            a_blind,
            a_commitment,
            b_poly,
            b_blind,
            b_commitment,
            c,
            nested_rx,
            nested_blind,
            nested_commitment,
        })
    }

    /// Compute query proof with mesh_xy bundled.
    ///
    /// Computes m(x, y), commits to it, then creates native and nested query commitments
    /// with the mesh_xy commitment bundled into the nested layer.
    fn compute_query<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        error_m: &proof::ErrorM<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<(
        proof::Query<C, R>,
        internal_circuits::stages::native::query::Witness<C>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        use InternalCircuitIndex::*;
        use internal_circuits::stages::native::query;

        let w = *w.value().take();
        let x = *x.value().take();
        let y = *y.value().take();
        let z = *z.value().take();
        let xz = x * z;

        // Compute mesh_xy components
        let mesh_xy_poly = self.circuit_mesh.xy(x, y);
        let mesh_xy_blind = C::CircuitField::random(&mut *rng);
        let mesh_xy_commitment =
            mesh_xy_poly.commit(C::host_generators(self.params), mesh_xy_blind);

        // Compute mesh_xy evaluations at each internal circuit's omega^j
        let mesh_at = |idx: InternalCircuitIndex| -> C::CircuitField {
            let circuit_id = idx.circuit_index(self.num_application_steps);
            mesh_xy_poly.eval(circuit_id.omega_j())
        };

        let query_witness = query::Witness {
            fixed_mesh: query::FixedMeshWitness {
                preamble_stage: mesh_at(PreambleStage),
                error_m_stage: mesh_at(ErrorMStage),
                error_n_stage: mesh_at(ErrorNStage),
                query_stage: mesh_at(QueryStage),
                eval_stage: mesh_at(EvalStage),
                error_n_final_staged: mesh_at(ErrorNFinalStaged),
                eval_final_staged: mesh_at(EvalFinalStaged),
                hashes_1_circuit: mesh_at(Hashes1Circuit),
                hashes_2_circuit: mesh_at(Hashes2Circuit),
                partial_collapse_circuit: mesh_at(PartialCollapseCircuit),
                full_collapse_circuit: mesh_at(FullCollapseCircuit),
                compute_v_circuit: mesh_at(ComputeVCircuit),
            },
            mesh_wxy: mesh_xy_poly.eval(w),
            left: query::ChildEvaluationsWitness::from_proof(
                left,
                w,
                x,
                xz,
                &mesh_xy_poly,
                &error_m.mesh_wy_poly,
            ),
            right: query::ChildEvaluationsWitness::from_proof(
                right,
                w,
                x,
                xz,
                &mesh_xy_poly,
                &error_m.mesh_wy_poly,
            ),
        };

        let stage_rx = query::Stage::<C, R, HEADER_SIZE>::rx(&query_witness)?;
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        // Nested query commitment (bundles mesh_xy_commitment + stage_commitment)
        let nested_query_witness = stages::nested::query::Witness {
            native_query: stage_commitment,
            mesh_xy: mesh_xy_commitment,
        };
        let nested_rx = stages::nested::query::Stage::<C::HostCurve, R>::rx(&nested_query_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::Query {
                mesh_xy_poly,
                mesh_xy_blind,
                mesh_xy_commitment,
                stage_rx,
                stage_blind,
                stage_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            query_witness,
        ))
    }

    /// Compute the F polynomial proof.
    fn compute_f<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        x: &Element<'dr, D>,
        alpha: &Element<'dr, D>,
        s_prime: &proof::SPrime<C, R>,
        error_m: &proof::ErrorM<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<proof::F<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        use InternalCircuitIndex::*;
        use arithmetic::factor_iter;
        use internal_circuits::stages::nested::f;

        let w = *w.value().take();
        let y = *y.value().take();
        let z = *z.value().take();
        let x = *x.value().take();
        let xz = x * z;
        let alpha = *alpha.value().take();

        let omega_j = |idx: InternalCircuitIndex| -> C::CircuitField {
            idx.circuit_index(self.num_application_steps).omega_j()
        };

        // List of each query of every polynomial in this fuse step.
        let mut iters = [
            // Check p(X) accumulator
            factor_iter(left.p.poly.iter_coeffs(), left.challenges.u),
            factor_iter(right.p.poly.iter_coeffs(), right.challenges.u),
            // Consistency checks for mesh polynomials
            factor_iter(left.query.mesh_xy_poly.iter_coeffs(), w),
            factor_iter(right.query.mesh_xy_poly.iter_coeffs(), w),
            factor_iter(s_prime.mesh_wx0_poly.iter_coeffs(), left.challenges.y),
            factor_iter(s_prime.mesh_wx1_poly.iter_coeffs(), right.challenges.y),
            factor_iter(s_prime.mesh_wx0_poly.iter_coeffs(), y),
            factor_iter(s_prime.mesh_wx1_poly.iter_coeffs(), y),
            factor_iter(error_m.mesh_wy_poly.iter_coeffs(), left.challenges.x),
            factor_iter(error_m.mesh_wy_poly.iter_coeffs(), right.challenges.x),
            factor_iter(error_m.mesh_wy_poly.iter_coeffs(), x),
            factor_iter(query.mesh_xy_poly.iter_coeffs(), w),
            // Fixed mesh polynomial queries at internal circuit omega^j points
            factor_iter(query.mesh_xy_poly.iter_coeffs(), omega_j(PreambleStage)),
            factor_iter(query.mesh_xy_poly.iter_coeffs(), omega_j(ErrorMStage)),
            factor_iter(query.mesh_xy_poly.iter_coeffs(), omega_j(ErrorNStage)),
            factor_iter(query.mesh_xy_poly.iter_coeffs(), omega_j(QueryStage)),
            factor_iter(query.mesh_xy_poly.iter_coeffs(), omega_j(EvalStage)),
            factor_iter(query.mesh_xy_poly.iter_coeffs(), omega_j(ErrorNFinalStaged)),
            factor_iter(query.mesh_xy_poly.iter_coeffs(), omega_j(EvalFinalStaged)),
            factor_iter(query.mesh_xy_poly.iter_coeffs(), omega_j(Hashes1Circuit)),
            factor_iter(query.mesh_xy_poly.iter_coeffs(), omega_j(Hashes2Circuit)),
            factor_iter(
                query.mesh_xy_poly.iter_coeffs(),
                omega_j(PartialCollapseCircuit),
            ),
            factor_iter(
                query.mesh_xy_poly.iter_coeffs(),
                omega_j(FullCollapseCircuit),
            ),
            factor_iter(query.mesh_xy_poly.iter_coeffs(), omega_j(ComputeVCircuit)),
            // Mesh polynomial queries at child proof circuit_ids
            factor_iter(
                query.mesh_xy_poly.iter_coeffs(),
                left.application.circuit_id.omega_j(),
            ),
            factor_iter(
                query.mesh_xy_poly.iter_coeffs(),
                right.application.circuit_id.omega_j(),
            ),
            // Child A/B polynomial queries at current x
            factor_iter(left.ab.a_poly.iter_coeffs(), x),
            factor_iter(left.ab.b_poly.iter_coeffs(), x),
            factor_iter(right.ab.a_poly.iter_coeffs(), x),
            factor_iter(right.ab.b_poly.iter_coeffs(), x),
            // Current step A/B polynomial queries at x
            factor_iter(ab.a_poly.iter_coeffs(), x),
            factor_iter(ab.b_poly.iter_coeffs(), x),
            // Left child proof stage/circuit polynomials
            factor_iter(left.preamble.stage_rx.iter_coeffs(), x),
            factor_iter(left.preamble.stage_rx.iter_coeffs(), xz),
            factor_iter(left.error_m.stage_rx.iter_coeffs(), x),
            factor_iter(left.error_m.stage_rx.iter_coeffs(), xz),
            factor_iter(left.error_n.stage_rx.iter_coeffs(), x),
            factor_iter(left.error_n.stage_rx.iter_coeffs(), xz),
            factor_iter(left.query.stage_rx.iter_coeffs(), x),
            factor_iter(left.query.stage_rx.iter_coeffs(), xz),
            factor_iter(left.eval.stage_rx.iter_coeffs(), x),
            factor_iter(left.eval.stage_rx.iter_coeffs(), xz),
            factor_iter(left.application.rx.iter_coeffs(), x),
            factor_iter(left.application.rx.iter_coeffs(), xz),
            factor_iter(left.circuits.hashes_1_rx.iter_coeffs(), x),
            factor_iter(left.circuits.hashes_1_rx.iter_coeffs(), xz),
            factor_iter(left.circuits.hashes_2_rx.iter_coeffs(), x),
            factor_iter(left.circuits.hashes_2_rx.iter_coeffs(), xz),
            factor_iter(left.circuits.partial_collapse_rx.iter_coeffs(), x),
            factor_iter(left.circuits.partial_collapse_rx.iter_coeffs(), xz),
            factor_iter(left.circuits.full_collapse_rx.iter_coeffs(), x),
            factor_iter(left.circuits.full_collapse_rx.iter_coeffs(), xz),
            factor_iter(left.circuits.compute_v_rx.iter_coeffs(), x),
            factor_iter(left.circuits.compute_v_rx.iter_coeffs(), xz),
            // Right child proof stage/circuit polynomials
            factor_iter(right.preamble.stage_rx.iter_coeffs(), x),
            factor_iter(right.preamble.stage_rx.iter_coeffs(), xz),
            factor_iter(right.error_m.stage_rx.iter_coeffs(), x),
            factor_iter(right.error_m.stage_rx.iter_coeffs(), xz),
            factor_iter(right.error_n.stage_rx.iter_coeffs(), x),
            factor_iter(right.error_n.stage_rx.iter_coeffs(), xz),
            factor_iter(right.query.stage_rx.iter_coeffs(), x),
            factor_iter(right.query.stage_rx.iter_coeffs(), xz),
            factor_iter(right.eval.stage_rx.iter_coeffs(), x),
            factor_iter(right.eval.stage_rx.iter_coeffs(), xz),
            factor_iter(right.application.rx.iter_coeffs(), x),
            factor_iter(right.application.rx.iter_coeffs(), xz),
            factor_iter(right.circuits.hashes_1_rx.iter_coeffs(), x),
            factor_iter(right.circuits.hashes_1_rx.iter_coeffs(), xz),
            factor_iter(right.circuits.hashes_2_rx.iter_coeffs(), x),
            factor_iter(right.circuits.hashes_2_rx.iter_coeffs(), xz),
            factor_iter(right.circuits.partial_collapse_rx.iter_coeffs(), x),
            factor_iter(right.circuits.partial_collapse_rx.iter_coeffs(), xz),
            factor_iter(right.circuits.full_collapse_rx.iter_coeffs(), x),
            factor_iter(right.circuits.full_collapse_rx.iter_coeffs(), xz),
            factor_iter(right.circuits.compute_v_rx.iter_coeffs(), x),
            factor_iter(right.circuits.compute_v_rx.iter_coeffs(), xz),
        ];

        let mut coeffs = Vec::new();
        while let Some(first) = iters[0].next() {
            let c = iters[1..]
                .iter_mut()
                .fold(first, |acc, iter| alpha * acc + iter.next().unwrap());
            coeffs.push(c);
        }
        coeffs.reverse();

        let poly = unstructured::Polynomial::from_coeffs(coeffs);
        let blind = C::CircuitField::random(&mut *rng);
        let commitment = poly.commit(C::host_generators(self.params), blind);

        let nested_f_witness = f::Witness {
            native_f: commitment,
        };
        let nested_rx = f::Stage::<C::HostCurve, R>::rx(&nested_f_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok(proof::F {
            poly,
            blind,
            commitment,
            nested_rx,
            nested_blind,
            nested_commitment,
        })
    }

    /// Commit to the evaluations of various polynomials at point $u$.
    fn compute_eval<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        error_m: &proof::ErrorM<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
    ) -> Result<(
        proof::Eval<C, R>,
        internal_circuits::stages::native::eval::Witness<C::CircuitField>,
    )>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let u = *u.value().take();

        let eval_witness = internal_circuits::stages::native::eval::Witness {
            left: stages::native::eval::ChildEvaluationsWitness::from_proof(left, u),
            right: stages::native::eval::ChildEvaluationsWitness::from_proof(right, u),
            current: stages::native::eval::CurrentStepWitness {
                mesh_wx0: s_prime.mesh_wx0_poly.eval(u),
                mesh_wx1: s_prime.mesh_wx1_poly.eval(u),
                mesh_wy: error_m.mesh_wy_poly.eval(u),
                a_poly: ab.a_poly.eval(u),
                b_poly: ab.b_poly.eval(u),
                mesh_xy: query.mesh_xy_poly.eval(u),
            },
        };
        let stage_rx =
            internal_circuits::stages::native::eval::Stage::<C, R, HEADER_SIZE>::rx(&eval_witness)?;
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        let nested_eval_witness = internal_circuits::stages::nested::eval::Witness {
            native_eval: stage_commitment,
        };
        let nested_rx = internal_circuits::stages::nested::eval::Stage::<C::HostCurve, R>::rx(
            &nested_eval_witness,
        )?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            proof::Eval {
                stage_rx,
                stage_blind,
                stage_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            eval_witness,
        ))
    }

    /// Compute the $P$ polynomial proof.
    fn compute_p<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        beta: &Element<'dr, D>,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        error_m: &proof::ErrorM<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        f: &proof::F<C, R>,
    ) -> Result<proof::P<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let beta = *beta.value().take();
        let u = *u.value().take();

        let mut poly = f.poly.clone();

        let acc_s = |p: &mut unstructured::Polynomial<_, _>, term| {
            p.scale(beta);
            p.add_structured(term);
        };
        let acc_u = |p: &mut unstructured::Polynomial<_, _>, term| {
            p.scale(beta);
            p.add_assign(term);
        };

        for proof in [left, right] {
            acc_s(&mut poly, &proof.application.rx);
            acc_s(&mut poly, &proof.preamble.stage_rx);
            acc_s(&mut poly, &proof.error_m.stage_rx);
            acc_s(&mut poly, &proof.error_n.stage_rx);
            acc_s(&mut poly, &proof.ab.a_poly);
            acc_s(&mut poly, &proof.ab.b_poly);
            acc_s(&mut poly, &proof.query.stage_rx);
            acc_u(&mut poly, &proof.query.mesh_xy_poly);
            acc_s(&mut poly, &proof.eval.stage_rx);
            acc_u(&mut poly, &proof.p.poly);
            acc_s(&mut poly, &proof.circuits.hashes_1_rx);
            acc_s(&mut poly, &proof.circuits.hashes_2_rx);
            acc_s(&mut poly, &proof.circuits.partial_collapse_rx);
            acc_s(&mut poly, &proof.circuits.full_collapse_rx);
            acc_s(&mut poly, &proof.circuits.compute_v_rx);
        }

        acc_u(&mut poly, &s_prime.mesh_wx0_poly);
        acc_u(&mut poly, &s_prime.mesh_wx1_poly);
        acc_s(&mut poly, &error_m.mesh_wy_poly);
        acc_s(&mut poly, &ab.a_poly);
        acc_s(&mut poly, &ab.b_poly);
        acc_u(&mut poly, &query.mesh_xy_poly);

        let blind = C::CircuitField::random(&mut *rng);
        let commitment = poly.commit(C::host_generators(self.params), blind);

        // Compute v = p(u)
        let v = poly.eval(u);

        Ok(proof::P {
            poly,
            blind,
            commitment,
            v,
        })
    }

    /// Compute internal circuits.
    fn compute_internal_circuits<RNG: Rng>(
        &self,
        rng: &mut RNG,
        preamble: &proof::Preamble<C, R>,
        s_prime: &proof::SPrime<C, R>,
        error_m: &proof::ErrorM<C, R>,
        error_n: &proof::ErrorN<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        f: &proof::F<C, R>,
        eval: &proof::Eval<C, R>,
        p: &proof::P<C, R>,
        preamble_witness: &stages::native::preamble::Witness<'_, C, R, HEADER_SIZE>,
        error_m_witness: &stages::native::error_m::Witness<C, NativeParameters>,
        error_n_witness: &stages::native::error_n::Witness<C, NativeParameters>,
        query_witness: &internal_circuits::stages::native::query::Witness<C>,
        eval_witness: &internal_circuits::stages::native::eval::Witness<C::CircuitField>,
        challenges: &proof::Challenges<C>,
    ) -> Result<proof::InternalCircuits<C, R>> {
        // Build unified instance from proof structs and challenges.
        let unified_instance = &unified::Instance {
            nested_preamble_commitment: preamble.nested_commitment,
            w: challenges.w,
            nested_s_prime_commitment: s_prime.nested_s_prime_commitment,
            y: challenges.y,
            z: challenges.z,
            nested_error_m_commitment: error_m.nested_commitment,
            mu: challenges.mu,
            nu: challenges.nu,
            nested_error_n_commitment: error_n.nested_commitment,
            mu_prime: challenges.mu_prime,
            nu_prime: challenges.nu_prime,
            c: ab.c,
            nested_ab_commitment: ab.nested_commitment,
            x: challenges.x,
            nested_query_commitment: query.nested_commitment,
            alpha: challenges.alpha,
            nested_f_commitment: f.nested_commitment,
            u: challenges.u,
            nested_eval_commitment: eval.nested_commitment,
            beta: challenges.beta,
            v: p.v,
        };

        // hashes_1 staged circuit.
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
            hashes_1_rx.commit(C::host_generators(self.params), hashes_1_rx_blind);

        // hashes_2 staged circuit.
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
            hashes_2_rx.commit(C::host_generators(self.params), hashes_2_rx_blind);

        // partial_collapse staged circuit (layer 1 folding verification).
        let (partial_collapse_rx, _) = internal_circuits::partial_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::new()
        .rx::<R>(
            internal_circuits::partial_collapse::Witness {
                preamble_witness,
                unified_instance,
                error_m_witness,
                error_n_witness,
            },
            self.circuit_mesh.get_key(),
        )?;
        let partial_collapse_rx_blind = C::CircuitField::random(&mut *rng);
        let partial_collapse_rx_commitment =
            partial_collapse_rx.commit(C::host_generators(self.params), partial_collapse_rx_blind);

        // full_collapse staged circuit.
        let (full_collapse_rx, _) =
            internal_circuits::full_collapse::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new()
                .rx::<R>(
                    internal_circuits::full_collapse::Witness {
                        unified_instance,
                        preamble_witness,
                        error_m_witness,
                        error_n_witness,
                    },
                    self.circuit_mesh.get_key(),
                )?;
        let full_collapse_rx_blind = C::CircuitField::random(&mut *rng);
        let full_collapse_rx_commitment =
            full_collapse_rx.commit(C::host_generators(self.params), full_collapse_rx_blind);

        // compute_v staged circuit.
        let (compute_v_rx, _) = internal_circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new(
            self.num_application_steps,
        )
        .rx::<R>(
            internal_circuits::compute_v::Witness {
                unified_instance,
                preamble_witness,
                query_witness,
                eval_witness,
            },
            self.circuit_mesh.get_key(),
        )?;
        let compute_v_rx_blind = C::CircuitField::random(&mut *rng);
        let compute_v_rx_commitment =
            compute_v_rx.commit(C::host_generators(self.params), compute_v_rx_blind);

        Ok(proof::InternalCircuits {
            hashes_1_rx,
            hashes_1_blind: hashes_1_rx_blind,
            hashes_1_commitment: hashes_1_rx_commitment,
            hashes_2_rx,
            hashes_2_blind: hashes_2_rx_blind,
            hashes_2_commitment: hashes_2_rx_commitment,
            partial_collapse_rx,
            partial_collapse_blind: partial_collapse_rx_blind,
            partial_collapse_commitment: partial_collapse_rx_commitment,
            full_collapse_rx,
            full_collapse_blind: full_collapse_rx_blind,
            full_collapse_commitment: full_collapse_rx_commitment,
            compute_v_rx,
            compute_v_blind: compute_v_rx_blind,
            compute_v_commitment: compute_v_rx_commitment,
        })
    }
}

/// Context for the prover to assemble a/b polynomial vectors for error term
/// computation.
///
/// TODO: Extract shared logic with `Verifier` into a common `ClaimBuilder` trait.
struct ProverContext<'m, 'rx, F: PrimeField, R: Rank> {
    circuit_mesh: &'m Mesh<'m, F, R>,
    num_application_steps: usize,
    y: F,
    z: F,
    tz: structured::Polynomial<F, R>,
    a: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
    b: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
}

impl<'m, 'rx, F: PrimeField, R: Rank> ProverContext<'m, 'rx, F, R> {
    /// Create a new prover context for assembling revdot claim polynomials.
    fn new(circuit_mesh: &'m Mesh<'m, F, R>, num_application_steps: usize, y: F, z: F) -> Self {
        Self {
            circuit_mesh,
            num_application_steps,
            y,
            z,
            tz: R::tz(z),
            a: Vec::new(),
            b: Vec::new(),
        }
    }

    /// Add a circuit claim with mesh polynomial transformation.
    ///
    /// Sets a = rx, b = rx(z) + s(y) + t(z).
    fn circuit(&mut self, circuit_id: CircuitIndex, rx: &'rx structured::Polynomial<F, R>) {
        self.circuit_impl(circuit_id, Cow::Borrowed(rx));
    }

    fn circuit_impl(
        &mut self,
        circuit_id: CircuitIndex,
        rx: Cow<'rx, structured::Polynomial<F, R>>,
    ) {
        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);
        let mut b = rx.as_ref().clone();
        b.dilate(self.z);
        b.add_assign(&sy);
        b.add_assign(&self.tz);

        self.a.push(rx);
        self.b.push(Cow::Owned(b));
    }

    /// Add an internal circuit claim, summing multiple stage polynomials.
    ///
    /// Sets a = sum(rxs), b = sum(rxs)(z) + s(y) + t(z).
    /// Used for hashes, collapse, and compute_v circuits.
    fn internal_circuit(
        &mut self,
        id: InternalCircuitIndex,
        rxs: &[&'rx structured::Polynomial<F, R>],
    ) {
        assert!(!rxs.is_empty(), "must provide at least one rx polynomial");
        let circuit_id = id.circuit_index(self.num_application_steps);

        let rx = if rxs.len() == 1 {
            Cow::Borrowed(rxs[0])
        } else {
            let mut sum = rxs[0].clone();
            for rx in &rxs[1..] {
                sum.add_assign(rx);
            }
            Cow::Owned(sum)
        };

        self.circuit_impl(circuit_id, rx);
    }

    /// Add a stage claim for batching stage polynomial verification.
    ///
    /// Sets a = fold(rxs, z), b = s(y). Used for k(y) = 0 stage checks.
    fn stage(&mut self, id: InternalCircuitIndex, rxs: &[&'rx structured::Polynomial<F, R>]) {
        assert!(!rxs.is_empty(), "must provide at least one rx polynomial");

        let circuit_id = id.circuit_index(self.num_application_steps);
        let sy = self.circuit_mesh.circuit_y(circuit_id, self.y);

        let a = if rxs.len() == 1 {
            Cow::Borrowed(rxs[0])
        } else {
            Cow::Owned(structured::Polynomial::fold(rxs.iter().copied(), self.z))
        };

        self.a.push(a);
        self.b.push(Cow::Owned(sy));
    }

    /// Add a raw claim without any mesh polynomial transformation.
    ///
    /// Used for proof::AB claims where k(y) = c (the revdot product).
    fn raw_claim(
        &mut self,
        a: &'rx structured::Polynomial<F, R>,
        b: &'rx structured::Polynomial<F, R>,
    ) {
        self.a.push(Cow::Borrowed(a));
        self.b.push(Cow::Borrowed(b));
    }
}
