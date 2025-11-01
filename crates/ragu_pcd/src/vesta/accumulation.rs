use crate::accumulator::{ConsistencyEvaluations, CycleAccumulator, FinalEvaluations};
use crate::engine::CycleEngine;
use crate::staging::b_stage::BInnerStage;
use crate::staging::d_stage::{
    D1InnerStage, D2InnerStage, DIndirectionStage, DSubcircuit1, DSubcircuit1Witness, DSubcircuit2,
    DSubcircuit2Witness, ErrorInnerStage,
};
use crate::staging::e_stage::{E2InnerStage, EIndirectionStage, ESubcircuit1, ESubcircuit1Witness};
use crate::transcript::AccumulationTranscript;
use crate::utilities::dummy_circuits::Circuits;
use crate::vesta::structures::{CommittedPolynomial, CommittedStructured};
use arithmetic::{Cycle, FixedGenerators, factor_iter};
use ff::Field;
use ragu_circuits::CircuitExt;
use ragu_circuits::mesh::Mesh;
use ragu_circuits::polynomials::{structured, unstructured};
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageExt, Staged},
};
use ragu_core::{Error, Result};
use ragu_pasta::Fp;
use rand::rngs::OsRng;
use rand::thread_rng;

impl<'a, C: Cycle + Default, R: Rank> CycleEngine<'a, C, R> {
    /// Executes the Vesta-side accumulation step.
    ///
    /// This is an Fp round: computations occur over Fp, and commitments
    /// are made on the Vesta host curve.
    pub fn accumulation_vesta(
        mesh: &Mesh<'_, C::CircuitField, R>,
        witnesses: &[C::CircuitField],
        acc1: &CycleAccumulator<C::HostCurve, C::NestedCurve, R>,
        acc2: &CycleAccumulator<C::HostCurve, C::NestedCurve, R>,
        cycle: &C,
    ) -> Result<()>
    where
        C: Cycle<CircuitField = Fp>,
    {
        // Mirror the dummy circuits instantiated in the mesh.
        const N: usize = 4;
        let circuits = Circuits::new();
        let circuit_list = [&circuits.s3, &circuits.s4, &circuits.s10, &circuits.s19];
        let circuit_ids: [C::CircuitField; N] =
            core::array::from_fn(|i| C::CircuitField::from(i as u64));

        // Intantiate a DUMMY transcript object.
        let mut transcript = AccumulationTranscript::<C::CircuitField>::new();

        // Instantiate new accumulator object, which contains the prover's split accumulator witness and instance parts.
        let cycle_accumulator = CycleAccumulator::<C::HostCurve, C::NestedCurve, R>::base(
            mesh,
            cycle.host_generators(),
        );

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Process endoscalars.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TODO: Determine the endoscaling operations, representing deferreds from the other curve.

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Map what needs to be deffered using some kind of map.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TODO: Collect all the deferreds we've marked in the code.

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Process `StagedObjects`.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TODO: Check the staged objects for staging consistency.

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Process other public inputs.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TODO: Determine what objects need to be in the public inputs.

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Process the application circuits. The witness polynomials
        // r(X) are over Fp, and produce commitments to Vesta points.
        ///////////////////////////////////////////////////////////////////////////////////////

        let mut a_polys = Vec::with_capacity(N + 2);
        let mut ky = Vec::with_capacity(N);

        for (&witness, circuit) in witnesses.iter().zip(circuit_list.iter()) {
            let (rx_poly, instance) = circuit.rx::<R>(witness)?;
            let blinding = C::CircuitField::random(OsRng);
            let commitment = rx_poly.commit(cycle.host_generators(), blinding);

            // r(X) witness polynomial.
            a_polys.push(CommittedPolynomial {
                poly: rx_poly,
                blind: blinding,
                commitment,
            });

            // k(Y) constraint polynomial.
            ky.push(circuit.ky(instance)?);
        }

        // Append the previous accumulator A polynomials.
        a_polys.push(CommittedPolynomial {
            poly: acc1.accumulator.witness.a_poly.clone(),
            blind: acc1.accumulator.witness.a_blinding,
            commitment: acc1.accumulator.instance.a,
        });
        a_polys.push(CommittedPolynomial {
            poly: acc2.accumulator.witness.a_poly.clone(),
            blind: acc2.accumulator.witness.a_blinding,
            commitment: acc2.accumulator.instance.a,
        });

        // TRANSCRIPT: Absorb k(Y) constraint evaluations.
        for instance in &ky {
            instance.iter().for_each(|&s| transcript.absorb_scalar(s));
        }

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: B STAGE. This uses a two-layer nested encoding.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Collect application circuit commitments (Vesta points).
        let a_commitments: [C::HostCurve; N + 2] = a_polys
            .iter()
            .map(|c| c.commitment)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(N))?;

        type BStagingPolynomial<C, const N: usize> = BInnerStage<C, N>;

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the Vesta commitments to r(X).
        let b_inner_rx = <BStagingPolynomial<C::HostCurve, { N + 2 }> as StageExt<
            C::ScalarField,
            R,
        >>::rx(&a_commitments)?;

        // NESTED ENCODING: Commit to the *partial* staging polynomial using Pallas generators (nested curve).
        let b_blinding = C::ScalarField::random(OsRng);
        let b_nested_commitment = b_inner_rx.commit(cycle.nested_generators(), b_blinding);

        // TRANSCRIPT: Absorb B stage commitment before deriving w challenge.
        transcript.absorb_point(b_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: D STAGE. This uses a two-layer nested encoding.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: W challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Derive w challenge from B commitment using Poseidon hash.
        //
        // NOTE: for now, this is a placeholder that we'll replace with an actual
        // call to Poseidon. We compute this off-circuit that allows us to continue
        // with the computation, similiar to predict(), and then later verify
        // it was computed properly inside the circuit.

        // TRANSCRIPT: Squeeze w challenge.
        let w_challenge = transcript.squeeze();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S' Mesh Polynomials.
        ///////////////////////////////////////////////////////////////////////////////////////

        // COMPUTE S': For each previous accumulator, compute M(w, x_i, Y) for checking mesh consistency.
        let s1_poly_acc1 = mesh.wx(w_challenge, acc1.accumulator.instance.x.0);
        let s1_blinding_acc1 = C::CircuitField::random(thread_rng());
        let s1_commitment_acc1 = s1_poly_acc1.commit(cycle.host_generators(), s1_blinding_acc1);

        let s1_poly_acc2 = mesh.wx(w_challenge, acc2.accumulator.instance.x.0);
        let s1_blinding_acc2 = C::CircuitField::random(thread_rng());
        let s1_commitment_acc2 = s1_poly_acc2.commit(cycle.host_generators(), s1_blinding_acc2);

        let s_prime = [
            CommittedPolynomial {
                poly: s1_poly_acc1,
                blind: s1_blinding_acc1,
                commitment: s1_commitment_acc1,
            },
            CommittedPolynomial {
                poly: s1_poly_acc2,
                blind: s1_blinding_acc2,
                commitment: s1_commitment_acc2,
            },
        ];

        let s_prime_commitments = [s_prime[0].commitment, s_prime[1].commitment];

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: D1 Two-Layer Nested Encoding.
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S' Vesta commitments.
        let d1_inner_rx = <D1InnerStage<C::HostCurve, 2> as StageExt<C::ScalarField, R>>::rx(
            &s_prime_commitments,
        )?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let d1_blinding = C::ScalarField::random(OsRng);
        let d1_nested_commitment = d1_inner_rx.commit(cycle.nested_generators(), d1_blinding);

        transcript.absorb_point(d1_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Y challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze y challenge.
        let y_challenge = transcript.squeeze();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S'' Mesh Polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        // COMPUTE S'': M(w, X, y) polynomial for final mesh consistency checks.
        let s2_poly = mesh.wy(w_challenge, y_challenge);
        let s2_blinding = C::CircuitField::random(thread_rng());
        let s2_commitment = s2_poly.commit(cycle.host_generators(), s2_blinding);

        let s_prime_prime = [CommittedPolynomial {
            poly: s2_poly,
            blind: s2_blinding,
            commitment: s2_commitment,
        }];

        // Append previous accumulator revdot claims as diagonal terms.
        let mut ky: Vec<Fp> = ky
            .iter()
            .map(|ky| arithmetic::eval(ky, y_challenge))
            .collect();
        ky.push(acc1.accumulator.instance.c);
        ky.push(acc2.accumulator.instance.c);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: D2 Two-Layer Nested Encoding
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S'' Vesta commitment.
        let d2_inner_rx =
            <D2InnerStage<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[s2_commitment])?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let d2_blinding = C::ScalarField::random(OsRng);
        let d2_nested_commitment = d2_inner_rx.commit(cycle.nested_generators(), d2_blinding);

        transcript.absorb_point(d2_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Z challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze z challenge.
        let z_challenge = transcript.squeeze();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute B polynomials for revdot verification.
        //
        //  For each application circuit: B_i(X) = A_i(X) * z + t(X,z) + M(circuit_id, X, y),
        //  and this construction ensures: A_i (revdot) B_i = k_i(y).
        ///////////////////////////////////////////////////////////////////////////////////////

        let tz = R::tz(z_challenge);
        let mut b_polys: Vec<CommittedStructured<R, C::HostCurve>> = a_polys
            .iter()
            .take(N)
            .zip(circuit_ids.iter())
            .map(|(a, &circuit_id)| {
                let mut b_poly = a.poly.clone();
                b_poly.dilate(z_challenge);
                b_poly.add_assign(&tz);
                b_poly.add_assign(&mesh.wy(circuit_id, y_challenge));

                let b_blinding = C::CircuitField::random(thread_rng());
                let b_commitment = b_poly.commit(cycle.host_generators(), b_blinding);

                CommittedPolynomial {
                    poly: b_poly,
                    blind: b_blinding,
                    commitment: b_commitment,
                }
            })
            .collect();

        // Append existing accumulator B polynomials.
        b_polys.push(CommittedPolynomial {
            poly: acc1.accumulator.witness.b_poly.clone(),
            blind: acc1.accumulator.witness.b_blinding,
            commitment: acc1.accumulator.instance.b,
        });
        b_polys.push(CommittedPolynomial {
            poly: acc2.accumulator.witness.b_poly.clone(),
            blind: acc2.accumulator.witness.b_blinding,
            commitment: acc2.accumulator.instance.b,
        });

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute error / slack term (from folding multiple revdot checks)
        // before computing the u and v evaluations.
        ///////////////////////////////////////////////////////////////////////////////////////

        // The prover computes all of the cross products a_i . b_j for i != j.
        let len = a_polys.len();
        let mut cross_products = Vec::new();
        for i in 0..len {
            for j in 0..len {
                if i != j {
                    let cross = a_polys[i].poly.revdot(&b_polys[j].poly);
                    cross_products.push(cross);
                }
            }
        }

        let mut cross_commitments = Vec::new();
        for cross_scalar in &cross_products {
            let blinding = C::CircuitField::random(OsRng);
            let commitment = cycle
                .host_generators()
                .short_commit(*cross_scalar, blinding);
            cross_commitments.push(commitment);
        }

        const CROSS_COUNT: usize = (N + 2) * (N + 1);
        let cross_array: [C::HostCurve; CROSS_COUNT] = cross_commitments
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(CROSS_COUNT))?;

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the cross-terms Vesta commitment.
        let d3_inner_rx = <ErrorInnerStage<C::HostCurve, CROSS_COUNT> as StageExt<
            C::ScalarField,
            R,
        >>::rx(&cross_array)?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let d3_blinding = C::ScalarField::random(OsRng);
        let d3_nested_commitment = d3_inner_rx.commit(cycle.nested_generators(), d3_blinding);

        // TRANSCRIPT: Absorb D3 stage commitment.
        transcript.absorb_point(d3_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Challenge circuit: verify w, y, and z challenges in-circuit.
        ///////////////////////////////////////////////////////////////////////////////////////

        let d_witness = DSubcircuit1Witness {
            b_nested_commitment,
            w_challenge,
            d1_nested_commitment,
            y_challenge,
            d2_nested_commitment,
            z_challenge,
            d3_nested_commitment,
        };

        let d_circuit = Staged::<Fp, R, _>::new(DSubcircuit1::<C::NestedCurve>::new());
        let (d_rx, _d_aux) = d_circuit.rx::<R>(d_witness)?;

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable, partially nested commitment for use in the transcript.
        let d_staged_circuit_blinding = C::CircuitField::random(OsRng);
        let d_staged_circuit_commitment =
            d_rx.commit(cycle.host_generators(), d_staged_circuit_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
        let d_staged_circuit_inner = <DIndirectionStage<C::HostCurve> as StageExt<
            C::ScalarField,
            R,
        >>::rx(d_staged_circuit_commitment)?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let d_staged_circuit_nested_blinding = C::ScalarField::random(OsRng);
        let d_staged_circuit_nested_commitment = d_staged_circuit_inner
            .commit(cycle.nested_generators(), d_staged_circuit_nested_blinding);

        transcript.absorb_point(d_staged_circuit_nested_commitment);
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: mu and nu challenge derivation for checking revdot claims are correct.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze mu challenge.
        let mu_challenge = transcript.squeeze();

        // TRANSCRIPT: Absorb mu challenge.
        transcript.absorb_scalar(mu_challenge);

        // TRANSCRIPT: Squeeze nu challenge.
        let nu_challenge = transcript.squeeze();

        let mu_inv = mu_challenge.invert().unwrap();
        let munu = mu_challenge * nu_challenge;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute C. The expected value of c = a.revdot(b).
        ///////////////////////////////////////////////////////////////////////////////////////

        // STAGED CIRCUIT: This simply allocates the partial nested commitment point inside the staged circuit.
        let c_circuit = Staged::<Fp, R, _>::new(DSubcircuit2::<C::NestedCurve>::new());
        let (c_rx, _c_aux) = c_circuit.rx::<R>(DSubcircuit2Witness {
            d3_nested_commitment,
            mu_challenge,
            nu_challenge,
            mu_inv,
            cross_products,
            ky_values: ky,
            len,
        })?;

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable, partially nested commitment for use in the transcript.
        let c_staged_circuit_blinding = C::CircuitField::random(OsRng);
        let c_staged_circuit_commitment =
            c_rx.commit(cycle.host_generators(), c_staged_circuit_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the B staged circuit Vesta commitment.
        let c_staged_circuit_inner = <DIndirectionStage<C::HostCurve> as StageExt<
            C::ScalarField,
            R,
        >>::rx(c_staged_circuit_commitment)?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let c_staged_circuit_nested_blinding = C::ScalarField::random(OsRng);
        let c_staged_circuit_nested_commitment = c_staged_circuit_inner
            .commit(cycle.nested_generators(), c_staged_circuit_nested_blinding);

        transcript.absorb_point(c_staged_circuit_nested_commitment);
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: E STAGE. This uses a two-layer nested encoding.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Check mu and nu challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // STAGED CIRCUIT: This simply allocates the partial nested commitment point inside the staged circuit.
        let e_circuit = Staged::<Fp, R, _>::new(ESubcircuit1::<C::NestedCurve>::new());
        let (e_rx, _e_aux) = e_circuit.rx::<R>(ESubcircuit1Witness {
            c_staged_circuit_nested_commitment,
            mu_challenge,
            nu_challenge,
        })?;

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable, partially nested commitment for use in the transcript.
        let e_staged_circuit_blinding = C::CircuitField::random(OsRng);
        let e_staged_circuit_commitment =
            e_rx.commit(cycle.host_generators(), e_staged_circuit_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the B staged circuit Vesta commitment.
        let e_staged_circuit_inner = <EIndirectionStage<C::HostCurve> as StageExt<
            C::ScalarField,
            R,
        >>::rx(e_staged_circuit_commitment)?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let e_staged_circuit_nested_blinding = C::ScalarField::random(OsRng);
        let cestaged_circuit_nested_commitment = c_staged_circuit_inner
            .commit(cycle.nested_generators(), e_staged_circuit_nested_blinding);

        transcript.absorb_point(cestaged_circuit_nested_commitment);
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Folding A and B polynomials into single polynomials.
        ///////////////////////////////////////////////////////////////////////////////////////

        let a_poly = structured::Polynomial::fold(a_polys.iter().map(|p| &p.poly), mu_inv);
        let a_blinding = C::CircuitField::random(OsRng);
        let a_commitment = a_poly.commit(cycle.host_generators(), a_blinding);

        let a_folded = CommittedPolynomial {
            poly: a_poly,
            blind: a_blinding,
            commitment: a_commitment,
        };

        let b_poly = structured::Polynomial::fold(a_polys.iter().map(|p| &p.poly), munu);
        let b_blinding = C::CircuitField::random(OsRng);
        let b_commitment = b_poly.commit(cycle.host_generators(), b_blinding);

        let b_folded = CommittedPolynomial {
            poly: b_poly,
            blind: b_blinding,
            commitment: b_commitment,
        };

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: x challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze x challenge.
        let x_challenge = transcript.squeeze();

        let xz = x_challenge * z_challenge;

        // TODO: This needs to be compputed inside the circuit.
        let txz = R::txz(x_challenge, z_challenge);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute S for mesh consistency.
        ///////////////////////////////////////////////////////////////////////////////////////

        let s_polynomial = mesh.xy(x_challenge, y_challenge);
        let s_blinding = C::CircuitField::random(OsRng);
        let s_commitment = s_polynomial.commit(cycle.host_generators(), s_blinding);

        let s = CommittedPolynomial {
            poly: s_polynomial,
            blind: s_blinding,
            commitment: s_commitment,
        };

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S Vesta commitment.
        let e1_inner_rx =
            <D2InnerStage<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[s_commitment])?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let e1_blinding = C::ScalarField::random(OsRng);
        let e1_nested_commitment = e1_inner_rx.commit(cycle.nested_generators(), e1_blinding);

        transcript.absorb_point(e1_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute evaluations.
        ///////////////////////////////////////////////////////////////////////////////////////

        let circuit_evaluations: [Fp; N] = [
            mesh.wxy(circuit_ids[0], x_challenge, y_challenge),
            mesh.wxy(circuit_ids[1], x_challenge, y_challenge),
            mesh.wxy(circuit_ids[2], x_challenge, y_challenge),
            mesh.wxy(circuit_ids[3], x_challenge, y_challenge),
        ];

        let consistency_evaluations = ConsistencyEvaluations::<C::HostCurve> {
            acc1_s_at_w: acc1.accumulator.witness.s_poly.eval(w_challenge),
            acc2_s_at_w: acc2.accumulator.witness.s_poly.eval(w_challenge),
            s1_acc1_at_y: s_prime[0].poly.eval(y_challenge),
            s1_acc2_at_y: s_prime[1].poly.eval(y_challenge),
            s2_at_x: s_prime_prime[0].poly.eval(x_challenge),
        };

        let a_polys_evals_x: Vec<Fp> = a_polys
            .iter()
            .map(|a_poly| a_poly.poly.eval(x_challenge))
            .collect();
        let a_polys_evals_xz: Vec<Fp> = a_polys
            .iter()
            .take(N)
            .map(|a_poly| a_poly.poly.eval(xz))
            .collect();
        let acc_b_evals_x = [
            acc1.accumulator.witness.b_poly.eval(x_challenge),
            acc2.accumulator.witness.b_poly.eval(x_challenge),
        ];

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute batched polynomial evaluation claims.
        ///////////////////////////////////////////////////////////////////////////////////////

        let batched_a_eval = {
            a_polys_evals_x
                .iter()
                .rev()
                .fold(Fp::zero(), |acc, &eval| acc * mu_inv + eval)
        };
        let batched_b_eval = {
            let circuit_b_evals = a_polys_evals_xz
                .iter()
                .zip(circuit_evaluations.iter())
                .map(|(&eval_xz, &circuit_eval)| eval_xz + txz + circuit_eval);

            let b_evals: Vec<_> = circuit_b_evals
                .chain(acc_b_evals_x.iter().copied())
                .collect();

            b_evals
                .iter()
                .rev()
                .fold(Fp::zero(), |acc, &eval| acc * munu + eval)
        };

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Absorb all evaluation data into the transcript before driving alpha.
        ///////////////////////////////////////////////////////////////////////////////////////

        for eval in circuit_evaluations {
            transcript.absorb_scalar(eval);
        }

        transcript.absorb_scalar(consistency_evaluations.acc1_s_at_w);
        transcript.absorb_scalar(consistency_evaluations.acc2_s_at_w);
        transcript.absorb_scalar(consistency_evaluations.s1_acc1_at_y);
        transcript.absorb_scalar(consistency_evaluations.s1_acc2_at_y);
        transcript.absorb_scalar(consistency_evaluations.s2_at_x);

        for eval in a_polys_evals_x {
            transcript.absorb_scalar(eval);
        }

        for eval in a_polys_evals_xz {
            transcript.absorb_scalar(eval);
        }

        for eval in acc_b_evals_x {
            transcript.absorb_scalar(eval);
        }

        transcript.absorb_scalar(batched_a_eval);
        transcript.absorb_scalar(batched_b_eval);

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: F STAGE.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: alpha challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze alpha challenge.
        let alpha_challenge = transcript.squeeze();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute and commit to the F polynomial which aggregates quotient
        // polynomials using the alpha challenge.
        ///////////////////////////////////////////////////////////////////////////////////////

        let f_polynomial = {
            let mut queries: Vec<Box<dyn Iterator<Item = Fp>>> = vec![
                factor_iter(a_folded.poly.iter_coeffs(), x_challenge),
                factor_iter(b_folded.poly.iter_coeffs(), x_challenge),
                factor_iter(
                    acc1.accumulator.witness.p_poly.iter_coeffs(),
                    acc1.accumulator.instance.u.0,
                ),
                factor_iter(
                    acc2.accumulator.witness.p_poly.iter_coeffs(),
                    acc2.accumulator.instance.u.0,
                ),
                factor_iter(acc1.accumulator.witness.s_poly.iter_coeffs(), w_challenge),
                factor_iter(acc2.accumulator.witness.s_poly.iter_coeffs(), w_challenge),
                factor_iter(s.poly.iter_coeffs(), circuit_ids[0]),
                factor_iter(s.poly.iter_coeffs(), circuit_ids[1]),
                factor_iter(s.poly.iter_coeffs(), circuit_ids[2]),
                factor_iter(s.poly.iter_coeffs(), circuit_ids[3]),
                factor_iter(s.poly.iter_coeffs(), w_challenge),
                factor_iter(s_prime[0].poly.iter_coeffs(), acc1.accumulator.instance.y.0),
                factor_iter(s_prime[1].poly.iter_coeffs(), acc2.accumulator.instance.y.0),
                factor_iter(s_prime[0].poly.iter_coeffs(), y_challenge),
                factor_iter(s_prime[1].poly.iter_coeffs(), y_challenge),
                factor_iter(
                    s_prime_prime[0].poly.iter_coeffs(),
                    acc1.accumulator.instance.x.0,
                ),
                factor_iter(
                    s_prime_prime[0].poly.iter_coeffs(),
                    acc2.accumulator.instance.x.0,
                ),
                factor_iter(s_prime_prime[0].poly.iter_coeffs(), x_challenge),
            ];

            for a_poly in &a_polys {
                queries.push(factor_iter(a_poly.poly.iter_coeffs(), x_challenge));
            }

            for a_poly in a_polys.iter().take(N) {
                queries.push(factor_iter(a_poly.poly.iter_coeffs(), xz));
            }

            let mut f_poly = Vec::with_capacity(R::num_coeffs());
            'poly: loop {
                let mut this_coeff = Fp::ZERO;
                for query in queries.iter_mut() {
                    this_coeff *= alpha_challenge;
                    if let Some(coeff) = query.next() {
                        this_coeff += coeff;
                    } else {
                        break 'poly;
                    }
                }
                f_poly.push(this_coeff);
            }
            f_poly.reverse();
            unstructured::Polynomial::<Fp, R>::from_coeffs(f_poly)
        };

        let f_blinding = C::CircuitField::random(OsRng);
        let f_commitment = f_polynomial.commit(cycle.host_generators(), f_blinding);

        let f = CommittedPolynomial {
            poly: f_polynomial,
            blind: f_blinding,
            commitment: f_commitment,
        };

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the F Vesta commitment.
        let e2_inner_rx =
            <E2InnerStage<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[f_commitment])?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let e2_blinding = C::ScalarField::random(OsRng);
        let e2_nested_commitment = e2_inner_rx.commit(cycle.nested_generators(), e2_blinding);

        transcript.absorb_point(e2_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: u challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze u challenge.
        let u_challenge = transcript.squeeze();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Supply the u evaluation claims.
        ///////////////////////////////////////////////////////////////////////////////////////

        let evaluations_final = FinalEvaluations::<C::HostCurve> {
            a: a_folded.poly.eval(u_challenge),
            b: b_folded.poly.eval(u_challenge),
            acc1_p: acc1.accumulator.witness.p_poly.eval(u_challenge),
            acc2_p: acc2.accumulator.witness.p_poly.eval(u_challenge),
            acc1_s: acc1.accumulator.witness.s_poly.eval(u_challenge),
            acc2_s: acc2.accumulator.witness.s_poly.eval(u_challenge),
            s: s.poly.eval(u_challenge),
            s1: [
                s_prime[0].poly.eval(u_challenge),
                s_prime[1].poly.eval(u_challenge),
            ],
            s2: s_prime_prime[0].poly.eval(u_challenge),
        };

        let a_polys_final_evals: Vec<Fp> = a_polys
            .iter()
            .map(|a_poly| a_poly.poly.eval(u_challenge))
            .collect();

        for eval in a_polys_final_evals {
            transcript.absorb_scalar(eval);
        }

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: b challenge derivation. This checks all evaluations are correct by
        // folding the claims together.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze b challenge.
        let b_challenge = transcript.squeeze();

        Ok(())
    }
}
