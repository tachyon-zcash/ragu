use std::array::from_fn;

use crate::accumulator::{
    Accumulator, AccumulatorInstance, AccumulatorWitness, ChallengePoint, ConsistencyEvaluations,
    EvaluationPoint, FinalEvaluations, StagedCircuitData, UncompressedAccumulator,
};
use crate::engine::CycleEngine;
use crate::staging::circuits::b_stage::EphemeralStageB;
use crate::staging::circuits::d_stage::{
    DCValueComputationStagedCircuit, DCValueComputationWitness, DChallengeDerivationStagedCircuit,
    DChallengeDerivationWitness, DStage, EphemeralStageD, IndirectionStageD,
};
use crate::staging::circuits::e_stage::{
    EChallengeDerivationStagedCircuit, EChallengeDerivationWitness, EStage, EphemeralStageE,
    IndirectionStageE,
};
use crate::staging::circuits::g_stage::{
    EphemeralStageG, GStage, GVComputationStagedCircuit, GVComputationStagedWitness,
    IndirectionStageG, KYStage, NUM_V_QUERIES,
};
use crate::staging::instance::UnifiedRecursionInstance;
use crate::utilities::dummy_circuits::Circuits;
use crate::vesta::commitments::{CommittedPolynomial, CommittedStructured};
use arithmetic::{Cycle, factor_iter};
use ff::Field;
use ragu_circuits::CircuitExt;
use ragu_circuits::mesh::Mesh;
use ragu_circuits::polynomials::{structured, unstructured};
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageExt, Staged},
};
use ragu_core::drivers::Driver;
use ragu_core::maybe::Maybe;
use ragu_core::{Error, Result};
use ragu_pasta::{Fp, PoseidonFp};
use ragu_primitives::GadgetExt;
use ragu_primitives::{Point, Sponge};
use rand::rngs::OsRng;

impl<'a, C: Cycle, R: Rank> CycleEngine<'a, C, R> {
    /// Executes the Vesta-side accumulation step.
    ///
    /// This is an Fp round: computations occur over Fp, and commitments
    /// are made on the Vesta host curve.
    pub fn accumulation_vesta(
        mesh: &Mesh<'_, C::CircuitField, R>,
        witnesses: &[C::CircuitField],
        acc1: &Accumulator<C::HostCurve, C::NestedCurve, R>,
        acc2: &Accumulator<C::HostCurve, C::NestedCurve, R>,
        params: &C,
    ) -> Result<()>
    where
        C: Cycle<CircuitField = Fp>,
    {
        // Hardcoded constants.
        const N: usize = 4;
        const R: usize = 8;
        const MAX_CROSS: usize = (N + 2) * (N + 1);
        const KY_DEGREE: usize = R;
        pub const TOTAL_KY_COEFFS: usize = N * KY_DEGREE;

        let circuits = Circuits::new();
        let circuit_list = [&circuits.s3, &circuits.s4, &circuits.s10, &circuits.s19];
        let circuit_ids: [C::CircuitField; N] = from_fn(|i| C::CircuitField::from(i as u64));

        // Simulate a dummy transcript object using Poseidon sponge construction, using an
        // emulator driver to run the sponge permutation. The permutations are treated as
        // as a fixed-length hash for fiat-shamir challenge derivation.
        //
        // TODO: Replace with a real transcript abstraction.
        let mut em = Emulator::<Always<()>, Fp>::default();
        let mut transcript = Sponge::new(&mut em, &PoseidonFp);

        // Instantiate new accumulator object, which contains the prover's split accumulator witness and instance parts.
        let mut accumulator =
            Accumulator::<C::HostCurve, C::NestedCurve, R>::base(mesh, params.host_generators());

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Process endoscalars.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TODO: Determine the endoscaling operations, representing deferreds from the
        // other curve.

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Process `StagedObjects` for staging consistency from the previous cycle.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TODO: For each, check lhs != ky_at_y.

        for staged_data in &acc1.staged_circuits {
            let y_challenge = acc1.accumulator.instance.y.0;
            let sy = staged_data.circuit.sy(y_challenge);
            let _ky_at_y = arithmetic::eval(&staged_data.ky, y_challenge);
            let _lhs = staged_data.final_rx.revdot(&sy);
        }

        for staged_data in &acc2.staged_circuits {
            let y_challenge = acc2.accumulator.instance.y.0;
            let sy = staged_data.circuit.sy(y_challenge);
            let _ky_at_y = arithmetic::eval(&staged_data.ky, y_challenge);
            let _lhs = staged_data.final_rx.revdot(&sy);
        }

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Process the application circuits. The witness polynomials
        // r(X) are over Fp, and produce commitments to Vesta points.
        ///////////////////////////////////////////////////////////////////////////////////////

        let mut a_polys = Vec::with_capacity(N + 2);
        let mut ky: Vec<Vec<Fp>> = Vec::with_capacity(N);

        for (&witness, circuit) in witnesses.iter().zip(circuit_list.iter()) {
            let (rx_poly, instance) = circuit.rx::<R>(witness)?;
            let blinding = C::CircuitField::random(OsRng);
            let commitment = rx_poly.commit(params.host_generators(), blinding);

            // r(X) witness polynomial.
            a_polys.push(CommittedPolynomial {
                poly: rx_poly,
                blind: blinding,
                commitment,
            });

            // k(Y) constraint polynomial for app circuits.
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

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: B STAGE.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Collect application circuit commitments (Vesta points).
        let a_commitments: [C::HostCurve; N + 2] = a_polys
            .iter()
            .map(|c| c.commitment)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(N))?;

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the Vesta commitments.
        let b_inner_rx = <EphemeralStageB<C::HostCurve, { N + 2 }> as StageExt<
            C::ScalarField,
            R,
        >>::rx(&a_commitments)?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators.
        let b_blinding = C::ScalarField::random(OsRng);
        let b_rx_nested_commitment = b_inner_rx.commit(params.nested_generators(), b_blinding);

        let b_point = Point::constant(&mut em, b_rx_nested_commitment)?;
        b_point.write(&mut em, &mut transcript)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: D STAGE. This uses a two-layer nested commitments.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: W challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze w challenge.
        let w = transcript.squeeze(&mut em)?;
        let w_challenge = *w.value().take();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S' Mesh Polynomials.
        ///////////////////////////////////////////////////////////////////////////////////////

        // COMPUTE S': For each previous accumulator, compute M(w, x_i, Y) for checking mesh consistency.
        let s1_poly_acc1 = mesh.wx(w_challenge, acc1.accumulator.instance.x.0);
        let s1_blinding_acc1 = C::CircuitField::random(OsRng);
        let s1_commitment_acc1 = s1_poly_acc1.commit(params.host_generators(), s1_blinding_acc1);

        let s1_poly_acc2 = mesh.wx(w_challenge, acc2.accumulator.instance.x.0);
        let s1_blinding_acc2 = C::CircuitField::random(OsRng);
        let s1_commitment_acc2 = s1_poly_acc2.commit(params.host_generators(), s1_blinding_acc2);

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
        // TASK: S' Nested Commitment.
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S' Vesta commitments.
        let d1_rx = <EphemeralStageD<C::HostCurve, 2> as StageExt<C::ScalarField, R>>::rx(
            &s_prime_commitments,
        )?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let d1_binding = C::ScalarField::random(OsRng);
        let d1_nested_commitment = d1_rx.commit(params.nested_generators(), d1_binding);

        let d1_point = Point::constant(&mut em, d1_nested_commitment)?;
        d1_point.write(&mut em, &mut transcript)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Y and Z challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze y challenge.
        let y = transcript.squeeze(&mut em)?;
        let y_challenge = *y.value().take();

        // TRANSCRIPT: Squeeze z challenge.
        let z = transcript.squeeze(&mut em)?;
        let z_challenge = *z.value().take();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S'' Mesh Polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        // COMPUTE S'': M(w, X, y) polynomial for final mesh consistency checks.
        let s2_poly = mesh.wy(w_challenge, y_challenge);
        let s2_blinding = C::CircuitField::random(OsRng);
        let s2_commitment = s2_poly.commit(params.host_generators(), s2_blinding);

        let s_prime_prime = [CommittedPolynomial {
            poly: s2_poly,
            blind: s2_blinding,
            commitment: s2_commitment,
        }];

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S'' Nested Commitment
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S'' Vesta commitment.
        let d2_rx = <EphemeralStageD<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[
            s2_commitment,
        ])?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let d2_binding = C::ScalarField::random(OsRng);
        let d2_nested_commitment = d2_rx.commit(params.nested_generators(), d2_binding);

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

                let b_blinding = C::CircuitField::random(OsRng);
                let b_commitment = b_poly.commit(params.host_generators(), b_blinding);

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

        pub const MAX_CROSS_PRODUCTS: usize = (N + 2) * (N + 1);

        // The prover computes all of the error terms (cross products).
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

        let cross_products: [C::CircuitField; MAX_CROSS_PRODUCTS] = cross_products
            .clone()
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(MAX_CROSS_PRODUCTS))?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute D staging polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        let d_staging_witness = (
            [w_challenge, y_challenge, z_challenge],
            [d1_nested_commitment, d2_nested_commitment],
            cross_products,
        );

        let d_rx =
            <DStage<C::NestedCurve, MAX_CROSS_PRODUCTS> as StageExt<Fp, R>>::rx(d_staging_witness)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable nested commitment for the transcript.
        let d_rx_blinding = C::CircuitField::random(OsRng);
        let d_rx_commitment = d_rx.commit(params.host_generators(), d_rx_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
        let d_rx_inner =
            <IndirectionStageD<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(d_rx_commitment)?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let d_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
        let d_rx_nested_commitment =
            d_rx_inner.commit(params.nested_generators(), d_rx_nested_commitment_blinding);

        let d_point = Point::constant(&mut em, d_rx_nested_commitment)?;
        d_point.write(&mut em, &mut transcript)?;
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: E STAGE. This uses a two-layer nested commitments.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: mu and nu challenge derivation for checking revdot claims are correct.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze mu challenge.
        let mu = transcript.squeeze(&mut em)?;
        let mu_challenge = *mu.value().take();

        // TRANSCRIPT: Squeeze nu challenge.
        let nu = transcript.squeeze(&mut em)?;
        let nu_challenge = *nu.value().take();

        let mu_inv = mu_challenge.invert().unwrap();
        let munu = mu_challenge * nu_challenge;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Folding A and B polynomials into single polynomials.
        ///////////////////////////////////////////////////////////////////////////////////////

        let a_poly = structured::Polynomial::fold(a_polys.iter().map(|a| &a.poly), mu_inv);
        let a_blinding = C::CircuitField::random(OsRng);
        let a_commitment = a_poly.commit(params.host_generators(), a_blinding);

        let a_folded = CommittedPolynomial {
            poly: a_poly,
            blind: a_blinding,
            commitment: a_commitment,
        };

        let b_poly = structured::Polynomial::fold(b_polys.iter().map(|b| &b.poly), munu);
        let b_blinding = C::CircuitField::random(OsRng);
        let b_commitment = b_poly.commit(params.host_generators(), b_blinding);

        let b_folded = CommittedPolynomial {
            poly: b_poly,
            blind: b_blinding,
            commitment: b_commitment,
        };

        let a_and_b_commmitments = [a_folded.commitment, b_folded.commitment];

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: A and B Nested Commitment
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the A and B Vesta commitments.
        let e1_rx = <EphemeralStageE<C::HostCurve, 2> as StageExt<C::ScalarField, R>>::rx(
            &a_and_b_commmitments,
        )?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let e1_binding = C::ScalarField::random(OsRng);
        let e1_nested_commitment = e1_rx.commit(params.nested_generators(), e1_binding);

        let e1_point = Point::constant(&mut em, e1_nested_commitment)?;
        e1_point.write(&mut em, &mut transcript)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: x challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze x challenge.
        let x = transcript.squeeze(&mut em)?;
        let x_challenge = *x.value().take();

        let xz = x_challenge * z_challenge;
        let txz_claimed = R::txz(x_challenge, z_challenge);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute S for mesh consistency.
        ///////////////////////////////////////////////////////////////////////////////////////

        let s_polynomial = mesh.xy(x_challenge, y_challenge);
        let s_blinding = C::CircuitField::random(OsRng);
        let s_commitment = s_polynomial.commit(params.host_generators(), s_blinding);

        let s = CommittedPolynomial {
            poly: s_polynomial,
            blind: s_blinding,
            commitment: s_commitment,
        };

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S Vesta commitment.
        let e2_inner_rx =
            <EphemeralStageE<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[s_commitment])?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let e2_blinding = C::ScalarField::random(OsRng);
        let e2_nested_commitment = e2_inner_rx.commit(params.nested_generators(), e2_blinding);

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
                .map(|(&eval_xz, &circuit_eval)| eval_xz + txz_claimed + circuit_eval);

            let b_evals: Vec<_> = circuit_b_evals
                .chain(acc_b_evals_x.iter().copied())
                .collect();

            b_evals
                .iter()
                .rev()
                .fold(Fp::zero(), |acc, &eval| acc * munu + eval)
        };

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Absorb all evaluations into the transcript before driving alpha.
        ///////////////////////////////////////////////////////////////////////////////////////

        for eval in circuit_evaluations {
            let _ = Element::constant(&mut em, eval).write(&mut em, &mut transcript);
        }

        let _ = Element::constant(&mut em, consistency_evaluations.acc1_s_at_w)
            .write(&mut em, &mut transcript);
        let _ = Element::constant(&mut em, consistency_evaluations.acc2_s_at_w)
            .write(&mut em, &mut transcript);
        let _ = Element::constant(&mut em, consistency_evaluations.s1_acc1_at_y)
            .write(&mut em, &mut transcript);
        let _ = Element::constant(&mut em, consistency_evaluations.s1_acc2_at_y)
            .write(&mut em, &mut transcript);
        let _ = Element::constant(&mut em, consistency_evaluations.s2_at_x)
            .write(&mut em, &mut transcript);

        for eval in a_polys_evals_x.iter().as_slice() {
            let _ = Element::constant(&mut em, *eval).write(&mut em, &mut transcript);
        }

        for eval in a_polys_evals_xz.iter().as_slice() {
            let _ = Element::constant(&mut em, *eval).write(&mut em, &mut transcript);
        }

        for eval in acc_b_evals_x {
            let _ = Element::constant(&mut em, eval).write(&mut em, &mut transcript);
        }

        let _ = Element::constant(&mut em, batched_a_eval).write(&mut em, &mut transcript);
        let _ = Element::constant(&mut em, batched_b_eval).write(&mut em, &mut transcript);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Collect evals – intermediate evaluations at challenge points used to
        // construct the batched claims.
        ///////////////////////////////////////////////////////////////////////////////////////

        let mut intermediate_evals = Vec::with_capacity(23);

        intermediate_evals.extend_from_slice(&circuit_evaluations);

        intermediate_evals.push(consistency_evaluations.acc1_s_at_w);
        intermediate_evals.push(consistency_evaluations.acc2_s_at_w);
        intermediate_evals.push(consistency_evaluations.s1_acc1_at_y);
        intermediate_evals.push(consistency_evaluations.s1_acc2_at_y);
        intermediate_evals.push(consistency_evaluations.s2_at_x);

        intermediate_evals.extend(a_polys_evals_x.iter().copied());
        intermediate_evals.extend(a_polys_evals_xz.iter().copied());

        intermediate_evals.extend_from_slice(&acc_b_evals_x);

        intermediate_evals.push(batched_a_eval);
        intermediate_evals.push(batched_b_eval);

        pub const NUM_INTERMEDIATE_EVALS: usize = 23;
        let intermediate_evals_array: [Fp; NUM_INTERMEDIATE_EVALS] = intermediate_evals
            .try_into()
            .expect("intermediate_evals should have exactly 23 elements");

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute E staging polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        let e_staging_witness = (
            [mu_challenge, nu_challenge, x_challenge],
            [e1_nested_commitment, e2_nested_commitment],
            intermediate_evals_array,
        );

        let e_rx = <EStage<C::NestedCurve, NUM_INTERMEDIATE_EVALS> as StageExt<Fp, R>>::rx(
            e_staging_witness,
        )?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable nested commitment for the transcript.
        let e_rx_blinding = C::CircuitField::random(OsRng);
        let e_rx_commitment = e_rx.commit(params.host_generators(), e_rx_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
        let e_rx_inner =
            <IndirectionStageE<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(e_rx_commitment)?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let e_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
        let e_rx_nested_commitment =
            e_rx_inner.commit(params.nested_generators(), e_rx_nested_commitment_blinding);

        let e_point = Point::constant(&mut em, e_rx_nested_commitment)?;
        e_point.write(&mut em, &mut transcript)?;
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: G STAGE.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: alpha challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze alpha challenge.
        let alpha = transcript.squeeze(&mut em)?;
        let alpha_challenge = *alpha.value().take();

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
        let f_commitment = f_polynomial.commit(params.host_generators(), f_blinding);

        let f = CommittedPolynomial {
            poly: f_polynomial,
            blind: f_blinding,
            commitment: f_commitment,
        };

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the F Vesta commitment.
        let g1_inner_rx =
            <EphemeralStageG<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[f.commitment])?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let g1_blinding = C::ScalarField::random(OsRng);
        let g1_nested_commitment: <C as Cycle>::NestedCurve =
            g1_inner_rx.commit(params.nested_generators(), g1_blinding);

        let g1_point = Point::constant(&mut em, g1_nested_commitment)?;
        g1_point.write(&mut em, &mut transcript)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: u challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze u challenge.
        let u = transcript.squeeze(&mut em)?;
        let u_challenge = *u.value().take();

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

        for eval in a_polys_final_evals.iter().as_slice() {
            let _ = Element::constant(&mut em, *eval).write(&mut em, &mut transcript);
        }

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: b challenge derivation. This checks all evaluations are correct by
        // folding the claims together.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze b challenge.
        let b = transcript.squeeze(&mut em)?;
        let b_challenge = *b.value().take();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Collect evals' – evaluations at final batching point u challenge.
        ///////////////////////////////////////////////////////////////////////////////////////

        let mut final_evals = Vec::with_capacity(16);

        final_evals.push(evaluations_final.a);
        final_evals.push(evaluations_final.b);
        final_evals.push(evaluations_final.acc1_p);
        final_evals.push(evaluations_final.acc2_p);
        final_evals.push(evaluations_final.acc1_s);
        final_evals.push(evaluations_final.acc2_s);
        final_evals.push(evaluations_final.s);
        final_evals.push(evaluations_final.s1[0]);
        final_evals.push(evaluations_final.s1[1]);
        final_evals.push(evaluations_final.s2);

        final_evals.extend(a_polys_final_evals.iter().copied());

        pub const NUM_FINAL_EVALS: usize = 16;
        let final_evals_array: [Fp; NUM_FINAL_EVALS] = final_evals
            .try_into()
            .expect("intermediate_evals should have exactly 23 elements");

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute G staging polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        let g_staging_witness = (
            [alpha_challenge, u_challenge],
            [g1_nested_commitment],
            final_evals_array,
        );

        let g_rx =
            <GStage<C::NestedCurve, NUM_FINAL_EVALS> as StageExt<Fp, R>>::rx(g_staging_witness)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable nested commitment for the transcript.
        let g_rx_blinding = C::CircuitField::random(OsRng);
        let g_rx_commitment = g_rx.commit(params.host_generators(), g_rx_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
        let g_rx_inner =
            <IndirectionStageE<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(g_rx_commitment)?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let g_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
        let g_rx_nested_commitment =
            g_rx_inner.commit(params.nested_generators(), g_rx_nested_commitment_blinding);

        let g_point = Point::constant(&mut em, g_rx_nested_commitment)?;
        g_point.write(&mut em, &mut transcript)?;
        ///////////////////////////////////////////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute v: batched polynomial evaluation check that verifies
        // all polynomial evaluations are consistent by batching them together
        /////////////////////////////////////////////////////////////////////////////////////

        // Build arrays for V computation witness.
        let mut eval_points = Vec::new();
        let mut intermediate_evals = Vec::new();
        let mut final_evals_for_queries = Vec::new();
        let mut inverses = Vec::new();

        // TODO: This should be it's own routine as well.
        let (v, p_poly, p_blind) = {
            let mut v = Fp::ZERO;

            let mut proc = |point: Fp, eval, eval_prime| {
                v *= alpha_challenge;
                v += (u_challenge - point).invert().unwrap() * (eval_prime - eval);

                eval_points.push(point);
                intermediate_evals.push(eval);
                final_evals_for_queries.push(eval_prime);
                inverses.push((u_challenge - point).invert().unwrap());
            };

            // Handle each of the queries.

            // Batched A and B evaluations at x.
            proc(x_challenge, batched_a_eval, evaluations_final.a);
            proc(x_challenge, batched_b_eval, evaluations_final.b);

            // Accumulator p polynomials at their u points.
            proc(
                acc1.accumulator.instance.u.0,
                acc1.accumulator.instance.v.0,
                evaluations_final.acc1_p,
            );
            proc(
                acc2.accumulator.instance.u.0,
                acc2.accumulator.instance.v.0,
                evaluations_final.acc2_p,
            );

            // Accumulator s polynomials at w.
            proc(
                w_challenge,
                consistency_evaluations.acc1_s_at_w,
                evaluations_final.acc1_s,
            );
            proc(
                w_challenge,
                consistency_evaluations.acc2_s_at_w,
                evaluations_final.acc2_s,
            );

            // Circuit evaluations at their IDs.
            proc(circuit_ids[0], circuit_evaluations[0], evaluations_final.s);
            proc(circuit_ids[1], circuit_evaluations[1], evaluations_final.s);
            proc(circuit_ids[2], circuit_evaluations[2], evaluations_final.s);
            proc(circuit_ids[3], circuit_evaluations[3], evaluations_final.s);

            // s2 at x.
            proc(
                w_challenge,
                consistency_evaluations.s2_at_x,
                evaluations_final.s,
            );

            // s1 polynomials at accumulator y points.
            proc(
                acc1.accumulator.instance.y.0,
                consistency_evaluations.acc1_s_at_w,
                evaluations_final.s1[0],
            );
            proc(
                acc2.accumulator.instance.y.0,
                consistency_evaluations.acc2_s_at_w,
                evaluations_final.s1[1],
            );

            // s1 polynomials at y.
            proc(
                y_challenge,
                consistency_evaluations.s1_acc1_at_y,
                evaluations_final.s1[0],
            );
            proc(
                y_challenge,
                consistency_evaluations.s1_acc2_at_y,
                evaluations_final.s1[1],
            );

            // s2 at accumulator x points.
            proc(
                acc1.accumulator.instance.x.0,
                consistency_evaluations.s1_acc1_at_y,
                evaluations_final.s2,
            );
            proc(
                acc2.accumulator.instance.x.0,
                consistency_evaluations.s1_acc2_at_y,
                evaluations_final.s2,
            );

            // a_polys evaluations at x.
            proc(
                x_challenge,
                consistency_evaluations.s2_at_x,
                evaluations_final.s2,
            );

            // Add proc calls for a_polys queries at x and xz
            for (eval_x, final_eval) in a_polys_evals_x.iter().zip(a_polys_final_evals.iter()) {
                proc(x_challenge, *eval_x, *final_eval);
            }
            // Only add xz proc calls for circuit polynomials
            for (eval_xz, final_eval) in a_polys_evals_xz
                .iter()
                .zip(a_polys_final_evals.iter().take(N))
            {
                proc(xz, *eval_xz, *final_eval);
            }

            drop(proc);

            let mut p_poly = f.poly.clone();
            let mut p_blind = f.blind;

            let mut proc =
                |f: &dyn Fn(&mut unstructured::Polynomial<Fp, R>), eval_prime: Fp, blind| {
                    p_poly.scale(b_challenge);
                    p_blind *= b_challenge;
                    v *= b_challenge;

                    f(&mut p_poly);
                    v += eval_prime;
                    p_blind += blind;
                };

            proc(
                &|p| p.add_structured(&a_folded.poly),
                evaluations_final.a,
                &a_folded.blind,
            );
            proc(
                &|p| p.add_structured(&b_folded.poly),
                evaluations_final.b,
                &b_folded.blind,
            );
            proc(
                &|p| p.add_assign(&acc1.accumulator.witness.p_poly),
                evaluations_final.acc1_p,
                &acc1.accumulator.witness.p_blinding,
            );
            proc(
                &|p| p.add_assign(&acc2.accumulator.witness.p_poly),
                evaluations_final.acc2_p,
                &acc2.accumulator.witness.p_blinding,
            );
            proc(
                &|p| p.add_assign(&acc1.accumulator.witness.s_poly),
                evaluations_final.acc1_s,
                &acc1.accumulator.witness.s_blinding,
            );
            proc(
                &|p| p.add_assign(&acc2.accumulator.witness.s_poly),
                evaluations_final.acc2_s,
                &acc2.accumulator.witness.s_blinding,
            );
            proc(&|p| p.add_assign(&s.poly), evaluations_final.s, &s.blind);
            proc(
                &|p| p.add_assign(&s_prime[0].poly),
                evaluations_final.s1[0],
                &s_prime[0].blind,
            );
            proc(
                &|p| p.add_assign(&s_prime[1].poly),
                evaluations_final.s1[1],
                &s_prime[1].blind,
            );
            proc(
                &|p| p.add_structured(&s_prime_prime[0].poly),
                evaluations_final.s2,
                &s_prime_prime[0].blind,
            );

            // Add proc calls for a_polys
            for (a_poly, final_eval) in a_polys.iter().zip(a_polys_final_evals.iter()) {
                proc(
                    &|p| p.add_structured(&a_poly.poly),
                    *final_eval,
                    &a_poly.blind,
                );
            }

            (v, p_poly, p_blind)
        };

        // Convert to fixed arrays
        let eval_points: [Fp; NUM_V_QUERIES] = eval_points
            .try_into()
            .expect("eval_points length should match NUM_V_QUERIES");
        let intermediate_evals: [Fp; NUM_V_QUERIES] = intermediate_evals
            .try_into()
            .expect("intermediate_evals length should match NUM_V_QUERIES");
        let final_evals_for_queries: [Fp; NUM_V_QUERIES] = final_evals_for_queries
            .try_into()
            .expect("final_evals_for_queries length should match NUM_V_QUERIES");
        let inverses: [Fp; NUM_V_QUERIES] = inverses
            .try_into()
            .expect("inverses length should match NUM_V_QUERIES");

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute p(X) commitment.
        ///////////////////////////////////////////////////////////////////////////////////////

        let p_commitment = p_poly.commit(params.host_generators(), p_blind);

        let p = CommittedPolynomial {
            poly: p_poly,
            blind: p_blind,
            commitment: p_commitment,
        };

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the F Vesta commitment.
        let g2_inner_rx =
            <EphemeralStageG<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[p.commitment])?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let g2_blinding = C::ScalarField::random(OsRng);
        let g2_nested_commitment: <C as Cycle>::NestedCurve =
            g2_inner_rx.commit(params.nested_generators(), g2_blinding);

        let g2_point = Point::constant(&mut em, g2_nested_commitment)?;
        g2_point.write(&mut em, &mut transcript)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Build KY staging polyhnomial for ky polynomial coefficients.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Append application circuits ky coefficients.
        let mut application_ky_coffs = Vec::new();
        for ky_poly in &ky {
            application_ky_coffs.extend_from_slice(ky_poly);
        }

        let ky_coeff_array: [C::CircuitField; TOTAL_KY_COEFFS] = application_ky_coffs
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(TOTAL_KY_COEFFS))?;

        // Build the K staging polynomial.
        let k_rx =
            <KYStage<C::NestedCurve, TOTAL_KY_COEFFS> as StageExt<Fp, R>>::rx(ky_coeff_array)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable nested commitment for the transcript.
        let k_rx_blinding = C::CircuitField::random(OsRng);
        let k_rx_commitment = k_rx.commit(params.host_generators(), k_rx_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
        let k_rx_inner =
            <IndirectionStageG<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(k_rx_commitment)?;

        // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
        let k_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
        let k_rx_nested_commitment =
            k_rx_inner.commit(params.nested_generators(), k_rx_nested_commitment_blinding);

        let k_point = Point::constant(&mut em, k_rx_nested_commitment)?;
        k_point.write(&mut em, &mut transcript)?;
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute c value using routine outside circuit.
        ///////////////////////////////////////////////////////////////////////////////////////

        use crate::routines::c::Evaluate as ComputeC;
        use crate::routines::horners::EvaluateKyPolynomials;
        use ragu_core::{drivers::Emulator, maybe::Always};
        use ragu_primitives::Element;

        // Evaluate ky polynomials at y_challenge using Horner's routine.
        let ky_degree = TOTAL_KY_COEFFS / N;
        let mut dr = Emulator::<Always<()>, Fp>::default();

        let mu_inv = mu_challenge.invert().unwrap();
        let ky_evaluated = dr
            .with((&ky_coeff_array[..], y_challenge), |dr, inputs| {
                let (ky_coeffs_slice, y_val) = inputs.cast();

                // Allocate ky coefficients.
                let mut ky_coeff_elems = Vec::with_capacity(TOTAL_KY_COEFFS);
                for i in 0..TOTAL_KY_COEFFS {
                    let coeff = ky_coeffs_slice.view().map(|s| s[i]);
                    ky_coeff_elems.push(Element::alloc(dr, coeff)?);
                }
                let ky_coeff_fixed = ragu_primitives::vec::FixedVec::new(ky_coeff_elems)
                    .expect("ky_coeff_elems length");

                let y_elem = Element::alloc(dr, y_val)?;

                let horner_routine = EvaluateKyPolynomials::<TOTAL_KY_COEFFS, N>::new(N, ky_degree);
                dr.routine(horner_routine, (ky_coeff_fixed, y_elem))
            })
            .expect("ky evaluation should succeed");

        // Extract evaluated ky values and add previous accumulator c values.
        let mut ky_values = Vec::with_capacity(N + 2);
        for ky_elem in ky_evaluated.iter().take(N) {
            ky_values.push(*ky_elem.value().take());
        }
        ky_values.push(acc1.accumulator.instance.c);
        ky_values.push(acc2.accumulator.instance.c);

        // Compute c using the routine.
        let c = *dr
            .with(
                (
                    (mu_challenge, nu_challenge, mu_inv),
                    (&cross_products[..], &ky_values[..]),
                ),
                |dr, inputs| {
                    let (challenges, slices) = inputs.cast();
                    let (mu, nu, mu_inv) = challenges.cast();
                    let (cross_slice, ky_slice) = slices.cast();

                    let mu = Element::alloc(dr, mu)?;
                    let nu = Element::alloc(dr, nu)?;
                    let mu_inv = Element::alloc(dr, mu_inv)?;

                    // Allocate cross products.
                    let mut cross_elems = Vec::with_capacity(MAX_CROSS);
                    for i in 0..MAX_CROSS {
                        let val = cross_slice
                            .view()
                            .map(|s| if i < s.len() { s[i] } else { Fp::ZERO });
                        cross_elems.push(Element::alloc(dr, val)?);
                    }
                    let cross_elems = ragu_primitives::vec::FixedVec::new(cross_elems)
                        .expect("cross_elems length");

                    // Allocate ky values.
                    let mut ky_elems = Vec::with_capacity(N + 2);
                    for i in 0..(N + 2) {
                        let val = ky_slice
                            .view()
                            .map(|s| if i < s.len() { s[i] } else { Fp::ZERO });
                        ky_elems.push(Element::alloc(dr, val)?);
                    }
                    let ky_elems =
                        ragu_primitives::vec::FixedVec::new(ky_elems).expect("ky_elems length");

                    let input = (((mu, nu), mu_inv), (cross_elems, ky_elems));
                    dr.routine(ComputeC::<MAX_CROSS, { N + 2 }>::new(len), input)
                },
            )
            .expect("c computation should succeed")
            .value()
            .take();

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: STAGED CIRCUITS for collective verification (In-circuit verifiers).
        ///////////////////////////////////////////////////////////////////////////////////////

        // TODO: Document the constraint costs of each circuit.

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Create the staged circuits.
        ///////////////////////////////////////////////////////////////////////////////////////

        let d_circuit = Staged::<Fp, R, _>::new(DChallengeDerivationStagedCircuit::<
            C::NestedCurve,
            MAX_CROSS,
        >::new());

        let c_circuit = Staged::<Fp, R, _>::new(DCValueComputationStagedCircuit::<
            C::NestedCurve,
            MAX_CROSS,
            TOTAL_KY_COEFFS,
            { N + 2 },
        >::new());

        let e_circuit =
            Staged::<Fp, R, _>::new(EChallengeDerivationStagedCircuit::<C::NestedCurve>::new());

        let g_circuit =
            Staged::<Fp, R, _>::new(GVComputationStagedCircuit::<C::NestedCurve>::new());

        // TODO: Missing circuit for beta challenge verification.

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute the unified k(Y) instance for all the recursion circuits
        ///////////////////////////////////////////////////////////////////////////////////////

        // Since each circuit will have the same public instance k(Y), we can just
        // compute it once.

        let unified_instance = UnifiedRecursionInstance {
            w_challenge,
            y_challenge,
            z_challenge,
            mu_challenge,
            nu_challenge,
            x_challenge,
            alpha_challenge,
            u_challenge,
            b_challenge,
            b_staging_nested_commitment: b_rx_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
            d_staging_nested_commitment: d_rx_nested_commitment,
            e1_nested_commitment,
            e2_nested_commitment,
            e_staging_nested_commitment: e_rx_nested_commitment,
            g1_nested_commitment,
            g_staging_nested_commitment: g_rx_nested_commitment,
            p_nested_commitment: g2_nested_commitment,
            // TODO: Missing the ky_nested_commitment?
            c,
            v,
        };

        let unified_ky = d_circuit.ky(unified_instance)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Verify w, y, and z challenges in-circuit.
        ///////////////////////////////////////////////////////////////////////////////////////

        let (d_rx, _d_aux) = d_circuit.rx::<R>(DChallengeDerivationWitness {
            cross_products,
            w_challenge,
            y_challenge,
            z_challenge,
            mu_challenge,
            nu_challenge,
            x_challenge,
            alpha_challenge,
            u_challenge,
            b_challenge,
            b_staging_nested_commitment: b_rx_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
            d_staging_nested_commitment: d_rx_nested_commitment,
            e1_nested_commitment,
            e2_nested_commitment,
            e_staging_nested_commitment: e_rx_nested_commitment,
            g1_nested_commitment,
            g_staging_nested_commitment: g_rx_nested_commitment,
            p_nested_commitment: g2_nested_commitment,
            c,
            v,
        })?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute C in-circuit. The expected value of c = a.revdot(b).
        ///////////////////////////////////////////////////////////////////////////////////////

        let (c_rx, c_aux) = c_circuit.rx::<R>(DCValueComputationWitness {
            mu_inv,
            cross_products: cross_products,
            ky_coeffs: ky_coeff_array,
            w_challenge,
            y_challenge,
            z_challenge,
            mu_challenge,
            nu_challenge,
            x_challenge,
            alpha_challenge,
            u_challenge,
            b_challenge,
            b_staging_nested_commitment: b_rx_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
            d_staging_nested_commitment: d_rx_nested_commitment,
            e1_nested_commitment,
            e2_nested_commitment,
            e_staging_nested_commitment: e_rx_nested_commitment,
            g1_nested_commitment,
            g_staging_nested_commitment: g_rx_nested_commitment,
            p_nested_commitment: g2_nested_commitment,
            c,
            v,
        })?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute T(X, z) in-circuit. This also checks mu and nu challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        let (e_rx, _e_aux) = e_circuit.rx::<R>(EChallengeDerivationWitness {
            evals: intermediate_evals_array,
            w_challenge,
            y_challenge,
            z_challenge,
            mu_challenge,
            nu_challenge,
            x_challenge,
            alpha_challenge,
            u_challenge,
            b_challenge,
            b_staging_nested_commitment: b_rx_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
            d_staging_nested_commitment: d_rx_nested_commitment,
            e1_nested_commitment,
            e2_nested_commitment,
            e_staging_nested_commitment: e_rx_nested_commitment,
            g1_nested_commitment,
            g_staging_nested_commitment: g_rx_nested_commitment,
            p_nested_commitment: g2_nested_commitment,
            c,
            v,
        })?;

        //////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute evaluation v in-circuit. This also checks alpha, u, and beta
        // challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        let (g_rx, _g_aux) = g_circuit.rx::<R>(GVComputationStagedWitness {
            evals: final_evals_array,
            eval_points,
            intermediate_evals,
            final_evals_for_queries,
            inverses,
            w_challenge,
            y_challenge,
            z_challenge,
            mu_challenge,
            nu_challenge,
            x_challenge,
            alpha_challenge,
            u_challenge,
            b_challenge,
            b_staging_nested_commitment: b_rx_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
            d_staging_nested_commitment: d_rx_nested_commitment,
            e1_nested_commitment,
            e2_nested_commitment,
            e_staging_nested_commitment: e_rx_nested_commitment,
            g1_nested_commitment,
            g_staging_nested_commitment: g_rx_nested_commitment,
            p_nested_commitment: g2_nested_commitment,
            c,
            v,
        })?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Collect staged circuit data for next cycle verification
        ///////////////////////////////////////////////////////////////////////////////////////

        let d_circuit_object = d_circuit.clone().into_object()?;
        let c_circuit_object = c_circuit.clone().into_object()?;
        let e_circuit_object = e_circuit.clone().into_object()?;
        let g_circuit_object = g_circuit.clone().into_object()?;

        accumulator.staged_circuits = vec![
            StagedCircuitData {
                final_rx: d_rx,
                ky: unified_ky.clone(),
                circuit: d_circuit_object,
            },
            StagedCircuitData {
                final_rx: c_rx,
                ky: unified_ky.clone(),
                circuit: c_circuit_object,
            },
            StagedCircuitData {
                final_rx: e_rx,
                ky: unified_ky.clone(),
                circuit: e_circuit_object,
            },
            StagedCircuitData {
                final_rx: g_rx,
                ky: unified_ky.clone(),
                circuit: g_circuit_object,
            },
        ];

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Collect deferreds (Vesta points to be checked on Pallas side).
        ///////////////////////////////////////////////////////////////////////////////////////

        // Everything that's in a nested polynomial gets deferred. Deferreds should be:
        //
        // - All the ephemeral nested commitments witnessing this round's work,
        // - All the staging polynomial nested commitments from D, E, G circuits,

        accumulator.deferreds = vec![
            b_rx_nested_commitment, // B staging polynomial commitment
            d1_nested_commitment,   // Witnesses S' commitments
            d2_nested_commitment,   // Witnesses S'' commitments
            d_rx_nested_commitment, // D staging polynomial commitment
            e1_nested_commitment,   // Witnesses A and B commitments
            e2_nested_commitment,   // Witnesses S commitment
            e_rx_nested_commitment, // E staging polynomial commitment
            g1_nested_commitment,   // Witnesses F commitment
            g_rx_nested_commitment, // G staging polynomial commitment
            k_rx_nested_commitment, // KY staging polynomial commitment
        ];

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compose the final accumulator.
        ///////////////////////////////////////////////////////////////////////////////////////

        let accumulator_witness = AccumulatorWitness::<C::HostCurve, R> {
            s_poly: s.poly,
            s_blinding: s.blind,
            a_poly: a_folded.poly,
            a_blinding: a_folded.blind,
            b_poly: b_folded.poly,
            b_blinding: b_folded.blind,
            p_poly: p.poly,
            p_blinding: p.blind,
        };

        let accumulator_instance = AccumulatorInstance::<C::HostCurve> {
            a: a_folded.commitment,
            b: b_folded.commitment,
            c: c_aux.c_value,
            p: p.commitment,
            u: ChallengePoint(u_challenge),
            v: EvaluationPoint(v),
            s: s.commitment,
            x: ChallengePoint(x_challenge),
            y: ChallengePoint(y_challenge),
        };

        accumulator.accumulator = UncompressedAccumulator::<C::HostCurve, R> {
            witness: accumulator_witness,
            instance: accumulator_instance,
        };

        Ok(())
    }
}
