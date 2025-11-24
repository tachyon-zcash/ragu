use arithmetic::{Cycle, factor_iter};
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    composition::{
        error_stage::{EphemeralStageError, ErrorStage, IndirectionStageError},
        evaluation_stage::{
            EphemeralStageEvaluation, EvaluationStage, IndirectionStageEvaluation, NUM_FINAL_EVALS,
            NUM_V_QUERIES,
        },
        preamble_stage::EphemeralStagePreamble,
        query_stage::{EphemeralStageQuery, IndirectionStageQuery, NUM_EVALS, QueryStage},
    },
    mesh::omega_j,
    polynomials::{Rank, structured, unstructured},
    staging::StageExt,
};
use ragu_core::{Error, Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{Element, Point, Sponge};
use rand::{Rng, rngs::OsRng};

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_primitives::vec::FixedVec;

use crate::{
    Pcd, Proof,
    proof::{CommittedPolynomial, CommittedStructured, ConsistencyEvaluations, FinalEvaluations},
    step::{Step, adapter::Adapter},
    verify::stub_step::StubStep,
};
use ragu_primitives::GadgetExt;

pub fn merge<'source, C: Cycle, R: Rank, RNG: Rng, S: Step<C>, const HEADER_SIZE: usize>(
    num_application_steps: usize,
    circuit_mesh: &ragu_circuits::mesh::Mesh<'_, C::CircuitField, R>,
    params: &C,
    _rng: &mut RNG,
    step: S,
    witness: S::Witness<'source>,
    left: Pcd<'source, C, R, S::Left>,
    right: Pcd<'source, C, R, S::Right>,
) -> Result<(Proof<C, R>, S::Aux<'source>)> {
    let host_generators = params.host_generators();
    let nested_generators = params.nested_generators();
    let circuit_poseidon = params.circuit_poseidon();

    ///////////////////////////////////////////////////////////////////////////////////////
    // PHASE: Initialize transcript.
    ///////////////////////////////////////////////////////////////////////////////////////

    // Simulate a dummy transcript object using Poseidon sponge construction, using an
    // emulator driver to run the sponge permutation. The permutations are treated as
    // as a fixed-length hash for fiat-shamir challenge derivation.
    //
    // TODO: Replace with a real transcript abstraction.
    let mut em = Emulator::execute();
    let mut transcript = Sponge::new(&mut em, circuit_poseidon);

    ///////////////////////////////////////////////////////////////////////////////////////
    // PHASE: Process endoscalars.
    ///////////////////////////////////////////////////////////////////////////////////////

    // TODO: Determine the endoscaling operations, representing deferreds from the
    // other curve.

    ///////////////////////////////////////////////////////////////////////////////////////
    // PHASE: Process `StagedObjects` for staging consistency from the previous cycle.
    ///////////////////////////////////////////////////////////////////////////////////////

    // Checks each staged circuit's constraint polynomial r(X) satisfies the mesh consistency equation.
    for staged_data in &left.proof.staged_circuits {
        let y_challenge = left.proof.instance.y.0;
        let sy = circuit_mesh.wy(staged_data.circuit_id, y_challenge);
        let ky_at_y = arithmetic::eval(&staged_data.ky, y_challenge);
        let lhs = staged_data.final_rx.revdot(&sy);
        if lhs != ky_at_y {
            return Err(Error::InvalidWitness(
                "Staged circuit constraint check failed (left proof): rx.revdot(sy) != ky(y)"
                    .into(),
            ));
        }
    }

    for staged_data in &right.proof.staged_circuits {
        let y_challenge = right.proof.instance.y.0;
        let sy = circuit_mesh.wy(staged_data.circuit_id, y_challenge);
        let ky_at_y = arithmetic::eval(&staged_data.ky, y_challenge);
        let lhs = staged_data.final_rx.revdot(&sy);
        if lhs != ky_at_y {
            return Err(Error::InvalidWitness(
                "Staged circuit constraint check failed (right proof): rx.revdot(sy) != ky(y)"
                    .into(),
            ));
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////
    // Phase: Process the application circuits. The witness polynomials
    // r(X) are over the `C::CircuitField`, and produce commitments to `C::HostCurve`
    // curve points.
    ///////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////////////////
    // Task: Execute application logic via `Step::witness()` through the Adapter.
    ///////////////////////////////////////////////////////////////////////////////////////

    let circuit_id = S::INDEX.circuit_index(Some(num_application_steps))?;
    let circuit = Adapter::<C, S, R, HEADER_SIZE>::new(step);

    // Clone data before moving into rx computation.
    let left_data = left.data.clone();
    let right_data = right.data.clone();

    // Compute r(X) polynomial for this step.
    let (rx, aux) = circuit.rx::<R>((left.data, right.data, witness), circuit_mesh.get_key())?;
    let ((left_header, right_header), aux) = aux;

    // Commit to r(X) with random blinding.
    let blinding = C::CircuitField::random(OsRng);
    let commitment = rx.clone().commit(host_generators, blinding);

    // Reconstruct k(Y) public input polynomial for the left input PCD.
    let left_ky_poly = {
        let adapter = Adapter::<C, StubStep<S::Left>, R, HEADER_SIZE>::new(StubStep::new());
        let left_header = FixedVec::try_from(left.proof.left_header.clone())
            .map_err(|_| Error::MalformedEncoding("left header size".into()))?;
        let right_header = FixedVec::try_from(left.proof.right_header.clone())
            .map_err(|_| Error::MalformedEncoding("right header size".into()))?;
        adapter.ky((left_header, right_header, left_data))?
    };

    // Reconstruct k(Y) public input polynomial for the right input PCD.
    let right_ky_poly = {
        let adapter = Adapter::<C, StubStep<S::Right>, R, HEADER_SIZE>::new(StubStep::new());
        let left_header = FixedVec::try_from(right.proof.left_header.clone())
            .map_err(|_| Error::MalformedEncoding("left header size".into()))?;
        let right_header = FixedVec::try_from(right.proof.right_header.clone())
            .map_err(|_| Error::MalformedEncoding("right header size".into()))?;
        adapter.ky((left_header, right_header, right_data))?
    };

    ///////////////////////////////////////////////////////////////////////////////////////
    // Task: Collect all A polynomials (application and previous accumulators).
    ///////////////////////////////////////////////////////////////////////////////////////

    let mut a_polys: Vec<CommittedStructured<R, C>> = Vec::new();
    let mut ky_polys: Vec<Vec<C::CircuitField>> = Vec::new();

    // Append r(X) witness polynomial from the application circuit.
    a_polys.push(CommittedPolynomial {
        poly: rx.clone(),
        blind: blinding,
        commitment,
    });

    // Append the previous accumulator A polynomials.
    a_polys.push(CommittedPolynomial {
        poly: left.proof.witness.a_poly.clone(),
        blind: left.proof.witness.a_blinding,
        commitment: left.proof.instance.a,
    });
    a_polys.push(CommittedPolynomial {
        poly: right.proof.witness.a_poly.clone(),
        blind: right.proof.witness.a_blinding,
        commitment: right.proof.instance.a,
    });

    // Append k(Y) polynomial from previous accumulators.
    ky_polys.push(left_ky_poly);
    ky_polys.push(right_ky_poly);

    ///////////////////////////////////////////////////////////////////////////////////////
    // PHASE: PREAMBLE STAGE.
    ///////////////////////////////////////////////////////////////////////////////////////

    // Temporary: Total circuits (1 application step + 2 accumulators)
    const NUM_CIRCUITS: usize = 3;
    const NUM_APP_CIRCUITS: usize = 1;

    // Collect application circuit commitments (Vesta points).
    let a_commitments = a_polys
        .iter()
        .map(|c| c.commitment)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Error::CircuitBoundExceeded(NUM_CIRCUITS))?;

    // INNER LAYER: Staging polynomial (over Fq) that witnesses the Vesta commitments.
    let preamble_rx = <EphemeralStagePreamble<C::HostCurve, NUM_CIRCUITS> as StageExt<
        C::ScalarField,
        R,
    >>::rx(&a_commitments)?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators.
    let preamble_blinding = C::ScalarField::random(OsRng);
    let preamble_rx_nested_commitment = preamble_rx.commit(nested_generators, preamble_blinding);

    let preamble_point = Point::constant(&mut em, preamble_rx_nested_commitment)?;
    preamble_point.write(&mut em, &mut transcript)?;

    ///////////////////////////////////////////////////////////////////////////////////////
    // PHASE: ERROR STAGE. This uses a two-layer nested commitments.
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
    let s1_poly_acc1 = circuit_mesh.wx(w_challenge, left.proof.instance.x.0);
    let s1_blinding_acc1 = C::CircuitField::random(OsRng);
    let s1_commitment_acc1 = s1_poly_acc1.commit(host_generators, s1_blinding_acc1);

    let s1_poly_acc2 = circuit_mesh.wx(w_challenge, right.proof.instance.x.0);
    let s1_blinding_acc2 = C::CircuitField::random(OsRng);
    let s1_commitment_acc2 = s1_poly_acc2.commit(host_generators, s1_blinding_acc2);

    let s_prime: [CommittedPolynomial<_, C>; 2] = [
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
    let e1_rx = <EphemeralStageError<C::HostCurve, 2> as StageExt<C::ScalarField, R>>::rx(
        &s_prime_commitments,
    )?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
    let e1_binding = C::ScalarField::random(OsRng);
    let e1_nested_commitment = e1_rx.commit(nested_generators, e1_binding);

    let e1_point = Point::constant(&mut em, e1_nested_commitment)?;
    e1_point.write(&mut em, &mut transcript)?;

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
    // TASK:  ky evaluation at y and appending accumulator c value
    ///////////////////////////////////////////////////////////////////////////////////////

    let mut ky_evals: Vec<C::CircuitField> = ky_polys
        .iter()
        .map(|ky| arithmetic::eval(ky, y_challenge))
        .collect();

    ky_evals.push(left.proof.instance.c);
    ky_evals.push(right.proof.instance.c);

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: S'' Mesh Polynomial.
    ///////////////////////////////////////////////////////////////////////////////////////

    // COMPUTE S'': M(w, X, y) polynomial for final mesh consistency checks.
    let s2_poly = circuit_mesh.wy(w_challenge, y_challenge);
    let s2_blinding = C::CircuitField::random(OsRng);
    let s2_commitment = s2_poly.commit(host_generators, s2_blinding);

    let s_prime_prime: [CommittedPolynomial<_, C>; 1] = [CommittedPolynomial {
        poly: s2_poly,
        blind: s2_blinding,
        commitment: s2_commitment,
    }];

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: S'' Nested Commitment
    //////////////////////////////////////////////////////////////////////////////////////

    // INNER LAYER: Staging polynomial (over Fq) that witnesses the S'' Vesta commitment.
    let e2_rx = <EphemeralStageError<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[
        s2_commitment,
    ])?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
    let e2_binding = C::ScalarField::random(OsRng);
    let e2_nested_commitment = e2_rx.commit(nested_generators, e2_binding);

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: Compute B polynomials for revdot verification.
    //
    // For each application circuit: B_i(X) = A_i(X) * z + t(X,z) + M(circuit_id, X, y),
    // and this construction ensures: A_i (revdot) B_i = k_i(y).
    ///////////////////////////////////////////////////////////////////////////////////////

    let tz = R::tz(z_challenge);

    let mut b_polys: Vec<CommittedStructured<R, C>> = a_polys
        .iter()
        .take(NUM_APP_CIRCUITS)
        .zip([circuit_id].iter())
        .map(|(a, &circuit_id)| {
            let mut b_poly = a.poly.clone();
            b_poly.dilate(z_challenge);
            b_poly.add_assign(&tz);
            b_poly.add_assign(&circuit_mesh.wy(omega_j(circuit_id as u32), y_challenge));

            let b_blinding = C::CircuitField::random(OsRng);
            let b_commitment = b_poly.commit(host_generators, b_blinding);

            CommittedPolynomial {
                poly: b_poly,
                blind: b_blinding,
                commitment: b_commitment,
            }
        })
        .collect();

    // Append existing accumulator B polynomials.
    b_polys.push(CommittedPolynomial {
        poly: left.proof.witness.b_poly.clone(),
        blind: left.proof.witness.b_blinding,
        commitment: left.proof.instance.b,
    });
    b_polys.push(CommittedPolynomial {
        poly: right.proof.witness.b_poly.clone(),
        blind: right.proof.witness.b_blinding,
        commitment: right.proof.instance.b,
    });

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: Compute error / slack term (from folding multiple revdot checks)
    // before computing the u and v evaluations.
    ///////////////////////////////////////////////////////////////////////////////////////

    assert_eq!(a_polys.len(), b_polys.len());

    // The prover computes all of the error terms (cross products).
    let mut cross_products = Vec::new();
    for (i, a_poly) in a_polys.iter().enumerate() {
        for (j, b_poly) in b_polys.iter().enumerate() {
            if i != j {
                let cross = a_poly.poly.revdot(&b_poly.poly);
                cross_products.push(cross);
            }
        }
    }

    // Verify cross products count: N * (N - 1) for N circuits.
    assert_eq!(cross_products.len(), NUM_CIRCUITS * (NUM_CIRCUITS - 1));

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: Compute Error staging polynomial.
    ///////////////////////////////////////////////////////////////////////////////////////

    let e_staging_witness = (
        [w_challenge, y_challenge, z_challenge],
        [e1_nested_commitment, e2_nested_commitment],
        cross_products,
    );

    let e_rx = <ErrorStage<C::NestedCurve, NUM_CIRCUITS> as StageExt<C::CircuitField, R>>::rx(
        e_staging_witness,
    )?;

    ///////////////////////////////////////////////////////////////////////////////////////
    // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
    // an Fp-hashable nested commitment for the transcript.
    let e_rx_blinding = C::CircuitField::random(OsRng);
    let e_rx_commitment = e_rx.commit(host_generators, e_rx_blinding);

    // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
    let e_rx_inner =
        <IndirectionStageError<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(e_rx_commitment)?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
    let e_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
    let e_rx_nested_commitment =
        e_rx_inner.commit(nested_generators, e_rx_nested_commitment_blinding);

    let e_point = Point::constant(&mut em, e_rx_nested_commitment)?;
    e_point.write(&mut em, &mut transcript)?;
    ///////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////////////////
    // PHASE: QUERY STAGE. This uses a two-layer nested commitments.
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
    let a_commitment = a_poly.commit(host_generators, a_blinding);

    let a_folded: CommittedPolynomial<_, C> = CommittedPolynomial {
        poly: a_poly,
        blind: a_blinding,
        commitment: a_commitment,
    };

    let b_poly = structured::Polynomial::fold(b_polys.iter().map(|b| &b.poly), munu);
    let b_blinding = C::CircuitField::random(OsRng);
    let b_commitment = b_poly.commit(host_generators, b_blinding);

    let b_folded: CommittedPolynomial<_, C> = CommittedPolynomial {
        poly: b_poly,
        blind: b_blinding,
        commitment: b_commitment,
    };

    let a_and_b_commmitments = [a_folded.commitment, b_folded.commitment];

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: A and B Nested Commitment
    //////////////////////////////////////////////////////////////////////////////////////

    // INNER LAYER: Staging polynomial (over Fq) that witnesses the A and B Vesta commitments.
    let q1_rx = <EphemeralStageQuery<C::HostCurve, 2> as StageExt<C::ScalarField, R>>::rx(
        &a_and_b_commmitments,
    )?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
    let q1_binding = C::ScalarField::random(OsRng);
    let q1_nested_commitment = q1_rx.commit(nested_generators, q1_binding);

    let q1_point = Point::constant(&mut em, q1_nested_commitment)?;
    q1_point.write(&mut em, &mut transcript)?;

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

    let s_polynomial = circuit_mesh.xy(x_challenge, y_challenge);
    let s_blinding = C::CircuitField::random(OsRng);
    let s_commitment = s_polynomial.commit(host_generators, s_blinding);

    let s: CommittedPolynomial<_, C> = CommittedPolynomial {
        poly: s_polynomial,
        blind: s_blinding,
        commitment: s_commitment,
    };

    // INNER LAYER: Staging polynomial (over Fq) that witnesses the S Vesta commitment.
    let q2_inner_rx =
        <EphemeralStageQuery<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[s_commitment])?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
    let q2_blinding = C::ScalarField::random(OsRng);
    let q2_nested_commitment = q2_inner_rx.commit(nested_generators, q2_blinding);

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: Compute evaluations.
    ///////////////////////////////////////////////////////////////////////////////////////

    let circuit_evaluations: [C::CircuitField; NUM_APP_CIRCUITS] =
        [circuit_mesh.wxy(omega_j(circuit_id as u32), x_challenge, y_challenge)];

    let consistency_evaluations = ConsistencyEvaluations::<C> {
        acc1_s_at_w: left.proof.witness.s_poly.eval(w_challenge),
        acc2_s_at_w: right.proof.witness.s_poly.eval(w_challenge),
        s1_acc1_at_y: s_prime[0].poly.eval(y_challenge),
        s1_acc2_at_y: s_prime[1].poly.eval(y_challenge),
        s2_at_x: s_prime_prime[0].poly.eval(x_challenge),
    };

    let a_polys_evals_x: Vec<C::CircuitField> = a_polys
        .iter()
        .map(|a_poly| a_poly.poly.eval(x_challenge))
        .collect();
    let a_polys_evals_xz: Vec<C::CircuitField> = a_polys
        .iter()
        .take(NUM_APP_CIRCUITS)
        .map(|a_poly| a_poly.poly.eval(xz))
        .collect();
    let acc_b_evals_x = [
        left.proof.witness.b_poly.eval(x_challenge),
        right.proof.witness.b_poly.eval(x_challenge),
    ];

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: Compute batched polynomial evaluation claims.
    ///////////////////////////////////////////////////////////////////////////////////////

    let batched_a_eval = {
        a_polys_evals_x
            .iter()
            .rev()
            .fold(C::CircuitField::ZERO, |acc, &eval| acc * mu_inv + eval)
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
            .fold(C::CircuitField::ZERO, |acc, &eval| acc * munu + eval)
    };

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: Absorb all evaluations into the transcript before deriving alpha.
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
    let _ =
        Element::constant(&mut em, consistency_evaluations.s2_at_x).write(&mut em, &mut transcript);

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

    let mut intermediate_evals = Vec::with_capacity(NUM_EVALS);

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

    let intermediate_evals_array: [C::CircuitField; NUM_EVALS] = intermediate_evals
        .try_into()
        .expect("intermediate_evals should have exactly NUM_EVALS elements");

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: Compute E staging polynomial.
    ///////////////////////////////////////////////////////////////////////////////////////

    let q_staging_witness = (
        [mu_challenge, nu_challenge, x_challenge],
        [q1_nested_commitment, q2_nested_commitment],
        intermediate_evals_array,
    );

    let q_rx = <QueryStage<C::NestedCurve> as StageExt<C::CircuitField, R>>::rx(q_staging_witness)?;

    ///////////////////////////////////////////////////////////////////////////////////////
    // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
    // an Fp-hashable nested commitment for the transcript.
    let q_rx_blinding = C::CircuitField::random(OsRng);
    let q_rx_commitment = q_rx.commit(host_generators, q_rx_blinding);

    // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
    let q_rx_inner =
        <IndirectionStageQuery<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(q_rx_commitment)?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
    let q_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
    let q_rx_nested_commitment =
        q_rx_inner.commit(nested_generators, q_rx_nested_commitment_blinding);

    let q_point = Point::constant(&mut em, q_rx_nested_commitment)?;
    q_point.write(&mut em, &mut transcript)?;
    ///////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////////////////
    // PHASE: EVALUATION STAGE.
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
        let mut queries: Vec<Box<dyn Iterator<Item = C::CircuitField>>> = vec![
            factor_iter(a_folded.poly.iter_coeffs(), x_challenge),
            factor_iter(b_folded.poly.iter_coeffs(), x_challenge),
            factor_iter(
                left.proof.witness.p_poly.iter_coeffs(),
                left.proof.instance.u.0,
            ),
            factor_iter(
                right.proof.witness.p_poly.iter_coeffs(),
                right.proof.instance.u.0,
            ),
            factor_iter(left.proof.witness.s_poly.iter_coeffs(), w_challenge),
            factor_iter(right.proof.witness.s_poly.iter_coeffs(), w_challenge),
            factor_iter(s.poly.iter_coeffs(), omega_j(circuit_id as u32)),
            factor_iter(s.poly.iter_coeffs(), w_challenge),
            factor_iter(s_prime[0].poly.iter_coeffs(), left.proof.instance.y.0),
            factor_iter(s_prime[1].poly.iter_coeffs(), right.proof.instance.y.0),
            factor_iter(s_prime[0].poly.iter_coeffs(), y_challenge),
            factor_iter(s_prime[1].poly.iter_coeffs(), y_challenge),
            factor_iter(s_prime_prime[0].poly.iter_coeffs(), left.proof.instance.x.0),
            factor_iter(
                s_prime_prime[0].poly.iter_coeffs(),
                right.proof.instance.x.0,
            ),
            factor_iter(s_prime_prime[0].poly.iter_coeffs(), x_challenge),
        ];

        for a_poly in &a_polys {
            queries.push(factor_iter(a_poly.poly.iter_coeffs(), x_challenge));
        }

        for a_poly in a_polys.iter().take(1) {
            queries.push(factor_iter(a_poly.poly.iter_coeffs(), xz));
        }

        let mut f_poly = Vec::with_capacity(R::num_coeffs());
        'poly: loop {
            let mut this_coeff = C::CircuitField::ZERO;
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
        unstructured::Polynomial::<C::CircuitField, R>::from_coeffs(f_poly)
    };

    let f_blinding = C::CircuitField::random(OsRng);
    let f_commitment = f_polynomial.commit(host_generators, f_blinding);

    let f: CommittedPolynomial<_, C> = CommittedPolynomial {
        poly: f_polynomial,
        blind: f_blinding,
        commitment: f_commitment,
    };

    // INNER LAYER: Staging polynomial (over Fq) that witnesses the F Vesta commitment.
    let g1_inner_rx =
        <EphemeralStageEvaluation<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[
            f.commitment
        ])?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
    let g1_blinding = C::ScalarField::random(OsRng);
    let g1_nested_commitment: <C as Cycle>::NestedCurve =
        g1_inner_rx.commit(nested_generators, g1_blinding);

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

    let evaluations_final = FinalEvaluations::<C> {
        a: a_folded.poly.eval(u_challenge),
        b: b_folded.poly.eval(u_challenge),
        acc1_p: left.proof.witness.p_poly.eval(u_challenge),
        acc2_p: right.proof.witness.p_poly.eval(u_challenge),
        acc1_s: left.proof.witness.s_poly.eval(u_challenge),
        acc2_s: right.proof.witness.s_poly.eval(u_challenge),
        s: s.poly.eval(u_challenge),
        s1: [
            s_prime[0].poly.eval(u_challenge),
            s_prime[1].poly.eval(u_challenge),
        ],
        s2: s_prime_prime[0].poly.eval(u_challenge),
    };

    let a_polys_final_evals: Vec<C::CircuitField> = a_polys
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

    let final_evals_array: [C::CircuitField; NUM_FINAL_EVALS] = final_evals
        .try_into()
        .expect("intermediate_evals should have exactly `NUM_FINAL_EVALS` elements");

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: Compute G staging polynomial.
    ///////////////////////////////////////////////////////////////////////////////////////

    let g_staging_witness = (
        [alpha_challenge, u_challenge],
        [g1_nested_commitment],
        final_evals_array,
    );

    let g_rx =
        <EvaluationStage<C::NestedCurve> as StageExt<C::CircuitField, R>>::rx(g_staging_witness)?;

    ///////////////////////////////////////////////////////////////////////////////////////
    // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
    // an Fp-hashable nested commitment for the transcript.
    let g_rx_blinding = C::CircuitField::random(OsRng);
    let g_rx_commitment = g_rx.commit(host_generators, g_rx_blinding);

    // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
    let g_rx_inner = <IndirectionStageEvaluation<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(
        g_rx_commitment,
    )?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
    let g_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
    let g_rx_nested_commitment =
        g_rx_inner.commit(nested_generators, g_rx_nested_commitment_blinding);

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
    let (_v, p_poly, p_blind) = {
        let mut v = C::CircuitField::ZERO;

        let mut proc = |point: C::CircuitField, eval, eval_prime| {
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
            left.proof.instance.u.0,
            left.proof.instance.v.0,
            evaluations_final.acc1_p,
        );
        proc(
            right.proof.instance.u.0,
            right.proof.instance.v.0,
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
        proc(
            omega_j(circuit_id as u32),
            circuit_evaluations[0],
            evaluations_final.s,
        );

        // s2 at x.
        proc(
            w_challenge,
            consistency_evaluations.s2_at_x,
            evaluations_final.s,
        );

        // s1 polynomials at accumulator y points.
        proc(
            left.proof.instance.y.0,
            consistency_evaluations.acc1_s_at_w,
            evaluations_final.s1[0],
        );
        proc(
            right.proof.instance.y.0,
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
            left.proof.instance.x.0,
            consistency_evaluations.s1_acc1_at_y,
            evaluations_final.s2,
        );
        proc(
            right.proof.instance.x.0,
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
            .zip(a_polys_final_evals.iter().take(1))
        {
            proc(xz, *eval_xz, *final_eval);
        }

        let mut p_poly = f.poly.clone();
        let mut p_blind = f.blind;

        let mut proc = |f: &dyn Fn(&mut unstructured::Polynomial<C::CircuitField, R>),
                        eval_prime: C::CircuitField,
                        blind| {
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
            &|p| p.add_assign(&left.proof.witness.p_poly),
            evaluations_final.acc1_p,
            &left.proof.witness.p_blinding,
        );
        proc(
            &|p| p.add_assign(&right.proof.witness.p_poly),
            evaluations_final.acc2_p,
            &right.proof.witness.p_blinding,
        );
        proc(
            &|p| p.add_assign(&left.proof.witness.s_poly),
            evaluations_final.acc1_s,
            &left.proof.witness.s_blinding,
        );
        proc(
            &|p| p.add_assign(&right.proof.witness.s_poly),
            evaluations_final.acc2_s,
            &right.proof.witness.s_blinding,
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
    let _eval_points: [C::CircuitField; NUM_V_QUERIES] = eval_points
        .try_into()
        .expect("eval_points length should match NUM_V_QUERIES");
    let _intermediate_evals: [C::CircuitField; NUM_V_QUERIES] = intermediate_evals
        .try_into()
        .expect("intermediate_evals length should match NUM_V_QUERIES");
    let _final_evals_for_queries: [C::CircuitField; NUM_V_QUERIES] = final_evals_for_queries
        .try_into()
        .expect("final_evals_for_queries length should match NUM_V_QUERIES");
    let _inverses: [C::CircuitField; NUM_V_QUERIES] = inverses
        .try_into()
        .expect("inverses length should match NUM_V_QUERIES");

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: Compute p(X) commitment.
    ///////////////////////////////////////////////////////////////////////////////////////

    let p_commitment = p_poly.commit(host_generators, p_blind);

    let p: CommittedPolynomial<_, C> = CommittedPolynomial {
        poly: p_poly,
        blind: p_blind,
        commitment: p_commitment,
    };

    // INNER LAYER: Staging polynomial (over Fq) that witnesses the F Vesta commitment.
    let g2_inner_rx =
        <EphemeralStageEvaluation<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[
            p.commitment
        ])?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
    let g2_blinding = C::ScalarField::random(OsRng);
    let g2_nested_commitment: <C as Cycle>::NestedCurve =
        g2_inner_rx.commit(nested_generators, g2_blinding);

    let g2_point = Point::constant(&mut em, g2_nested_commitment)?;
    g2_point.write(&mut em, &mut transcript)?;

    ///////////////////////////////////////////////////////////////////////////////////////
    // TASK: Build KY staging polyhnomial for ky polynomial coefficients.
    ///////////////////////////////////////////////////////////////////////////////////////

    // TODO: Rethink this.

    // // Append application circuits ky coefficients.
    // let mut application_ky_coffs = Vec::new();
    // for ky_poly in &ky_polys {
    //     application_ky_coffs.extend_from_slice(ky_poly);
    // }

    // // Convert to FixedVec for KYStage.
    // let ky_coeffs_vec = FixedVec::<_, TotalKyCoeffsLen<NUM_APP_CIRCUITS, HEADER_SIZE>>::try_from(
    //     application_ky_coffs,
    // )
    // .map_err(|_| {
    //     Error::CircuitBoundExceeded(TotalKyCoeffsLen::<NUM_APP_CIRCUITS, HEADER_SIZE>::len())
    // })?;

    // // Build the K staging polynomial.
    // let k_rx = <KYStage<C::NestedCurve, NUM_APP_CIRCUITS, HEADER_SIZE> as StageExt<
    //     C::CircuitField,
    //     R,
    // >>::rx(ky_coeffs_vec)?;

    // ///////////////////////////////////////////////////////////////////////////////////////
    // // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
    // // an Fp-hashable nested commitment for the transcript.
    // let k_rx_blinding = C::CircuitField::random(OsRng);
    // let k_rx_commitment = k_rx.commit(host_generators, k_rx_blinding);

    // // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
    // let k_rx_inner =
    //     <IndirectionStageKY<C::HostCurve> as StageExt<C::ScalarField, R>>::rx(k_rx_commitment)?;

    // // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators (nested curve).
    // let k_rx_nested_commitment_blinding = C::ScalarField::random(OsRng);
    // let k_rx_nested_commitment =
    //     k_rx_inner.commit(nested_generators, k_rx_nested_commitment_blinding);

    // let k_point = Point::constant(&mut em, k_rx_nested_commitment)?;
    // k_point.write(&mut em, &mut transcript)?;
    /////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////////////////
    // PHASE: Return the proof.
    ///////////////////////////////////////////////////////////////////////////////////////

    Ok((
        Proof {
            circuit_id,
            left_header: left_header.into_inner(),
            right_header: right_header.into_inner(),
            rx,
            _marker: PhantomData,
            witness: left.proof.witness,
            instance: left.proof.instance,
            endoscalars: left.proof.endoscalars,
            deferreds: left.proof.deferreds,
            staged_circuits: left.proof.staged_circuits,
        },
        aux,
    ))
}
