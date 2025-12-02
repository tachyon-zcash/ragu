use arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    composition::{
        error_stage::{EphemeralStageError, ErrorStage, IndirectionStageError},
        preamble_stage::EphemeralStagePreamble,
    },
    mesh::omega_j,
    polynomials::Rank,
    staging::StageExt,
};
use ragu_core::{Error, Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{Point, Sponge};
use rand::{Rng, rngs::OsRng};

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_primitives::vec::FixedVec;

use crate::{
    Pcd, Proof,
    proof::{CommittedPolynomial, CommittedStructured},
    step::{Step, adapter::Adapter},
    verify::stub_step::StubStep,
};
use ff::Field;
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
        _blind: blinding,
        commitment,
    });

    // Append the previous accumulator A polynomials.
    a_polys.push(CommittedPolynomial {
        poly: left.proof.witness.a_poly.clone(),
        _blind: left.proof.witness.a_blinding,
        commitment: left.proof.instance.a,
    });
    a_polys.push(CommittedPolynomial {
        poly: right.proof.witness.a_poly.clone(),
        _blind: right.proof.witness.a_blinding,
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
            _blind: s1_blinding_acc1,
            commitment: s1_commitment_acc1,
        },
        CommittedPolynomial {
            poly: s1_poly_acc2,
            _blind: s1_blinding_acc2,
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

    let _s_prime_prime: [CommittedPolynomial<_, C>; 1] = [CommittedPolynomial {
        poly: s2_poly,
        _blind: s2_blinding,
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
                _blind: b_blinding,
                commitment: b_commitment,
            }
        })
        .collect();

    // Append existing accumulator B polynomials.
    b_polys.push(CommittedPolynomial {
        poly: left.proof.witness.b_poly.clone(),
        _blind: left.proof.witness.b_blinding,
        commitment: left.proof.instance.b,
    });
    b_polys.push(CommittedPolynomial {
        poly: right.proof.witness.b_poly.clone(),
        _blind: right.proof.witness.b_blinding,
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
