use arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt, composition::b_stage::EphemeralStageB, polynomials::Rank, staging::StageExt,
};
use ragu_core::{Error, Result, drivers::emulator::Emulator};
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
    let mut _ky_polys: Vec<Vec<C::CircuitField>> = Vec::new();

    // Append r(X) witness polynomial from the application circuit.
    a_polys.push(CommittedPolynomial {
        _poly: rx.clone(),
        _blind: blinding,
        commitment,
    });

    // Append the previous accumulator A polynomials.
    a_polys.push(CommittedPolynomial {
        _poly: left.proof.witness.a_poly.clone(),
        _blind: left.proof.witness.a_blinding,
        commitment: left.proof.instance.a,
    });
    a_polys.push(CommittedPolynomial {
        _poly: right.proof.witness.a_poly.clone(),
        _blind: right.proof.witness.a_blinding,
        commitment: right.proof.instance.a,
    });

    // Append k(Y) polynomial from previous accumulators.
    _ky_polys.push(left_ky_poly);
    _ky_polys.push(right_ky_poly);

    ///////////////////////////////////////////////////////////////////////////////////////
    // PHASE: B STAGE.
    ///////////////////////////////////////////////////////////////////////////////////////

    // Temporary: Total circuits (1 application step + 2 accumulators)
    const NUM_CIRCUITS: usize = 3;
    const _NUM_APP_CIRCUITS: usize = 1;

    // Collect application circuit commitments (Vesta points).
    let a_commitments = a_polys
        .iter()
        .map(|c| c.commitment)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Error::CircuitBoundExceeded(NUM_CIRCUITS))?;

    // INNER LAYER: Staging polynomial (over Fq) that witnesses the Vesta commitments.
    let b_inner_rx = <EphemeralStageB<C::HostCurve, NUM_CIRCUITS> as StageExt<
        C::ScalarField,
        R,
    >>::rx(&a_commitments)?;

    // NESTED COMMITMENT: Commit to the epehemeral polynomial using Pallas generators.
    let b_blinding = C::ScalarField::random(OsRng);
    let b_rx_nested_commitment = b_inner_rx.commit(nested_generators, b_blinding);

    let b_point = Point::constant(&mut em, b_rx_nested_commitment)?;
    b_point.write(&mut em, &mut transcript)?;

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
