use arithmetic::Cycle;
use ragu_circuits::{
    CircuitExt,
    composition::preamble_stage::{NestedPreambleStage, PreambleStage},
    polynomials::{Rank, TotalKyCoeffsLen},
    staging::StageExt,
};
use ragu_core::{Error, Result, drivers::emulator::Emulator};
use ragu_primitives::{Point, Sponge};
use rand::{Rng, rngs::OsRng};

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_primitives::vec::FixedVec;

use crate::{
    Pcd, Proof,
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
    // Task: Execute application logic via `Step::witness()` through the `Adapter`.
    ///////////////////////////////////////////////////////////////////////////////////////

    let circuit_id = S::INDEX.circuit_index(Some(num_application_steps))?;
    let circuit = Adapter::<C, S, R, HEADER_SIZE>::new(step);

    let left_data = left.data.clone();
    let right_data = right.data.clone();

    // Compute r(X) polynomial and commitments for this step.
    let (rx, aux) = circuit.rx::<R>((left.data, right.data, witness), circuit_mesh.get_key())?;
    let ((left_header, right_header), aux) = aux;

    ///////////////////////////////////////////////////////////////////////////////////////
    // Task: Reconstruct k(Y) public input polynomial for the left and right PCDs.
    ///////////////////////////////////////////////////////////////////////////////////////

    let left_ky_poly = {
        let adapter = Adapter::<C, StubStep<S::Left>, R, HEADER_SIZE>::new(StubStep::new());
        let left_header = FixedVec::try_from(left.proof.left_header.clone())
            .map_err(|_| Error::MalformedEncoding("left header size".into()))?;
        let right_header = FixedVec::try_from(left.proof.right_header.clone())
            .map_err(|_| Error::MalformedEncoding("right header size".into()))?;
        adapter.ky((left_header, right_header, left_data))?
    };

    let right_ky_poly = {
        let adapter = Adapter::<C, StubStep<S::Right>, R, HEADER_SIZE>::new(StubStep::new());
        let left_header = FixedVec::try_from(right.proof.left_header.clone())
            .map_err(|_| Error::MalformedEncoding("left header size".into()))?;
        let right_header = FixedVec::try_from(right.proof.right_header.clone())
            .map_err(|_| Error::MalformedEncoding("right header size".into()))?;
        adapter.ky((left_header, right_header, right_data))?
    };

    // Flatten k(Y) coefficients from left and right input PCDs.
    let ky_coeffs: Vec<C::CircuitField> = [left_ky_poly, right_ky_poly]
        .into_iter()
        .flatten()
        .collect();

    ///////////////////////////////////////////////////////////////////////////////////////
    // PHASE: PREAMBLE STAGE.
    //
    // Two-layer staging architecture.
    ///////////////////////////////////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////////////////////////////
    // LAYER 1: Preamble Stage (over C::CircuitField)
    ///////////////////////////////////////////////////////////////////////////////////////

    let preamble_rx =
        <PreambleStage<C::CircuitField, TotalKyCoeffsLen<HEADER_SIZE, 2>> as StageExt<
            C::CircuitField,
            R,
        >>::rx(&ky_coeffs)?;

    let preamble_blinding = C::CircuitField::random(OsRng);
    let preamble_commitment = preamble_rx.commit(host_generators, preamble_blinding);

    ///////////////////////////////////////////////////////////////////////////////////////
    // LAYER 2: Nested Preamble Stage (over C::ScalarField)
    //
    // We now introduce another nested commitment layer to produce an C::CircuitField-
    // hashable nested commitment for the transcript.
    ///////////////////////////////////////////////////////////////////////////////////////

    let nested_points: [C::HostCurve; 3] = [
        preamble_commitment,
        left.proof.instance.a,
        right.proof.instance.a,
    ];

    let nested_rx =
        <NestedPreambleStage<C::HostCurve, 3> as StageExt<C::ScalarField, R>>::rx(&nested_points)?;

    // NESTED COMMITMENT: Commit to the nested polynomial using Pallas generators (nested curve).
    let nested_blinding = C::ScalarField::random(OsRng);
    let nested_commitment = nested_rx.commit(nested_generators, nested_blinding);

    ///////////////////////////////////////////////////////////////////////////////////////
    // ABSORB-IN-TRANSCRIPT: The Pallas point can be absorbed in the Fp transcript.
    ///////////////////////////////////////////////////////////////////////////////////////

    let preamble_point = Point::constant(&mut em, nested_commitment)?;
    preamble_point.write(&mut em, &mut transcript)?;

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
