use arithmetic::Cycle;
use ragu_circuits::{CircuitExt, polynomials::Rank};
use ragu_core::{Error, Result, drivers::emulator::Emulator};
use ragu_primitives::Sponge;
use rand::Rng;

use core::marker::PhantomData;

use crate::{
    Pcd, Proof,
    step::{Step, adapter::Adapter},
};

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
    let _host_generators = params.host_generators();
    let _nested_generators = params.nested_generators();
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
    let mut _transcript = Sponge::new(&mut em, circuit_poseidon);

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
    // Task: Execute application logic via `Step::witness()` through the `Adapter`.
    ///////////////////////////////////////////////////////////////////////////////////////

    let circuit_id = S::INDEX.circuit_index(Some(num_application_steps))?;
    let circuit = Adapter::<C, S, R, HEADER_SIZE>::new(step);
    let (rx, aux) = circuit.rx::<R>((left.data, right.data, witness), circuit_mesh.get_key())?;

    let ((left_header, right_header), aux) = aux;

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
