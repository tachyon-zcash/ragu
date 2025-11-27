use arithmetic::Cycle;
use ragu_circuits::{CircuitExt, polynomials::Rank};
use ragu_core::Result;
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
    let _circuit_poseidon = params.circuit_poseidon();
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
        },
        aux,
    ))
}
