use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    mesh::{Mesh, omega_j},
    polynomials::Rank,
    staging::{StageExt, Staged},
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt, Point, Sponge};
use rand::Rng;

use core::marker::PhantomData;

use crate::{
    Pcd, Proof, internal_circuits, stages,
    step::{Step, adapter::Adapter},
};

pub fn merge<'source, C: Cycle, R: Rank, RNG: Rng, S: Step<C>, const HEADER_SIZE: usize>(
    num_application_steps: usize,
    circuit_mesh: &ragu_circuits::mesh::Mesh<'_, C::CircuitField, R>,
    params: &C,
    rng: &mut RNG,
    step: S,
    witness: S::Witness<'source>,
    left: Pcd<'source, C, R, S::Left>,
    right: Pcd<'source, C, R, S::Right>,
) -> Result<(Proof<C, R>, S::Aux<'source>)> {
    let host_generators = params.host_generators();
    let nested_generators = params.nested_generators();
    let circuit_poseidon = params.circuit_poseidon();

    // Compute the preamble (just a stub)
    let preamble_rx = stages::native::preamble::Stage::<C, R>::rx(())?;
    let preamble_blind = C::CircuitField::random(&mut *rng);
    let preamble_commitment = preamble_rx.commit(host_generators, preamble_blind);

    // Compute nested preamble
    let nested_preamble_rx =
        stages::nested::preamble::Stage::<C::HostCurve, R>::rx(preamble_commitment)?;
    let nested_preamble_blind = C::ScalarField::random(&mut *rng);
    let nested_preamble_commitment =
        nested_preamble_rx.commit(nested_generators, nested_preamble_blind);

    // Compute w = H(nested_preamble_commitment)
    let w: C::CircuitField = Emulator::emulate_wireless(nested_preamble_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        let mut sponge = Sponge::new(dr, circuit_poseidon);
        point.write(dr, &mut sponge)?;
        Ok(*sponge.squeeze(dr)?.value().take())
    })?;

    // Create the unified instance.
    let unified_instance = &internal_circuits::unified::Instance {
        nested_preamble_commitment,
        w,
    };

    // Circuit for computing `c` value (incomplete)
    // See: c.rs
    let internal_circuit_c = internal_circuits::c::Circuit::<C, R>::new(circuit_poseidon);
    let internal_circuit_c_witness = internal_circuits::c::Witness { unified_instance };
    let internal_circuit_c_staged = Staged::new(internal_circuit_c);
    let (internal_circuit_c_rx, _) =
        internal_circuit_c_staged.rx::<R>(internal_circuit_c_witness, circuit_mesh.get_key())?;

    let ky = Staged::new(internal_circuits::c::Circuit::<C, R>::new(circuit_poseidon))
        .ky(unified_instance)?;

    {
        let mut combined_rx = preamble_rx.clone();
        combined_rx.add_assign(&internal_circuit_c_rx);

        debug_assert_rx_valid::<C, R, _>(
            &combined_rx,
            &ky,
            circuit_mesh,
            num_application_steps,
            internal_circuits::c::CIRCUIT_ID,
            rng,
        );
    }

    // Application
    let application_circuit_id = S::INDEX.circuit_index(Some(num_application_steps))?;
    let (application_rx, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step)
        .rx::<R>((left.data, right.data, witness), circuit_mesh.get_key())?;
    let ((left_header, right_header), aux) = aux;

    Ok((
        Proof {
            application_circuit_id,
            left_header: left_header.into_inner(),
            right_header: right_header.into_inner(),
            application_rx,
            _marker: PhantomData,
        },
        aux,
    ))
}

/// Debug helper to assert that an rx polynomial is valid for a given internal circuit.
///
/// This samples random challenges and verifies the polynomial identity:
/// `rx.revdot(rhs) == eval(ky, y)` where `rhs = rx * z + sy + tz`.
fn debug_assert_rx_valid<C: Cycle, R: Rank, RNG: Rng>(
    rx: &ragu_circuits::polynomials::structured::Polynomial<C::CircuitField, R>,
    ky: &[C::CircuitField],
    circuit_mesh: &Mesh<'_, C::CircuitField, R>,
    num_application_steps: usize,
    internal_circuit_id: usize,
    rng: &mut RNG,
) {
    let tmp_y = C::CircuitField::random(&mut *rng);
    let tmp_z = C::CircuitField::random(&mut *rng);

    let circuit_id =
        omega_j(internal_circuits::index(num_application_steps, internal_circuit_id) as u32);
    let sy = circuit_mesh.wy(circuit_id, tmp_y);
    let tz = R::tz(tmp_z);

    let mut rhs = rx.clone();
    rhs.dilate(tmp_z);
    rhs.add_assign(&sy);
    rhs.add_assign(&tz);

    assert_eq!(rx.revdot(&rhs), arithmetic::eval(ky.iter(), tmp_y));
}
