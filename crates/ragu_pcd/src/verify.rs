//! Proof-carrying data verification.

use arithmetic::{Cycle, eval};
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    mesh::{Mesh, omega_j},
    polynomials::Rank,
};
use ragu_core::{Error, Result};
use ragu_primitives::vec::{ConstLen, FixedVec};
use rand::Rng;

use crate::{Pcd, header::Header, step::adapter::Adapter};

mod stub_step;
use stub_step::StubStep;

/// Verifies some [`Pcd`] for the provided [`Header`].
pub fn verify<C: Cycle, R: Rank, RNG: Rng, H: Header<C::CircuitField>, const HEADER_SIZE: usize>(
    circuit_mesh: &Mesh<'_, C::CircuitField, R>,
    pcd: &Pcd<'_, C, R, H>,
    mut rng: RNG,
) -> Result<bool> {
    let application_rx = &pcd.proof.application_rx;
    let circuit_id = omega_j(pcd.proof.application_circuit_id as u32);
    let y = C::CircuitField::random(&mut rng);
    let z = C::CircuitField::random(&mut rng);
    let sy = circuit_mesh.wy(circuit_id, y);
    let tz = R::tz(z);

    let mut rhs = application_rx.clone();
    rhs.dilate(z);
    rhs.add_assign(&sy);
    rhs.add_assign(&tz);

    let left_header = FixedVec::<_, ConstLen<HEADER_SIZE>>::try_from(pcd.proof.left_header.clone())
        .map_err(|_| Error::MalformedEncoding("left_header has incorrect size".into()))?;
    let right_header =
        FixedVec::<_, ConstLen<HEADER_SIZE>>::try_from(pcd.proof.right_header.clone())
            .map_err(|_| Error::MalformedEncoding("right_header has incorrect size".into()))?;

    let ky = {
        let adapter = Adapter::<C, StubStep<H>, R, HEADER_SIZE>::new(StubStep::new());
        let instance = (left_header, right_header, pcd.data.clone());
        adapter.ky(instance)?
    };

    let valid = application_rx.revdot(&rhs) == eval(ky.iter(), y);

    Ok(valid)
}
