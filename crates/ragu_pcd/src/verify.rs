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
    host_generators: &C::HostGenerators,
    mut rng: RNG,
) -> Result<bool> {
    let witness = &pcd.proof.witness;
    let instance = &pcd.proof.instance;

    ///////////////////////////////////////////////////////////////////////////////////////
    // High-level revdot equation check: rx.revdot(rhs) == k(y)
    ///////////////////////////////////////////////////////////////////////////////////////

    let rx = &pcd.proof.rx;
    let circuit_id = omega_j(pcd.proof.circuit_id as u32);
    let y = C::CircuitField::random(&mut rng);
    let z = C::CircuitField::random(&mut rng);
    let sy = circuit_mesh.wy(circuit_id, y);
    let tz = R::tz(z);

    let mut rhs = rx.clone();
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

    if rx.revdot(&rhs) != eval(ky.iter(), y) {
        return Ok(false);
    }

    ///////////////////////////////////////////////////////////////////////////////////////
    // Witness/instance consistency checks
    ///////////////////////////////////////////////////////////////////////////////////////

    // Check revdot: a.revdot(b) == c.
    if witness.a_poly.revdot(&witness.b_poly) != instance.c {
        return Ok(false);
    }

    // Check polynomial evaluation: p_poly(u) == v.
    if witness.p_poly.eval(instance.u.0) != instance.v.0 {
        return Ok(false);
    }

    // Check mesh consistency: s_poly == mesh.xy(x, y).
    if witness.s_poly != circuit_mesh.xy(instance.x.0, instance.y.0) {
        return Ok(false);
    }

    ///////////////////////////////////////////////////////////////////////////////////////
    // Commitment opening checks (TODO: implement full IPA verification)
    ///////////////////////////////////////////////////////////////////////////////////////

    // Verify commitment openings with pedersen vector commitments.
    let a_commitment = witness.a_poly.commit(host_generators, witness.a_blinding);
    if a_commitment != instance.a {
        return Ok(false);
    }

    let b_commitment = witness.b_poly.commit(host_generators, witness.b_blinding);
    if b_commitment != instance.b {
        return Ok(false);
    }

    let p_commitment = witness.p_poly.commit(host_generators, witness.p_blinding);
    if p_commitment != instance.p {
        return Ok(false);
    }

    let s_commitment = witness.s_poly.commit(host_generators, witness.s_blinding);
    if s_commitment != instance.s {
        return Ok(false);
    }

    Ok(true)
}
