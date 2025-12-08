//! Transcript routines for computing Fiat-Shamir challenges.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, emulator::Emulator},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, Point, Sponge};

/// In-circuit computation of w = H(nested_preamble_commitment)
pub fn compute_w<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nested_preamble_commitment: &Point<'dr, D, C::NestedCurve>,
    circuit_poseidon: &'dr C::CircuitPoseidon,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, circuit_poseidon);
    nested_preamble_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Compute w using the emulator (for use outside circuit context)
pub fn emulate_w<C: Cycle>(
    nested_preamble_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField>
where
    C::NestedCurve: Send,
{
    let circuit_poseidon = params.circuit_poseidon();
    Emulator::emulate_wireless(nested_preamble_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        Ok(*compute_w::<_, C>(dr, &point, circuit_poseidon)?
            .value()
            .take())
    })
}
