//! Transcript routines for computing Fiat-Shamir challenges.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, emulator::Emulator},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, Point, Sponge};

/// Computation of w = H(nested_preamble_commitment)
pub fn derive_w<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nested_preamble_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    nested_preamble_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Compute $w$ challenge using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_w<C: Cycle>(
    nested_preamble_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless(nested_preamble_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_w::<_, C>(dr, &point, params)?.value().take())
    })
}
