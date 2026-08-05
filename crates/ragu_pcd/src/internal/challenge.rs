//! The native side of challenge derivation.

use ragu_arithmetic::{Cycle, ff::PrimeField};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{Element, GadgetExt, poseidon::Sponge};

/// Absorbed first by every challenge derivation, before the inputs.
///
/// Its value is arbitrary; what it buys is that the sponge is never empty, so
/// a derivation absorbing nothing is still a derivation and a layout may
/// declare challenges of width zero.
const DOMAIN_TAG: u128 = u64::from_le_bytes(*b"raguchal") as u128;

/// [`DOMAIN_TAG`] in the circuit field.
pub(crate) fn domain_tag<C: Cycle>() -> C::CircuitField {
    C::CircuitField::from_u128(DOMAIN_TAG)
}

/// The challenge `inputs` derives. The `challenge_binding` circuit enforces
/// this same sponge, and the two must agree exactly, [`DOMAIN_TAG`] included.
pub(crate) fn challenge_of<C: Cycle>(
    params: &C::Params,
    inputs: &[C::CircuitField],
) -> Result<C::CircuitField> {
    let mut dr = Emulator::execute();
    let mut sponge = Sponge::new(&mut dr, C::circuit_poseidon(params));
    // The tag is not carried anywhere: it is a constant both sides know, and
    // absorbing it is what makes a zero-width derivation a derivation.
    Element::constant(&mut dr, domain_tag::<C>()).write(&mut dr, &mut sponge)?;
    for &input in inputs {
        Element::constant(&mut dr, input).write(&mut dr, &mut sponge)?;
    }
    let challenge = sponge.squeeze(&mut dr)?;
    Ok(*challenge.value().take())
}
