//! Fiat-Shamir transcript using Poseidon sponge.

use ff::{Field, PrimeField};
use ragu_arithmetic::{CurveAffine, Cycle, PoseidonPermutation};
use ragu_core::drivers::emulator::{Emulator, Wireless};
use ragu_core::maybe::{Always, Maybe};
use ragu_primitives::{Element, poseidon::Sponge};

/// Fiat-Shamir transcript using Poseidon sponge.
pub(crate) struct Transcript<'p, C: Cycle> {
    emulator: Emulator<Wireless<Always<()>, C::CircuitField>>,
    sponge: Sponge<'p, Emulator<Wireless<Always<()>, C::CircuitField>>, C::CircuitPoseidon>,
}

impl<'p, C: Cycle> Transcript<'p, C>
where
    C::CircuitField: PrimeField,
    C::CircuitPoseidon: PoseidonPermutation<C::CircuitField>,
{
    pub(crate) fn new(poseidon: &'p C::CircuitPoseidon) -> Self {
        let mut emulator = Emulator::execute();
        let sponge = Sponge::new(&mut emulator, poseidon);
        Transcript { emulator, sponge }
    }

    pub(crate) fn absorb_scalar(&mut self, scalar: &C::CircuitField) {
        let elem = Element::constant(&mut self.emulator, *scalar);
        self.sponge.absorb(&mut self.emulator, &elem).unwrap();
    }

    pub(crate) fn absorb_point(&mut self, point: &C::HostCurve)
    where
        C::ScalarField: PrimeField,
    {
        let coords = point.coordinates();
        if coords.is_some().into() {
            let coords = coords.unwrap();
            self.absorb_scalar(&field_from_bytes::<C::CircuitField>(
                coords.x().to_repr().as_ref(),
            ));
            self.absorb_scalar(&field_from_bytes::<C::CircuitField>(
                coords.y().to_repr().as_ref(),
            ));
        } else {
            self.absorb_scalar(&C::CircuitField::ZERO);
            self.absorb_scalar(&C::CircuitField::ZERO);
        }
    }

    pub(crate) fn squeeze_challenge(&mut self) -> C::CircuitField {
        *self
            .sponge
            .squeeze(&mut self.emulator)
            .unwrap()
            .value()
            .take()
    }
}

fn field_from_bytes<F: PrimeField>(bytes: &[u8]) -> F {
    let mut repr = F::Repr::default();
    let len = core::cmp::min(bytes.len(), repr.as_ref().len());
    repr.as_mut()[..len].copy_from_slice(&bytes[..len]);
    F::from_repr_vartime(repr).unwrap_or_else(|| {
        bytes
            .iter()
            .take(32)
            .enumerate()
            .fold(F::ZERO, |acc, (i, &b)| {
                acc + F::from(b as u64) * F::from(256u64).pow([i as u64])
            })
    })
}
