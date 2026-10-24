//! Gadget handles for commitments to witnessed polynomials.

use core::marker::PhantomData;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, consistent::Consistent, io::Write};
use udon::{curve::Affine as _, field::Field};

/// Circuit-field elements occupied by a polynomial commitment handle.
const HANDLE_WIRES: usize = 2;

/// Encodes a host-curve commitment as two circuit-field elements.
fn commitment_limbs<C: Cycle>(commitment: C::HostCurve) -> Result<[C::CircuitField; HANDLE_WIRES]> {
    let repr = commitment.to_bytes();
    let Ok(repr) = <[u8; 32]>::try_from(repr.as_ref()) else {
        return Err(Error::InvalidWitness(
            "only 32-byte point encodings are supported".into(),
        ));
    };
    let (lo, hi) = repr.split_at(16);
    let limb = |bytes: &[u8]| {
        C::CircuitField::from_u128(u128::from_le_bytes(
            bytes.try_into().expect("a limb contains 16 bytes"),
        ))
    };
    Ok([limb(lo), limb(hi)])
}

/// A gadget naming the commitment behind a polynomial witnessed by this step.
///
/// The commitment is on the host curve, whose coordinates cannot be represented
/// as native circuit-field elements. The handle instead carries its compressed
/// encoding in two circuit-field elements, so it can be opened, absorbed into
/// challenges, or serialized like other gadgets.
#[derive(Gadget, Write, Consistent)]
pub struct PolyHandle<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    #[ragu(gadget)]
    limbs: [Element<'dr, D>; HANDLE_WIRES],
    #[ragu(phantom)]
    _cycle: PhantomData<C>,
}

impl<'dr, D, C> PolyHandle<'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    pub(crate) fn new<R: Rank>(
        dr: &mut D,
        params: &C::Params,
        polynomial: &DriverValue<D, sparse::Polynomial<C::CircuitField, R>>,
    ) -> Result<(Self, DriverValue<D, C::HostCurve>)> {
        let to_commit = polynomial.as_ref();
        let commitment = D::just(move || {
            to_commit
                .take()
                .commit_to_affine(C::host_generators(params))
        });
        let encoded = commitment.as_ref();
        let limbs = D::try_just(move || commitment_limbs::<C>(*encoded.take()))?;
        let handle = Self::alloc(dr, limbs)?;
        Ok((handle, commitment))
    }

    fn alloc(dr: &mut D, limbs: DriverValue<D, [D::F; HANDLE_WIRES]>) -> Result<Self> {
        Ok(Self {
            limbs: [
                Element::alloc(dr, &mut (), limbs.as_ref().map(|limbs| limbs[0]))?,
                Element::alloc(dr, &mut (), limbs.as_ref().map(|limbs| limbs[1]))?,
            ],
            _cycle: PhantomData,
        })
    }

    pub(crate) fn value(&self) -> DriverValue<D, [D::F; HANDLE_WIRES]> {
        let limbs = [self.limbs[0].value(), self.limbs[1].value()];
        D::just(move || limbs.map(|limb| *limb.take()))
    }
}
