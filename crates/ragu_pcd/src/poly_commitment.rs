//! Handles to the commitments behind witnessed polynomials.
//!
//! A witnessed polynomial is over [`Cycle::CircuitField`], so its commitment
//! lands on [`Cycle::HostCurve`], whose elements are in
//! [`Cycle::ScalarField`]. A step cannot hold one, so it gets a handle.

use core::{array, marker::PhantomData};

use ragu_arithmetic::{Cycle, ff::PrimeField, group::GroupEncoding};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, consistent::Consistent, io::Write};

/// Circuit-field elements a handle occupies.
pub const HANDLE_WIRES: usize = 2;

/// The commitment's compressed encoding, split across two circuit-field
/// elements.
pub(crate) fn handle<C: Cycle>(host: C::HostCurve) -> Result<[C::CircuitField; HANDLE_WIRES]> {
    let repr = host.to_bytes();
    let Ok(repr) = <[u8; 32]>::try_from(repr.as_ref()) else {
        return Err(Error::InvalidWitness(
            "only 32-byte point encodings are supported".into(),
        ));
    };
    let (lo, hi) = repr.split_at(16);

    let limb = |bytes: &[u8]| {
        C::CircuitField::from_u128(u128::from_le_bytes(bytes.try_into().expect("16 bytes")))
    };
    Ok([limb(lo), limb(hi)])
}

/// A cross-field handle for a polynomial commitment.
#[derive(Gadget, Write, Consistent)]
pub struct PolyHandle<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    #[ragu(gadget)]
    handle: [Element<'dr, D>; HANDLE_WIRES],
    #[ragu(phantom)]
    _cycle: PhantomData<C>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> PolyHandle<'dr, D, C> {
    pub(crate) fn new<R: Rank>(
        dr: &mut D,
        params: &C::Params,
        polynomial: &DriverValue<D, sparse::Polynomial<C::CircuitField, R>>,
    ) -> Result<(Self, DriverValue<D, C::HostCurve>)> {
        let to_commit = polynomial.as_ref();
        let point = D::just(move || {
            to_commit
                .take()
                .commit_to_affine(C::host_generators(params))
        });

        let cast = point.as_ref();
        let handle = D::try_just(move || handle::<C>(*cast.take()))?;

        Ok((Self::alloc(dr, handle)?, point))
    }

    pub(crate) fn alloc(dr: &mut D, handle: DriverValue<D, [D::F; HANDLE_WIRES]>) -> Result<Self> {
        Ok(Self {
            handle: [
                Element::alloc(dr, &mut (), handle.as_ref().map(|h| h[0]))?,
                Element::alloc(dr, &mut (), handle.as_ref().map(|h| h[1]))?,
            ],
            _cycle: PhantomData,
        })
    }

    pub(crate) fn wires(&self) -> [Element<'dr, D>; HANDLE_WIRES] {
        self.handle.clone()
    }

    pub(crate) fn value(&self) -> DriverValue<D, [D::F; HANDLE_WIRES]> {
        let limbs: [_; HANDLE_WIRES] = array::from_fn(|i| self.handle[i].value());
        D::just(move || limbs.map(|limb| *limb.take()))
    }
}
