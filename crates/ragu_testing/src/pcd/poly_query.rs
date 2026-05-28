//! Test fixture: a Step that opens a polynomial commitment, chains the
//! commitment into a Poseidon-hash digest of the previous step's hash, and
//! threads an unstructured polynomial through the PCD tree as accompanying
//! data.
//!
//! The polynomial lives in [`HashedOpening`]'s `Data`, so it travels with
//! `Pcd<C, R, HashedOpening<R>>` and is reachable from `fuse(...)` via
//! [`Pcd::data`](ragu_pcd::Pcd::data) on the input children and from the
//! `application_data` produced for the resulting `Pcd`. It is **not**
//! exposed to the circuit — `Header::encode` only allocates the hash
//! digest. The commitment-and-opening claim view of the polynomial is
//! enforced via [`FrameworkHooks::enforce_polynomial_query`].
//!
//! [`FrameworkHooks::enforce_polynomial_query`]: ragu_pcd::framework_hooks::FrameworkHooks::enforce_polynomial_query

use core::marker::PhantomData;

use ff::Field;
use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    header::{Header, Suffix},
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{
    Element, GadgetExt, Point,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
};

/// Data carried by a [`HashedOpening`] header.
///
/// `hash` is the only field exposed to the circuit (via
/// [`Header::encode`]). `polynomial` is unstructured PCD data: it flows
/// through the tree alongside the proof but the circuit never sees it.
pub struct HashedOpeningData<F: Field, R: Rank> {
    pub hash: F,
    pub polynomial: sparse::Polynomial<F, R>,
}

impl<F: Field, R: Rank> Clone for HashedOpeningData<F, R> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            polynomial: self.polynomial.clone(),
        }
    }
}

pub struct HashedOpening<R>(PhantomData<R>);

impl<F: Field, R: Rank> Header<F> for HashedOpening<R> {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = HashedOpeningData<F, R>;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let hash = witness.map(|d| d.hash);
        Element::alloc(dr, allocator, hash)
    }
}

pub struct OpenAndHash<'params, C: Cycle, R> {
    pub poseidon_params: &'params C::CircuitPoseidon,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> OpenAndHash<'params, C, R> {
    pub fn new(poseidon_params: &'params C::CircuitPoseidon) -> Self {
        Self {
            poseidon_params,
            _marker: PhantomData,
        }
    }
}

pub struct OpenAndHashWitness<C: CurveAffine, R: Rank> {
    pub com: C,
    pub x: C::Base,
    pub y: C::Base,
    pub polynomial: sparse::Polynomial<C::Base, R>,
}

impl<C: Cycle, R: Rank> Step<C> for OpenAndHash<'_, C, R> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = OpenAndHashWitness<C::NestedCurve, R>;
    type Aux<'source> = ();
    type Left = HashedOpening<R>;
    type Right = ();
    type Output = HashedOpening<R>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C::NestedCurve>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, HashedOpeningData<C::CircuitField, R>>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left_encoded = Encoded::new(ctx.dr, allocator, left)?;

        let com_witness = witness.as_ref().map(|w| w.com);
        let x_witness = witness.as_ref().map(|w| w.x);
        let y_witness = witness.as_ref().map(|w| w.y);
        let polynomial_witness = witness.map(|w| w.polynomial);

        let com = Point::alloc(ctx.dr, com_witness)?;
        let x = Element::alloc(ctx.dr, allocator, x_witness)?;
        let y = Element::alloc(ctx.dr, allocator, y_witness)?;

        let mut sponge = Sponge::new(ctx.dr, self.poseidon_params);
        sponge.absorb(ctx.dr, left_encoded.as_gadget())?;
        com.write(ctx.dr, &mut sponge)?;
        let output = sponge.squeeze(ctx.dr)?;
        let output_hash = output.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(output);

        ctx.enforce_poly_query(com, x, y)?;

        let output_data = output_hash.and_then(|hash| {
            polynomial_witness.map(|polynomial| HashedOpeningData { hash, polynomial })
        });

        Ok((
            (left_encoded, Encoded::from_gadget(()), output_encoded),
            output_data,
            D::unit(),
        ))
    }
}
