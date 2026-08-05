//! Test fixtures for the polynomial-query oracle: [`CommitAndOpen`] is a
//! seedable leaf, [`OpenAndHash`] a fuse of two such leaves. The polynomial
//! rides in [`HashedOpening`]'s `Data`, never in the circuit.

use core::marker::PhantomData;

use ff::{Field, PrimeField};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    AppHooks, Application, ApplicationBuilder, HANDLE_WIRES,
    header::{Header, Suffix},
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{
    Element, GadgetExt,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
};

/// Data carried by a [`HashedOpening`] header: the digest (the only field
/// the circuit sees) and the polynomial as unstructured PCD data.
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

/// Header exposing a Poseidon digest as a single element.
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

/// Witness for [`CommitAndOpen`]: the polynomial to witness, and an opening
/// `(x, y)` to claim for it. A `y` that is not `polynomial.eval(x)` makes the
/// step dishonest.
pub struct CommitAndOpenWitness<C: Cycle, R: Rank> {
    pub polynomial: sparse::Polynomial<C::CircuitField, R>,
    pub x: C::CircuitField,
    pub y: C::CircuitField,
}

/// A seedable leaf: witnesses a committed polynomial, derives a challenge
/// bound to the commitment, evaluates at it, and enforces the evaluation as
/// a poly query. The output header is a Poseidon digest of the commitment.
pub struct CommitAndOpen<'params, C: Cycle, R> {
    /// Cycle parameters, for challenge derivation and the Poseidon sponge.
    pub params: &'params C::Params,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> CommitAndOpen<'params, C, R> {
    pub fn new(params: &'params C::Params) -> Self {
        Self {
            params,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for CommitAndOpen<'_, C, R> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = CommitAndOpenWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = HashedOpening<R>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
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

        let x_witness = witness.as_ref().map(|w| w.x);
        let y_witness = witness.as_ref().map(|w| w.y);
        let polynomial = witness.map(|w| w.polynomial);
        let handle = ctx.witness_polynomial(polynomial.as_ref().map(|p| p.clone()))?;

        // No caller can know where the derived challenge lands, so this opening
        // is always honest.
        let z = ctx.derive_challenge(&handle)?;
        let at_z_value = ctx.evaluate(&handle, z.value().map(|z| *z))?;
        let at_z = Element::alloc(ctx.dr, allocator, at_z_value)?;
        ctx.enforce_poly_query(&handle, z, at_z)?;

        // The same handle again, so this spends a query slot, not a polynomial.
        let x = Element::alloc(ctx.dr, allocator, x_witness)?;
        let y = Element::alloc(ctx.dr, allocator, y_witness)?;
        ctx.enforce_poly_query(&handle, x, y)?;

        let mut sponge = Sponge::new(ctx.dr, C::circuit_poseidon(self.params));
        handle.write(ctx.dr, &mut sponge)?;
        let output = sponge.squeeze(ctx.dr)?;
        let output_hash = output.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(output);

        let output_data = output_hash
            .and_then(|hash| polynomial.map(|polynomial| HashedOpeningData { hash, polynomial }));

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                output_encoded,
            ),
            output_data,
            D::unit(),
        ))
    }
}

/// Witness for [`OpenAndHash`]: an opening `(x, y)` of a polynomial.
pub struct OpenAndHashWitness<C: Cycle, R: Rank> {
    pub polynomial: sparse::Polynomial<C::CircuitField, R>,
    pub x: C::CircuitField,
    pub y: C::CircuitField,
}

/// A fuse of two [`HashedOpening`] children: opens a witnessed commitment
/// at a witnessed point and chains it with both children's digests into a
/// new Poseidon digest.
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

impl<C: Cycle, R: Rank> Step<C> for OpenAndHash<'_, C, R> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = OpenAndHashWitness<C, R>;
    type Aux<'source> = ();
    type Left = HashedOpening<R>;
    type Right = HashedOpening<R>;
    type Output = HashedOpening<R>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, HashedOpeningData<C::CircuitField, R>>,
        right: DriverValue<D, HashedOpeningData<C::CircuitField, R>>,
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
        let right_encoded = Encoded::new(ctx.dr, allocator, right)?;

        let x_witness = witness.as_ref().map(|w| w.x);
        let y_witness = witness.as_ref().map(|w| w.y);
        let polynomial = witness.map(|w| w.polynomial);
        let handle = ctx.witness_polynomial(polynomial.as_ref().map(|p| p.clone()))?;

        let x = Element::alloc(ctx.dr, allocator, x_witness)?;
        let y = Element::alloc(ctx.dr, allocator, y_witness)?;

        let mut sponge = Sponge::new(ctx.dr, self.poseidon_params);
        sponge.absorb(ctx.dr, left_encoded.as_gadget())?;
        sponge.absorb(ctx.dr, right_encoded.as_gadget())?;
        handle.write(ctx.dr, &mut sponge)?;
        let output = sponge.squeeze(ctx.dr)?;
        let output_hash = output.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(output);

        ctx.enforce_poly_query(&handle, x, y)?;

        let output_data = output_hash
            .and_then(|hash| polynomial.map(|polynomial| HashedOpeningData { hash, polynomial }));

        Ok((
            (left_encoded, right_encoded, output_encoded),
            output_data,
            D::unit(),
        ))
    }
}

/// The header size [`CommitAndOpen`] and [`OpenAndHash`] are exercised at.
pub const HEADER_SIZE: usize = 4;

/// The fixtures' hook layout: one polynomial, two queries against it, and one
/// challenge derived from a handle.
pub type PolyQueryHooks = AppHooks<1, 2, 1, HANDLE_WIRES>;

/// An [`Application`] at the fixtures' layout.
pub type PolyQueryApp<'params, C, R> = Application<'params, C, R, HEADER_SIZE, PolyQueryHooks>;

/// A polynomial from small integer coefficients.
pub fn poly<F: PrimeField, R: Rank>(coeffs: &[u64]) -> sparse::Polynomial<F, R> {
    sparse::Polynomial::from_coeffs(coeffs.iter().map(|c| F::from(*c)).collect())
}

/// Both fixtures registered and finalized: the application every poly-query
/// test proves through.
pub fn poly_query_app<C: Cycle, R: Rank>(params: &C::Params) -> Result<PolyQueryApp<'_, C, R>> {
    ApplicationBuilder::<C, R, HEADER_SIZE, PolyQueryHooks>::new(params)
        .register(CommitAndOpen::<C, R>::new(params))?
        .register(OpenAndHash::<C, R>::new(C::circuit_poseidon(params)))?
        .finalize()
}
