//! Test fixtures whose headers carry a polynomial: a set accumulator, the
//! polynomial $\prod_i (X - r_i)$ over the set's elements, carried beside a
//! count of them.
//!
//! The steps exercise every way a step uses its online oracles: committing
//! an output polynomial computed from the witness ([`SeedAccumulator`]),
//! from an input polynomial ([`ExtendAccumulator`]) and from two
//! ([`MergeAccumulators`]), each proving the relation at $\zeta$; and
//! opening an input polynomial at a witnessed point to prove membership
//! ([`ProveMember`]) or non-membership ([`ProveNonMember`]).

use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    header::{Header, Suffix},
    step::{Encoded, HeaderInput, Index, Oracles, Slot, Step},
};
use ragu_primitives::{
    Element, GadgetExt,
    allocator::{Allocator, Standard},
};
use udon::field::Field;

/// The accumulator header: the number of accumulated elements as its data,
/// and the accumulator polynomial $\prod_i (X - r_i)$ as its one
/// polynomial.
pub struct Accumulator;

impl<F: Field> Header<F> for Accumulator {
    const SUFFIX: Suffix = Suffix::new(10);
    const NUM_POLYNOMIALS: usize = 1;
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

/// The coefficients of $\prod_i (X - r_i)$, ascending in degree.
pub fn vanishing<F: Field>(roots: &[F]) -> Vec<F> {
    let mut coeffs = vec![F::ONE];
    for root in roots {
        coeffs = multiply_linear(&coeffs, *root);
    }
    coeffs
}

/// The coefficients of `poly * (X - root)`.
pub fn multiply_linear<F: Field>(poly: &[F], root: F) -> Vec<F> {
    let mut out = vec![F::ZERO; poly.len() + 1];
    for (i, coeff) in poly.iter().enumerate() {
        out[i + 1] += *coeff;
        out[i] -= *coeff * root;
    }
    out
}

/// The coefficients of the product of two polynomials.
pub fn multiply<F: Field>(a: &[F], b: &[F]) -> Vec<F> {
    let mut out = vec![F::ZERO; a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            out[i + j] += *x * *y;
        }
    }
    out
}

/// Seeds an accumulator over a witnessed set: the output polynomial is
/// $\prod_i (X - r_i)$ and the circuit checks its value at $\zeta$ against
/// the product over the witnessed roots.
pub struct SeedAccumulator;

impl<C: Cycle> Step<C> for SeedAccumulator {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Vec<C::CircuitField>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Accumulator;

    fn polynomials<'source>(
        &self,
        roots: &Self::Witness<'source>,
        _: HeaderInput<'_, C::CircuitField, ()>,
        _: HeaderInput<'_, C::CircuitField, ()>,
    ) -> Result<Vec<Vec<C::CircuitField>>> {
        Ok(vec![vanishing(roots)])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        roots: DriverValue<D, Self::Witness<'source>>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
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
        // The circuit is fixed by the set's size: this fixture seeds sets of
        // `SEED_SIZE` elements.
        let roots: Vec<Element<'dr, D>> = (0..SEED_SIZE)
            .map(|i| Element::alloc(dr, allocator, roots.as_ref().map(|r| r[i])))
            .collect::<Result<_>>()?;
        let zeta = oracles.zeta().clone();
        let mut product = Element::one();
        for root in &roots {
            let factor = zeta.sub(dr, root);
            product = product.mul(dr, &factor)?;
        }
        let at_zeta = oracles.query_at_zeta(dr, Slot::output(0))?;
        at_zeta.enforce_equal(dr, &product)?;

        let count = Element::constant(dr, C::CircuitField::from(SEED_SIZE as u64));
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(count),
            ),
            D::just(|| C::CircuitField::from(SEED_SIZE as u64)),
            D::unit(),
        ))
    }
}

/// The number of roots [`SeedAccumulator`] takes.
pub const SEED_SIZE: usize = 3;

/// Adds one witnessed element to an accumulator: the output polynomial is
/// the input's times $(X - t)$, and the circuit checks
/// $O(\zeta) = L(\zeta)(\zeta - t)$.
pub struct ExtendAccumulator;

impl<C: Cycle> Step<C> for ExtendAccumulator {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = C::CircuitField;
    type Aux<'source> = ();
    type Left = Accumulator;
    type Right = ();
    type Output = Accumulator;

    fn polynomials<'source>(
        &self,
        root: &Self::Witness<'source>,
        left: HeaderInput<'_, C::CircuitField, Accumulator>,
        _: HeaderInput<'_, C::CircuitField, ()>,
    ) -> Result<Vec<Vec<C::CircuitField>>> {
        Ok(vec![multiply_linear(&left.polynomials[0], *root)])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        root: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, C::CircuitField>,
        right: DriverValue<D, ()>,
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
        let left: Encoded<'dr, D, Accumulator, HEADER_SIZE> = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let root = Element::alloc(dr, allocator, root)?;

        let zeta = oracles.zeta().clone();
        let input = oracles.query_at_zeta(dr, Slot::left(0))?;
        let output = oracles.query_at_zeta(dr, Slot::output(0))?;
        let factor = zeta.sub(dr, &root);
        let expected = input.mul(dr, &factor)?;
        output.enforce_equal(dr, &expected)?;

        let count = left.as_gadget().add(dr, &Element::one());
        let data = count.value().map(|v| *v);
        Ok(((left, right, Encoded::from_gadget(count)), data, D::unit()))
    }
}

/// Merges two accumulators: the output polynomial is the inputs' product,
/// and the circuit checks $O(\zeta) = L(\zeta) R(\zeta)$.
pub struct MergeAccumulators;

impl<C: Cycle> Step<C> for MergeAccumulators {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Accumulator;
    type Right = Accumulator;
    type Output = Accumulator;

    fn polynomials<'source>(
        &self,
        _: &Self::Witness<'source>,
        left: HeaderInput<'_, C::CircuitField, Accumulator>,
        right: HeaderInput<'_, C::CircuitField, Accumulator>,
    ) -> Result<Vec<Vec<C::CircuitField>>> {
        Ok(vec![multiply(&left.polynomials[0], &right.polynomials[0])])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, C::CircuitField>,
        right: DriverValue<D, C::CircuitField>,
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
        let left: Encoded<'dr, D, Accumulator, HEADER_SIZE> = Encoded::new(dr, allocator, left)?;
        let right: Encoded<'dr, D, Accumulator, HEADER_SIZE> = Encoded::new(dr, allocator, right)?;

        let l = oracles.query_at_zeta(dr, Slot::left(0))?;
        let r = oracles.query_at_zeta(dr, Slot::right(0))?;
        let output = oracles.query_at_zeta(dr, Slot::output(0))?;
        let expected = l.mul(dr, &r)?;
        output.enforce_equal(dr, &expected)?;

        let count = left.as_gadget().add(dr, right.as_gadget());
        let data = count.value().map(|v| *v);
        Ok(((left, right, Encoded::from_gadget(count)), data, D::unit()))
    }
}

/// Proves a witnessed element is in the left accumulator: its polynomial,
/// opened at the element, is zero. Outputs the unit header.
pub struct ProveMember;

impl<C: Cycle> Step<C> for ProveMember {
    const INDEX: Index = Index::new(3);
    type Witness<'source> = C::CircuitField;
    type Aux<'source> = ();
    type Left = Accumulator;
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        member: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, C::CircuitField>,
        right: DriverValue<D, ()>,
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
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let member = Element::alloc(dr, allocator, member)?;
        oracles
            .query(dr, Slot::left(0), &member)?
            .enforce_zero(dr)?;
        Ok((
            (left, right, Encoded::from_gadget(())),
            D::unit(),
            D::unit(),
        ))
    }
}

/// Proves a witnessed element is not in the left accumulator: its
/// polynomial, opened at the element, is nonzero. Outputs the unit header.
pub struct ProveNonMember;

impl<C: Cycle> Step<C> for ProveNonMember {
    const INDEX: Index = Index::new(4);
    type Witness<'source> = C::CircuitField;
    type Aux<'source> = ();
    type Left = Accumulator;
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        element: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, C::CircuitField>,
        right: DriverValue<D, ()>,
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
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let element = Element::alloc(dr, allocator, element)?;
        oracles
            .query(dr, Slot::left(0), &element)?
            .enforce_nonzero(dr)?;
        Ok((
            (left, right, Encoded::from_gadget(())),
            D::unit(),
            D::unit(),
        ))
    }
}
