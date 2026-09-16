//! Small nontrivial-header fixtures for unit tests that need private proof
//! access. The ragu_testing steps implement the separately compiled public
//! crate's traits, so they cannot be used by this crate's unit-test build.

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Pasta};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
};

use crate::{
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};

pub struct Number;

impl Header<Fp> for Number {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

pub struct Leaf;

impl Step<Pasta> for Leaf {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Number;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, (), HEADER_SIZE>,
            Encoded<'dr, D, Number, HEADER_SIZE>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let output = Encoded::new(dr, &mut Standard::new(), witness.as_ref().map(|v| *v))?;
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            witness,
            D::unit(),
        ))
    }
}

pub struct Add;

impl Step<Pasta> for Add {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Number;
    type Right = Number;
    type Output = Number;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Number, HEADER_SIZE>,
            Encoded<'dr, D, Number, HEADER_SIZE>,
            Encoded<'dr, D, Number, HEADER_SIZE>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::<_, Number, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::<_, Number, HEADER_SIZE>::new(dr, allocator, right)?;
        let sum = left.as_gadget().add(dr, right.as_gadget());
        let data = sum.value().map(|v| *v);
        Ok(((left, right, Encoded::from_gadget(sum)), data, D::unit()))
    }
}

/// An ordered relation whose public output distinguishes the two child roles.
#[cfg(feature = "unstable-fuzzing")]
pub struct OrderedAdd;

#[cfg(feature = "unstable-fuzzing")]
impl Step<Pasta> for OrderedAdd {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Number;
    type Right = Number;
    type Output = Number;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Number, HEADER_SIZE>,
            Encoded<'dr, D, Number, HEADER_SIZE>,
            Encoded<'dr, D, Number, HEADER_SIZE>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::<_, Number, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::<_, Number, HEADER_SIZE>::new(dr, allocator, right)?;
        let twice_right = right.as_gadget().add(dr, right.as_gadget());
        let ordered_sum = left.as_gadget().add(dr, &twice_right);
        let data = ordered_sum.value().map(|v| *v);
        Ok((
            (left, right, Encoded::from_gadget(ordered_sum)),
            data,
            D::unit(),
        ))
    }
}

/// Symmetric addition at the same application index as [`OrderedAdd`].
///
/// Separate applications can register these two steps under the same proof
/// metadata while assigning that metadata different public semantics.
#[cfg(feature = "unstable-fuzzing")]
pub struct AddAtTwo;

#[cfg(feature = "unstable-fuzzing")]
impl Step<Pasta> for AddAtTwo {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Number;
    type Right = Number;
    type Output = Number;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Number, HEADER_SIZE>,
            Encoded<'dr, D, Number, HEADER_SIZE>,
            Encoded<'dr, D, Number, HEADER_SIZE>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::<_, Number, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::<_, Number, HEADER_SIZE>::new(dr, allocator, right)?;
        let sum = left.as_gadget().add(dr, right.as_gadget());
        let data = sum.value().map(|v| *v);
        Ok(((left, right, Encoded::from_gadget(sum)), data, D::unit()))
    }
}

/// Two different private witnesses, r and -r, give the same public output.
#[cfg(feature = "unstable-fuzzing")]
pub struct AddSquare;

#[cfg(feature = "unstable-fuzzing")]
impl Step<Pasta> for AddSquare {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = Number;
    type Right = Number;
    type Output = Number;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Number, HEADER_SIZE>,
            Encoded<'dr, D, Number, HEADER_SIZE>,
            Encoded<'dr, D, Number, HEADER_SIZE>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::<_, Number, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::<_, Number, HEADER_SIZE>::new(dr, allocator, right)?;
        let root = Element::alloc(dr, allocator, witness)?;
        let square = root.square(dr)?;
        let sum = left.as_gadget().add(dr, right.as_gadget()).add(dr, &square);
        let data = sum.value().map(|v| *v);
        Ok(((left, right, Encoded::from_gadget(sum)), data, D::unit()))
    }
}
