use core::marker::PhantomData;

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{
    ApplicationBuilder,
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
};
use udon::field::Field;

// Header A with suffix 0
struct HSuffixA;
// Header B with suffix 1
struct HSuffixB;
// Different type, same suffix 0 (duplicate)
struct HSuffixAOther;

impl<F: Field> Header<F> for HSuffixA {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = ();
    type Output = ();
    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        _: &mut D,
        _: &mut A,
        _: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }
}

impl<F: Field> Header<F> for HSuffixB {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data = ();
    type Output = ();
    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        _: &mut D,
        _: &mut A,
        _: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }
}

impl<F: Field> Header<F> for HSuffixAOther {
    const SUFFIX: Suffix = Suffix::new(0); // duplicate suffix
    type Data = ();
    type Output = ();
    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        _: &mut D,
        _: &mut A,
        _: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }
}

// Step 0 -> produces HSuffixA
struct Step0;
impl<C: ragu_core::Cycle> Step<C> for Step0 {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = HSuffixA;
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::unit(), D::unit()))
    }
}

// Step 1 -> consumes A and produces B
struct Step1;
impl<C: ragu_core::Cycle> Step<C> for Step1 {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = HSuffixA;
    type Right = HSuffixA;
    type Output = HSuffixB;
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::unit(), D::unit()))
    }
}

// Duplicate suffix step (index 1) producing different header with same suffix
struct Step1Dup;
impl<C: ragu_core::Cycle> Step<C> for Step1Dup {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = HSuffixA;
    type Right = HSuffixA;
    type Output = HSuffixAOther;
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::unit(), D::unit()))
    }
}

#[test]
fn register_steps_success_and_finalize() {
    let pasta = ragu_pcd::pasta::baked();
    let builder = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(Step0)
        .unwrap()
        .register(Step1)
        .unwrap();
    builder.finalize(pasta).unwrap();
}

#[test]
#[should_panic(expected = "steps must be registered in sequential order")]
fn register_steps_out_of_order_should_fail() {
    ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(Step1)
        .unwrap();
}

#[test]
#[should_panic(expected = "two different Header implementations using the same suffix")]
fn register_steps_duplicate_suffix_should_fail() {
    ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(Step0)
        .unwrap()
        .register(Step1Dup)
        .unwrap();
}

// Copies the public unit suffix while carrying data, without using () itself.
struct CopiedUnitSuffix;

impl Header<Fp> for CopiedUnitSuffix {
    const SUFFIX: Suffix = <() as Header<Fp>>::SUFFIX;
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

struct HeaderStep<L, R, O>(PhantomData<(L, R, O)>);

impl<L: Header<Fp>, R: Header<Fp>, O: Header<Fp>> Step<Pasta> for HeaderStep<L, R, O> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = O::Data;
    type Aux<'source> = ();
    type Left = L;
    type Right = R;
    type Output = O;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, L::Data>,
        right: DriverValue<D, R::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, O::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::new(dr, allocator, witness.clone())?;
        Ok(((left, right, output), witness, D::unit()))
    }
}

fn rejects_reserved_suffix<L: Header<Fp>, R: Header<Fp>, O: Header<Fp>>() {
    let result =
        ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
            .register(HeaderStep::<L, R, O>(PhantomData));
    assert!(matches!(
        result,
        Err(Error::Initialization(message))
            if message.to_string() == "only the unit Header () may use a reserved internal suffix"
    ));
}

#[test]
fn register_rejects_copied_unit_suffix_without_unit_header() {
    rejects_reserved_suffix::<CopiedUnitSuffix, CopiedUnitSuffix, CopiedUnitSuffix>();
}

#[test]
fn register_rejects_reserved_suffix_in_each_header_position() {
    rejects_reserved_suffix::<CopiedUnitSuffix, HSuffixA, HSuffixA>();
    rejects_reserved_suffix::<HSuffixA, CopiedUnitSuffix, HSuffixA>();
    rejects_reserved_suffix::<HSuffixA, HSuffixA, CopiedUnitSuffix>();
}

#[test]
fn register_accepts_unit_in_every_header_position() {
    ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(HeaderStep::<(), (), ()>(PhantomData))
        .unwrap();
}
