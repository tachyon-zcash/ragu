use ff::Field;
use ragu_circuits::polynomials::R;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};
use ragu_pasta::Pasta;
use ragu_pcd::step::{Encoded, Index, Step};
use ragu_pcd::{
    ApplicationBuilder,
    header::{Header, Suffix},
};

// Header A with suffix 0
struct HSuffixA;
// Header B with suffix 1
struct HSuffixB;
// Different type, same suffix 0 (duplicate)
struct HSuffixAOther;

impl<F: Field> Header<F> for HSuffixA {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data<'source> = ();
    type Output = ();
    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        _: &mut D,
        _: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Ok(())
    }
}

impl<F: Field> Header<F> for HSuffixB {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data<'source> = ();
    type Output = ();
    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        _: &mut D,
        _: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Ok(())
    }
}

impl<F: Field> Header<F> for HSuffixAOther {
    const SUFFIX: Suffix = Suffix::new(0); // duplicate suffix
    type Data<'source> = ();
    type Output = ();
    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        _: &mut D,
        _: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Ok(())
    }
}

// Step 0 -> produces HSuffixA
struct Step0;
impl<C: arithmetic::Cycle> Step<C> for Step0 {
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
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::just(|| ())))
    }
}

// Step 1 -> consumes A and produces B
struct Step1;
impl<C: arithmetic::Cycle> Step<C> for Step1 {
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
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::just(|| ())))
    }
}

// Duplicate suffix step (index 1) producing different header with same suffix
struct Step1Dup;
impl<C: arithmetic::Cycle> Step<C> for Step1Dup {
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
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::just(|| ())))
    }
}

#[test]
fn register_steps_success_and_finalize() {
    let pasta = Pasta::baked();
    let builder = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(Step0)
        .unwrap()
        .register(Step1)
        .unwrap();
    builder.finalize(pasta).unwrap();
}

#[test]
#[should_panic]
fn register_steps_out_of_order_should_fail() {
    ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(Step1)
        .unwrap();
}

#[test]
#[should_panic]
fn register_steps_duplicate_suffix_should_fail() {
    ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(Step0)
        .unwrap()
        .register(Step1Dup)
        .unwrap();
}
