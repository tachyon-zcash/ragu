use ff::Field;
use ragu_circuits::polynomials::R;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};
use ragu_pasta::Pasta;
use ragu_pcd::step::{Encoded, Encoder, Index, Step};
use ragu_pcd::{
    ApplicationBuilder,
    header::{Header, Prefix},
};
use rand::{SeedableRng, rngs::StdRng};

// Header A with prefix 0
struct HPrefixA;
// Header B with prefix 1
struct HPrefixB;
// Different type, same prefix 0 (duplicate)
struct HPrefixAOther;

impl<F: Field> Header<F> for HPrefixA {
    const PREFIX: Prefix = Prefix::new(0);
    type Data<'source> = ();
    type Output = ();
    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        _: &mut D,
        _: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Ok(())
    }
}

impl<F: Field> Header<F> for HPrefixB {
    const PREFIX: Prefix = Prefix::new(1);
    type Data<'source> = ();
    type Output = ();
    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        _: &mut D,
        _: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Ok(())
    }
}

impl<F: Field> Header<F> for HPrefixAOther {
    const PREFIX: Prefix = Prefix::new(0); // duplicate prefix
    type Data<'source> = ();
    type Output = ();
    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        _: &mut D,
        _: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Ok(())
    }
}

// Step 0 -> produces HPrefixA
struct Step0;
impl<C: arithmetic::Cycle> Step<C> for Step0 {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = HPrefixA;
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let left = left.encode(dr)?;
        let right = right.encode(dr)?;
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
    type Left = HPrefixA;
    type Right = HPrefixA;
    type Output = HPrefixB;
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let left = left.encode(dr)?;
        let right = right.encode(dr)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::just(|| ())))
    }
}

// Duplicate prefix step (index 1) producing different header with same prefix
struct Step1Dup;
impl<C: arithmetic::Cycle> Step<C> for Step1Dup {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = HPrefixA;
    type Right = HPrefixA;
    type Output = HPrefixAOther;
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let left = left.encode(dr)?;
        let right = right.encode(dr)?;
        let output = Encoded::from_gadget(());

        Ok(((left, right, output), D::just(|| ())))
    }
}

#[test]
fn register_steps_success_and_finalize() {
    let pasta = Pasta::baked();
    let builder = ApplicationBuilder::<Pasta, R<8>, 4>::new()
        .register(Step0)
        .unwrap()
        .register(Step1)
        .unwrap();
    builder.finalize(pasta).unwrap();
}

#[test]
#[should_panic]
fn register_steps_out_of_order_should_fail() {
    ApplicationBuilder::<Pasta, R<8>, 4>::new()
        .register(Step1)
        .unwrap();
}

#[test]
#[should_panic]
fn register_steps_duplicate_prefix_should_fail() {
    ApplicationBuilder::<Pasta, R<8>, 4>::new()
        .register(Step0)
        .unwrap()
        .register(Step1Dup)
        .unwrap();
}

#[test]
fn test_decide_random_proof() -> Result<()> {
    let pasta = Pasta::default();

    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(Step0)
        .unwrap()
        .register(Step1)
        .unwrap()
        .finalize(&pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(1234);

    let trivial = app.trivial().carry::<()>(());
    assert!(app.verify(&trivial, &mut rng).unwrap());

    let rerandom = app.rerandomize(trivial.clone(), &mut rng).unwrap();
    assert!(app.verify(&rerandom, &mut rng).unwrap());

    let is_valid = app.verify(&rerandom, &mut rng)?;

    assert!(is_valid, "Random proof should verify");

    Ok(())
}

#[test]
fn test_merge_random_proof() -> Result<()> {
    let pasta = Pasta::default();

    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(Step0)
        .unwrap()
        .register(Step1)
        .unwrap()
        .finalize(&pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(1234);

    let trivial = app.trivial().carry::<()>(());
    assert!(app.verify(&trivial, &mut rng).unwrap());

    let trivial_2 = app.trivial().carry::<()>(());
    assert!(app.verify(&trivial, &mut rng).unwrap());

    let left_pcd = app.rerandomize(trivial.clone(), &mut rng).unwrap();
    assert!(app.verify(&left_pcd, &mut rng).unwrap());

    let right_pcd = app.rerandomize(trivial_2.clone(), &mut rng).unwrap();
    assert!(app.verify(&right_pcd, &mut rng).unwrap());

    let merged_proof = app.merge(&mut rng, Step0, (), left_pcd, right_pcd)?;
    let pcd = merged_proof.0.carry::<HPrefixA>(());

    let is_valid = app.verify(&pcd, &mut rng)?;

    assert!(is_valid, "Merged proof should verify");

    Ok(())
}
