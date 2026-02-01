use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::polynomials::R;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{
    ApplicationBuilder,
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};
use ragu_primitives::Element;
use rand::SeedableRng;
use rand::rngs::StdRng;

// Header A (suffix 0) - unit data
struct HeaderA;

impl<F: Field> Header<F> for HeaderA {
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

// Header with real data (suffix 2) - carries a field element
struct HeaderWithData;

impl Header<Fp> for HeaderWithData {
    const SUFFIX: Suffix = Suffix::new(2);
    type Data<'source> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)
    }
}

// Step that produces HeaderWithData from trivial inputs
struct StepWithData;
impl Step<Pasta> for StepWithData {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = Fp;
    type Left = ();
    type Right = ();
    type Output = HeaderWithData;
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
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
        let output = Encoded::new(dr, witness.clone())?;
        Ok(((left, right, output), witness))
    }
}

// Step0: () , ()  -> HeaderA
struct Step0;
impl<C: Cycle> Step<C> for Step0 {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = HeaderA;
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

struct Step1;
impl<C: Cycle> Step<C> for Step1 {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = HeaderA;
    type Right = HeaderA;
    type Output = HeaderA;
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
fn rerandomization_flow() {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(Step0)
        .unwrap()
        .register(Step1)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(1234);

    let seeded = app.seed(&mut rng, Step0, ()).unwrap().0;
    let seeded = seeded.carry::<HeaderA>(());
    assert!(app.verify(&seeded, &mut rng).unwrap());

    // Rerandomize
    let seeded = app.rerandomize(seeded, &mut rng).unwrap();
    assert!(app.verify(&seeded, &mut rng).unwrap());

    let fused = app
        .fuse(&mut rng, Step1, (), seeded.clone(), seeded)
        .unwrap()
        .0;
    let fused = fused.carry::<HeaderA>(());
    assert!(app.verify(&fused, &mut rng).unwrap());

    let fused = app.rerandomize(fused, &mut rng).unwrap();
    assert!(app.verify(&fused, &mut rng).unwrap());
}

#[test]
fn multiple_rerandomizations_all_verify() {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(Step0)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(9999);

    let original = app.seed(&mut rng, Step0, ()).unwrap().0;
    let original = original.carry::<HeaderA>(());
    assert!(app.verify(&original, &mut rng).unwrap());

    // Rerandomize multiple times - each should verify
    let rerand1 = app.rerandomize(original.clone(), &mut rng).unwrap();
    assert!(app.verify(&rerand1, &mut rng).unwrap());

    let rerand2 = app.rerandomize(original.clone(), &mut rng).unwrap();
    assert!(app.verify(&rerand2, &mut rng).unwrap());

    // Rerandomize an already rerandomized proof
    let rerand3 = app.rerandomize(rerand1, &mut rng).unwrap();
    assert!(app.verify(&rerand3, &mut rng).unwrap());
}

#[test]
fn rerandomization_preserves_header_data() {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(StepWithData)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(4321);

    // Use a non-trivial data value
    let test_data = Fp::from(123456789u64);

    let original = app.seed(&mut rng, StepWithData, test_data).unwrap().0;
    let original = original.carry::<HeaderWithData>(test_data);
    assert!(app.verify(&original, &mut rng).unwrap());

    let rerandomized = app.rerandomize(original.clone(), &mut rng).unwrap();
    assert!(app.verify(&rerandomized, &mut rng).unwrap());

    // Header data should be preserved (non-unit comparison)
    assert_eq!(
        original.data, rerandomized.data,
        "rerandomization should preserve header data"
    );
    assert_eq!(
        rerandomized.data,
        Fp::from(123456789u64),
        "header data should match original value"
    );
}

#[test]
fn rerandomized_fused_proof_verifies() {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(Step0)
        .unwrap()
        .register(Step1)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(7777);

    // Create two seeded proofs
    let left = app
        .seed(&mut rng, Step0, ())
        .unwrap()
        .0
        .carry::<HeaderA>(());
    let right = app
        .seed(&mut rng, Step0, ())
        .unwrap()
        .0
        .carry::<HeaderA>(());

    // Fuse them
    let fused = app.fuse(&mut rng, Step1, (), left, right).unwrap().0;
    let fused = fused.carry::<HeaderA>(());
    assert!(app.verify(&fused, &mut rng).unwrap());

    // Rerandomize the fused proof
    let rerandomized = app.rerandomize(fused, &mut rng).unwrap();
    assert!(
        app.verify(&rerandomized, &mut rng).unwrap(),
        "rerandomized fused proof should verify"
    );
}
