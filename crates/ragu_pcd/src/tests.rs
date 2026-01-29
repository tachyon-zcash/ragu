//! Unit tests for ragu_pcd.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::polynomials::R;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};
use ragu_pasta::{Fp, Pasta};
use rand::{SeedableRng, rngs::StdRng};

use crate::step::{Encoded, Index, Step};
use crate::{
    ApplicationBuilder,
    header::{Header, Suffix},
};

// ============================================================================
// Test fixtures for registration_errors tests
// ============================================================================

struct HSuffixA;
struct HSuffixB;
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

struct RegStep0;
impl<C: Cycle> Step<C> for RegStep0 {
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

struct RegStep1;
impl<C: Cycle> Step<C> for RegStep1 {
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

struct RegStep1Dup;
impl<C: Cycle> Step<C> for RegStep1Dup {
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

// ============================================================================
// Registration error tests
// ============================================================================

#[test]
fn register_steps_success_and_finalize() {
    let pasta = Pasta::baked();
    let builder = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(RegStep0)
        .unwrap()
        .register(RegStep1)
        .unwrap();
    builder.finalize(pasta).unwrap();
}

#[test]
#[should_panic]
fn register_steps_out_of_order_should_fail() {
    ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(RegStep1)
        .unwrap();
}

#[test]
#[should_panic]
fn register_steps_duplicate_suffix_should_fail() {
    ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(RegStep0)
        .unwrap()
        .register(RegStep1Dup)
        .unwrap();
}

// ============================================================================
// Rerandomization tests
// ============================================================================

#[test]
fn rerandomization_flow() {
    use crate::test_fixtures::trivial;

    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(trivial::Step0)
        .unwrap()
        .register(trivial::Step1)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(1234);

    let seeded = app.seed(&mut rng, trivial::Step0, ()).unwrap().0;
    let seeded = seeded.carry::<trivial::HeaderA>(());
    assert!(app.verify(&seeded, &mut rng).unwrap());

    let seeded = app.rerandomize(seeded, &mut rng).unwrap();
    assert!(app.verify(&seeded, &mut rng).unwrap());

    let fused = app
        .fuse(&mut rng, trivial::Step1, (), seeded.clone(), seeded)
        .unwrap()
        .0;
    let fused = fused.carry::<trivial::HeaderA>(());
    assert!(app.verify(&fused, &mut rng).unwrap());

    let fused = app.rerandomize(fused, &mut rng).unwrap();
    assert!(app.verify(&fused, &mut rng).unwrap());
}

// ============================================================================
// Nontrivial tests
// ============================================================================

#[test]
fn various_merging_operations() -> Result<()> {
    use crate::test_fixtures::nontrivial;

    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(nontrivial::WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(nontrivial::Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .finalize(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);

    let leaf1 = app.seed(
        &mut rng,
        nontrivial::WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    let leaf1 = leaf1.0.carry(leaf1.1);
    assert!(app.verify(&leaf1, &mut rng)?);

    let leaf2 = app.seed(
        &mut rng,
        nontrivial::WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    let leaf2 = leaf2.0.carry(leaf2.1);
    assert!(app.verify(&leaf2, &mut rng)?);

    let node1 = app.fuse(
        &mut rng,
        nontrivial::Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        leaf1,
        leaf2,
    )?;
    let node1 = node1.0.carry::<nontrivial::InternalNode>(node1.1);

    assert!(app.verify(&node1, &mut rng)?);

    Ok(())
}
