//! The receiver's registry tags must survive proving, recursion and compression.
//! Change one tag at a time, keeping the profile, circuits and parameters fixed.
//! The test seam installs a tag the derivation would not give these circuits,
//! standing in for another setup; the public API derives both tags from the
//! registered circuits and cannot make such a pair.

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Result,
    pasta::{Pasta, PastaParams},
};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use crate::{
    Application, ApplicationBuilder, Pcd,
    ipa::IpaCycle,
    profile::{Aggregator, Profile, Profiled, ProfiledCycle, testing::UnitStep},
};

const HEADER_SIZE: usize = 4;
type App<C> = Application<'static, C, ProductionRank, HEADER_SIZE>;
type TestPcd<C> = Pcd<C, ProductionRank, ()>;

#[derive(Clone, Copy, Debug)]
enum ChangedTag {
    Native,
    Nested,
}

fn application<C>(changed: Option<ChangedTag>) -> Result<App<C>>
where
    C: IpaCycle + ProfiledCycle<Base = Pasta, Params = PastaParams>,
    <C::Profile as Profile>::Context<'static, Pasta, ProductionRank, ReferenceBackend>: Default,
{
    let builder = ApplicationBuilder::<C, ProductionRank, HEADER_SIZE>::new().register(UnitStep)?;
    match changed {
        Some(ChangedTag::Native) => {
            builder.with_native_tag(C::CircuitField::from_uniform_bytes(&[0x43; 64]))
        }
        Some(ChangedTag::Nested) => {
            builder.with_nested_tag(C::ScalarField::from_uniform_bytes(&[0x43; 64]))
        }
        None => builder,
    }
    .finalize(crate::pasta::baked())
}

fn check_both_verifiers<C>(
    app: &App<C>,
    pcd: &TestPcd<C>,
    accepted: bool,
    rng: &mut StdRng,
) -> Result<()>
where
    C: IpaCycle + ProfiledCycle,
{
    assert_eq!(
        app.verify_uncompressed(pcd, &mut *rng)?,
        accepted,
        "ordinary verifier"
    );
    // Compression does not validate the input proof. In particular, invoking
    // the receiving setup's compressor must not repair a foreign setup's proof.
    let compressed = app.compress(pcd, rng)?;
    assert_eq!(
        app.verify_compressed(&compressed)?,
        accepted,
        "compressed verifier"
    );
    Ok(())
}

fn check_setup_binding<C>(changed: ChangedTag) -> Result<()>
where
    C: IpaCycle + ProfiledCycle<Base = Pasta, Params = PastaParams>,
    <C::Profile as Profile>::Context<'static, Pasta, ProductionRank, ReferenceBackend>: Default,
{
    let sender = application::<C>(None)?;
    let receiver = application::<C>(Some(changed))?;
    assert_eq!(
        sender.native_registry.tag() == receiver.native_registry.tag(),
        matches!(changed, ChangedTag::Nested),
    );
    assert_eq!(
        sender.nested_registry.tag() == receiver.nested_registry.tag(),
        matches!(changed, ChangedTag::Native),
    );

    let mut rng = StdRng::seed_from_u64(1234);
    let (foreign, ()) = sender.seed(&mut rng, UnitStep, ())?;
    let (local, ()) = receiver.seed(&mut rng, UnitStep, ())?;
    check_both_verifiers(&sender, &foreign, true, &mut rng)?;
    check_both_verifiers(&receiver, &local, true, &mut rng)?;

    // A proof compressed under its own setup must reject under the other one,
    // even though the public data, Rust proof type and wire shape all agree.
    let compressed = sender.compress(&foreign, &mut rng)?;
    assert!(!receiver.verify_compressed(&compressed)?);
    check_both_verifiers(&receiver, &foreign, false, &mut rng)?;

    let refreshed = receiver.rerandomize(local.clone(), &mut rng)?;
    check_both_verifiers(&receiver, &refreshed, true, &mut rng)?;
    let refreshed = receiver.rerandomize(foreign.clone(), &mut rng)?;
    check_both_verifiers(&receiver, &refreshed, false, &mut rng)?;

    let (parent, ()) = receiver.fuse(&mut rng, UnitStep, (), local.clone(), local.clone())?;
    check_both_verifiers(&receiver, &parent, true, &mut rng)?;
    let (grandparent, ()) = receiver.fuse(&mut rng, UnitStep, (), parent, local.clone())?;
    check_both_verifiers(&receiver, &grandparent, true, &mut rng)?;

    // The parent uses only the receiver's registries. Neither child position
    // may bring another setup into an accepted parent or grandparent.
    for (left, right) in [(foreign.clone(), local.clone()), (local.clone(), foreign)] {
        let (parent, ()) = receiver.fuse(&mut rng, UnitStep, (), left, right)?;
        check_both_verifiers(&receiver, &parent, false, &mut rng)?;
        let (grandparent, ()) = receiver.fuse(&mut rng, UnitStep, (), parent, local.clone())?;
        check_both_verifiers(&receiver, &grandparent, false, &mut rng)?;
    }
    Ok(())
}

#[test]
fn standard_native_setup_binding() -> Result<()> {
    check_setup_binding::<Pasta>(ChangedTag::Native)
}

#[test]
fn standard_nested_setup_binding() -> Result<()> {
    check_setup_binding::<Pasta>(ChangedTag::Nested)
}

#[test]
fn aggregator_native_setup_binding() -> Result<()> {
    check_setup_binding::<Profiled<Pasta, Aggregator>>(ChangedTag::Native)
}

#[test]
fn aggregator_nested_setup_binding() -> Result<()> {
    check_setup_binding::<Profiled<Pasta, Aggregator>>(ChangedTag::Nested)
}
