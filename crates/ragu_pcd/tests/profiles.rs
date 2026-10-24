//! Two profiles in one binary: a standard-profile application over `Pasta`
//! and an aggregator-profile application over the same curves, each proving,
//! verifying and compressing its own proofs. The cycles are distinct types,
//! so neither application accepts the other's proofs.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Pasta, PastaParams},
};
use ragu_pcd::{
    Application, ApplicationBuilder,
    ipa::IpaCycle,
    profile::{Aggregator, Profiled, ProfiledCycle, Shape, Standard},
};
use ragu_testing::pcd::nontrivial::{Hash2, WitnessLeaf};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

/// The standard-profile application over `Pasta`.
fn wallet() -> Result<Application<'static, Pasta, R, HEADER_SIZE>> {
    let pasta = ragu_pcd::pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register(WitnessLeaf { poseidon_params })?
        .register(Hash2 { poseidon_params })?
        .finalize(pasta)
}

/// The aggregator cycle over the Pasta curves.
type Agg = Profiled<Pasta, Aggregator>;

/// The aggregator-profile application over the same curves.
fn aggregator() -> Result<Application<'static, Agg, R, HEADER_SIZE>> {
    let pasta = ragu_pcd::pasta::baked();
    let poseidon_params = Agg::circuit_poseidon(pasta);
    ApplicationBuilder::<Agg, R, HEADER_SIZE>::new()
        .register(WitnessLeaf { poseidon_params })?
        .register(Hash2 { poseidon_params })?
        .finalize(pasta)
}

fn prove_verify_compress<C>(app: &Application<'_, C, R, HEADER_SIZE>, seed: u64) -> Result<()>
where
    C: Cycle<Params = PastaParams, CircuitField = Fp> + ProfiledCycle + IpaCycle,
{
    let mut rng = StdRng::seed_from_u64(seed);
    let poseidon_params = C::circuit_poseidon(ragu_pcd::pasta::baked());
    let (leaf, _) = app.seed(&mut rng, WitnessLeaf { poseidon_params }, Fp::from(42))?;
    let (node, _) = app.fuse(&mut rng, Hash2 { poseidon_params }, (), leaf.clone(), leaf)?;
    assert!(app.verify(&node, &mut rng)?);
    let compressed = app.compress(&node, &mut rng)?;
    assert!(app.verify_compressed(&compressed)?);
    Ok(())
}

#[test]
fn both_profiles_prove_in_one_binary() -> Result<()> {
    // Until the aggregator's circuits land, its shape is the standard one.
    assert_eq!(Shape::of::<Aggregator>(), Shape::of::<Standard>());
    prove_verify_compress(&wallet()?, 1)?;
    prove_verify_compress(&aggregator()?, 2)
}
