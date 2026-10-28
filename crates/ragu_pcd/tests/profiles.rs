//! Two profiles in one binary: a standard-profile application over `Pasta`
//! at the production rank and an aggregator-profile application over the
//! same curves at the aggregator rank. The standard application proves,
//! verifies and compresses its proofs; the aggregator's registries build
//! with the decompression circuits, and its bootstrap waits on their
//! prover. The cycles are distinct types, so neither application accepts
//! the other's proofs.

use ragu_circuits::polynomials::{AggregatorRank, ProductionRank, Rank};
use ragu_core::{
    Cycle, Error, Result,
    pasta::{Fp, Pasta, PastaParams},
};
use ragu_pcd::{
    Application, ApplicationBuilder,
    ipa::IpaCycle,
    profile::{Aggregator, Profiled, ProfiledCycle, Shape, Standard},
};
use ragu_testing::pcd::nontrivial::{Hash2, WitnessLeaf};
use rand::{SeedableRng, rngs::StdRng};

const HEADER_SIZE: usize = 4;

/// The wallet application: the standard profile at the production rank.
fn wallet() -> Result<Application<'static, Pasta, ProductionRank, HEADER_SIZE>> {
    let pasta = ragu_pcd::pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(WitnessLeaf { poseidon_params })?
        .register(Hash2 { poseidon_params })?
        .finalize(pasta)
}

fn prove_verify_compress<C, R>(app: &Application<'_, C, R, HEADER_SIZE>, seed: u64) -> Result<()>
where
    C: Cycle<Params = PastaParams, CircuitField = Fp> + ProfiledCycle + IpaCycle,
    R: Rank,
{
    let mut rng = StdRng::seed_from_u64(seed);
    let poseidon_params = C::circuit_poseidon(ragu_pcd::pasta::baked());
    let (leaf, _) = app.seed(&mut rng, WitnessLeaf { poseidon_params }, Fp::from(42))?;
    let (node, _) = app.fuse(&mut rng, Hash2 { poseidon_params }, (), leaf.clone(), leaf)?;
    assert!(app.verify_uncompressed(&node, &mut rng)?);
    let compressed = app.compress(&node, &mut rng)?;
    assert!(app.verify_compressed(&compressed)?);
    Ok(())
}

#[test]
fn both_profiles_build_in_one_binary() -> Result<()> {
    prove_verify_compress(&wallet()?, 1)?;

    // The aggregator's shape is its own, and its registries build at the
    // aggregator rank: the fuse fits the budget with the decompression
    // circuits registered. Finalizing proves the bootstrap, which stops at
    // the extension's prover, the next step.
    type Agg = Profiled<Pasta, Aggregator<HEADER_SIZE>>;
    assert_ne!(
        Shape::of::<Aggregator<HEADER_SIZE>>(),
        Shape::of::<Standard>()
    );
    let pasta = ragu_pcd::pasta::baked_aggregator();
    let poseidon_params = Agg::circuit_poseidon(pasta);
    let result = ApplicationBuilder::<Agg, AggregatorRank, HEADER_SIZE>::new()
        .register(WitnessLeaf { poseidon_params })?
        .register(Hash2 { poseidon_params })?
        .finalize(pasta);
    assert!(matches!(result, Err(Error::Initialization(_))));
    Ok(())
}
