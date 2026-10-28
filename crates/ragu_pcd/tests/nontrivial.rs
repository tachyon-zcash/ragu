use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Pasta},
};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::nontrivial::{Hash2, Merge2, WitnessLeaf};
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn various_merging_operations() -> Result<()> {
    let pasta = ragu_pcd::pasta::baked_aggregator();
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .register(WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(Merge2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .finalize(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);

    let (leaf1, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    assert!(app.verify_uncompressed(&leaf1, &mut rng)?);

    let (leaf2, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    assert!(app.verify_uncompressed(&leaf2, &mut rng)?);

    let (node1, _) = app.fuse(
        &mut rng,
        Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        leaf1,
        leaf2,
    )?;
    assert!(app.verify_uncompressed(&node1, &mut rng)?);

    // Consume the first fold in another generation before compressing it.
    let (node2, _) = app.fuse(
        &mut rng,
        Merge2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        node1.clone(),
        node1,
    )?;
    assert!(app.verify_uncompressed(&node2, &mut rng)?);
    let compressed = app.compress(&node2, &mut rng)?;
    assert!(app.verify_compressed(&compressed)?);

    Ok(())
}
