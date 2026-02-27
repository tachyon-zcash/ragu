use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::nontrivial::{Hash2, InternalNode, WitnessLeaf};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn various_merging_operations() -> Result<()> {
    let pasta = Pasta::baked();
    let mut builder = ApplicationBuilder::<Pasta, ProductionRank, 4>::new();
    let witness_leaf_handle = builder.register(WitnessLeaf {
        poseidon_params: Pasta::circuit_poseidon(pasta),
    })?;
    let hash2_handle = builder.register(Hash2 {
        poseidon_params: Pasta::circuit_poseidon(pasta),
    })?;
    let app = builder.finalize(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);

    let leaf1 = app.seed(
        &mut rng,
        &witness_leaf_handle,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    let leaf1 = leaf1.0.carry(leaf1.1);
    assert!(app.verify(&leaf1, &mut rng)?);

    let leaf2 = app.seed(
        &mut rng,
        &witness_leaf_handle,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    let leaf2 = leaf2.0.carry(leaf2.1);
    assert!(app.verify(&leaf2, &mut rng)?);

    let node1 = app.fuse(
        &mut rng,
        &hash2_handle,
        Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        leaf1,
        leaf2,
    )?;
    let node1 = node1.0.carry::<InternalNode>(node1.1);

    assert!(app.verify(&node1, &mut rng)?);

    Ok(())
}
