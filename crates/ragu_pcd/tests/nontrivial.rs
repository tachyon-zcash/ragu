use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{ApplicationBuilder, PcdConfig};
use ragu_primitives::vec::ConstLen;

struct TestCfg;
impl PcdConfig for TestCfg { type HeaderSize = ConstLen<4>; }
use ragu_testing::pcd::nontrivial::{Hash2, WitnessLeaf};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn various_merging_operations() -> Result<()> {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, ProductionRank, TestCfg>::new()
        .register(WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(Hash2 {
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
    assert!(app.verify(&leaf1, &mut rng)?);

    let (leaf2, _) = app.seed(
        &mut rng,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        Fp::from(42u64),
    )?;
    assert!(app.verify(&leaf2, &mut rng)?);

    let (node1, _) = app.fuse(
        &mut rng,
        Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        },
        (),
        leaf1,
        leaf2,
    )?;
    assert!(app.verify(&node1, &mut rng)?);

    Ok(())
}
