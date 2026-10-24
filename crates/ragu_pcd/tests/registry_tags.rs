use ragu_circuits::{polynomials::ProductionRank, registry::Tag};
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{Application, ApplicationBuilder, RegistryTags};
use ragu_testing::pcd::nontrivial::{Hash2, WitnessLeaf};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

fn application(
    tags: RegistryTags<Pasta>,
) -> Result<Application<'static, Pasta, ProductionRank, 4>> {
    let pasta = ragu_pcd::pasta::baked();
    ApplicationBuilder::<Pasta, ProductionRank, 4>::new(pasta)
        .register(WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .with_registry_tags(tags)
        .finalize()
}

#[test]
fn beacon_tags_support_recursive_proofs() -> Result<()> {
    let tags = || RegistryTags::<Pasta>::from_beacon(&[0x42; 32], &[0x24; 20]);
    let app = application(tags())?;
    let mut rng = StdRng::seed_from_u64(1234);
    let poseidon_params = Pasta::circuit_poseidon(ragu_pcd::pasta::baked());
    let (leaf, _) = app.seed(&mut rng, WitnessLeaf { poseidon_params }, Fp::from(42))?;
    let (node, _) = app.fuse(&mut rng, Hash2 { poseidon_params }, (), leaf.clone(), leaf)?;
    let proof = app.rerandomize(node, &mut rng)?;
    assert!(app.verify(&proof, &mut rng)?);

    // An independently initialized verifier agrees on the same beacon tags.
    assert!(application(tags())?.verify(&proof, &mut rng)?);

    // A different native tag must reject this proof.
    let mut wrong_native = tags();
    wrong_native.native = Tag::new(wrong_native.native.value() + Fp::ONE);
    assert!(!application(wrong_native)?.verify(&proof, &mut rng)?);
    Ok(())
}
