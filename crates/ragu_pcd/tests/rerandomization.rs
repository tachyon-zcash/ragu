use ragu_circuits::polynomials::R;
use ragu_pasta::Pasta;
use ragu_pcd::{ApplicationBuilder, test_fixtures::trivial};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn rerandomization_flow() {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(trivial::NoopLeafStep)
        .unwrap()
        .register(trivial::NoopMergeStep)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(1234);

    let seeded = app.seed(&mut rng, trivial::NoopLeafStep, ()).unwrap().0;
    let seeded = seeded.carry::<trivial::NoopHeader>(());
    assert!(app.verify(&seeded, &mut rng).unwrap());

    // Rerandomize
    let seeded = app.rerandomize(seeded, &mut rng).unwrap();
    assert!(app.verify(&seeded, &mut rng).unwrap());

    let fused = app
        .fuse(&mut rng, trivial::NoopMergeStep, (), seeded.clone(), seeded)
        .unwrap()
        .0;
    let fused = fused.carry::<trivial::NoopHeader>(());
    assert!(app.verify(&fused, &mut rng).unwrap());

    let fused = app.rerandomize(fused, &mut rng).unwrap();
    assert!(app.verify(&fused, &mut rng).unwrap());
}
