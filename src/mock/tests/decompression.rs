use alloc::{vec, vec::Vec};

use ragu_circuits::polynomials::{ProductionRank, R, Rank};
use ragu_core::{
    Result,
    pasta::{Fp, Pasta},
};
use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use super::application::{Merge, Seed, ValueHeader, test_builder_for, test_params_for};
use crate::{CompressedPcd, CompressedProof};

type Compressed = CompressedPcd<Pasta, ValueHeader>;

fn transport(pcd: Compressed) -> Compressed {
    let (proof, data) = pcd.into_parts();
    CompressedProof::from_bytes(&proof.to_bytes().expect("encode compressed proof"))
        .expect("decode compressed proof")
        .carry::<ValueHeader>(data)
}

fn polynomials(root: u64) -> [Vec<Fp>; 2] {
    [vec![Fp::ONE], vec![-Fp::from(root), Fp::ONE]]
}

#[test]
fn decompress_fuse_recompress_after_transport() -> Result<()> {
    let app = test_builder_for::<ProductionRank>()
        .register(Seed::<0>)?
        .register(Merge(false))?
        .finalize(test_params_for::<ProductionRank>())?;
    let mut rng = StdRng::seed_from_u64(94);
    let (left, ()) = app.seed(&mut rng, Seed::<0>, Fp::from(5))?;
    let (right, ()) = app.seed(&mut rng, Seed::<0>, Fp::from(7))?;
    let left = transport(app.compress(&left, &mut rng)?);
    let right = transport(app.compress(&right, &mut rng)?);
    let left_restored = app.decompress(&mut rng, &left, polynomials(5))?;
    assert_eq!(left_restored.data(), left.data());
    assert_eq!(left_restored.commitments(), left.online_commitments());
    assert!(app.verify_uncompressed(&left_restored, &mut rng)?);
    let right_restored = app.decompress(&mut rng, &right, polynomials(7))?;
    let (merged, ()) = app.fuse(&mut rng, Merge(false), None, left_restored, right_restored)?;
    let product = [vec![Fp::ONE], vec![Fp::from(35), -Fp::from(12), Fp::ONE]];
    assert_eq!(merged.polynomials(), product);
    let compressed = transport(app.compress(&merged, &mut rng)?);
    assert!(app.verify_compressed(&compressed)?);
    // A received aggregate can itself be decompressed and aggregated again.
    let aggregate = app.decompress(&mut rng, &compressed, product)?;
    let right_restored = app.decompress(&mut rng, &right, polynomials(7))?;
    let (merged_again, ()) = app.fuse(&mut rng, Merge(false), None, aggregate, right_restored)?;
    assert!(app.verify_compressed(&transport(app.compress(&merged_again, &mut rng)?))?);
    Ok(())
}

#[test]
fn decompression_rejects_bad_polynomial_witnesses_and_statements() -> Result<()> {
    let app = test_builder_for::<ProductionRank>()
        .register(Seed::<0>)?
        .finalize(test_params_for::<ProductionRank>())?;
    let mut rng = StdRng::seed_from_u64(95);
    let (pcd, ()) = app.seed(&mut rng, Seed::<0>, Fp::from(5))?;
    let compressed = transport(app.compress(&pcd, &mut rng)?);
    for invalid in [
        [vec![], polynomials(5)[1].clone()],
        [vec![Fp::ZERO], polynomials(5)[1].clone()],
        [
            vec![Fp::ONE; ProductionRank::num_coeffs() + 1],
            polynomials(5)[1].clone(),
        ],
        polynomials(6),
        // Substituting padding for a meaningful online polynomial is unsafe.
        [vec![Fp::ONE], vec![Fp::ONE]],
        [polynomials(5)[1].clone(), vec![Fp::ONE]],
    ] {
        assert!(app.decompress(&mut rng, &compressed, invalid).is_err());
    }
    let relabelled = compressed
        .proof()
        .clone()
        .carry::<ValueHeader>(*compressed.data() + Fp::ONE);
    assert!(
        app.decompress(&mut rng, &relabelled, polynomials(5))
            .is_err()
    );
    let wrong_suffix = compressed.proof().clone().carry::<()>(());
    assert!(
        app.decompress(&mut rng, &wrong_suffix, polynomials(5))
            .is_err()
    );
    let mut corrupt = compressed.clone();
    corrupt.proof.binding[0] ^= 1;
    assert!(app.decompress(&mut rng, &corrupt, polynomials(5)).is_err());
    assert!(
        app.decompress(&mut rng, &compressed, polynomials(5))
            .is_ok()
    );
    Ok(())
}

#[test]
fn decompression_rejects_a_different_application_or_rank() -> Result<()> {
    let params = test_params_for::<R<14>>();
    let app = test_builder_for::<ProductionRank>()
        .register(Seed::<0>)?
        .finalize(params)?;
    // Another application: its step stages two values.
    let other = test_builder_for::<ProductionRank>()
        .register(Seed::<0, 2>)?
        .finalize(params)?;
    let larger = test_builder_for::<R<14>>()
        .register(Seed::<0>)?
        .finalize(params)?;
    let mut rng = StdRng::seed_from_u64(96);
    let (pcd, ()) = app.seed(&mut rng, Seed::<0>, Fp::from(5))?;
    let compressed = transport(app.compress(&pcd, &mut rng)?);
    assert!(
        other
            .decompress(&mut rng, &compressed, polynomials(5))
            .is_err()
    );
    assert!(
        larger
            .decompress(&mut rng, &compressed, polynomials(5))
            .is_err()
    );
    Ok(())
}
