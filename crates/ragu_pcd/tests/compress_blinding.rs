//! Recompress known-blinded trace commitments through the real transcript.
//! Mounted under `proof` so the test can replace a commitment cache without
//! exposing a mutation API or changing the committed polynomial.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle, FixedGenerators,
    pasta::{Fp, Fq, Pasta},
};
use rand::{SeedableRng, rngs::StdRng};
use udon::curve::{Affine, Projective};

use crate::{ApplicationBuilder, ipa::IpaCycle};

#[test]
fn rejects_recompressed_blinded_trace_commitments() {
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new(crate::pasta::baked())
        .finalize()
        .unwrap();
    let honest = app.bootstrap_pcd();
    let mut rng = StdRng::seed_from_u64(0x462);
    assert!(
        app.verify_compressed(&app.compress(&honest, &mut rng).unwrap())
            .unwrap()
    );

    // Hashes1 is the report's source component. The polynomial and data
    // remain honest; only the commitment acquires a known nonzero blind.
    for base in [
        *Pasta::host_generators(app.params).h(),
        *Pasta::host_u(app.params),
    ] {
        let (mut proof, ()) = honest.clone().into_parts();
        proof.native_hashes_1_commitment.0 = (proof.native_hashes_1_commitment.0.to_projective()
            + (base * Fp::from(0x462)))
        .to_affine();
        let blinded = proof.carry::<()>(());
        assert!(!app.verify(&blinded, StdRng::seed_from_u64(0x462)).unwrap());
        // Rebuild all reductions and opening messages after changing the
        // instance; this is not replay of an old proof or transcript.
        let compressed = app.compress(&blinded, &mut rng).unwrap();
        assert!(!app.verify_compressed(&compressed).unwrap());
    }

    // Exercise the same boundary on the other curve, whose challenges and
    // scalar encodings use the nested transcript.
    for base in [
        *Pasta::nested_generators(app.params).h(),
        *Pasta::nested_u(app.params),
    ] {
        let (mut proof, ()) = honest.clone().into_parts();
        proof.nested_compute_v_commitment.0 = (proof.nested_compute_v_commitment.0.to_projective()
            + (base * Fq::from(0x462)))
        .to_affine();
        let blinded = proof.carry::<()>(());
        assert!(!app.verify(&blinded, StdRng::seed_from_u64(0x462)).unwrap());
        let compressed = app.compress(&blinded, &mut rng).unwrap();
        assert!(!app.verify_compressed(&compressed).unwrap());
    }
}
