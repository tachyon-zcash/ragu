//! Transport and production verification through the common proof-form API.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{Application, ProofForm, header::NUM_ONLINE_POLYNOMIALS};
use ragu_testing::pcd::nontrivial::LeafNode;
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use crate::nontrivial_support::{HEADER_SIZE, app, leaf};

fn assert_roundtrip_and_verification<P: ProofForm<Pasta, ProductionRank>>(
    application: &Application<'_, Pasta, ProductionRank, HEADER_SIZE>,
    proof: P,
    data: Fp,
    expected: [<Pasta as Cycle>::HostCurve; NUM_ONLINE_POLYNOMIALS],
    rng: &mut StdRng,
) {
    assert_eq!(proof.online_commitments(), expected);
    let bytes = proof.to_bytes().expect("encode");
    assert_eq!(bytes.len(), P::encoded_len::<HEADER_SIZE>());
    let decoded = P::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded.to_bytes().expect("re-encode"), bytes);
    assert_eq!(decoded.online_commitments(), expected);
    assert!(P::from_bytes(&bytes[..bytes.len() - 1]).is_err());

    let carried = decoded.carry::<LeafNode>(data);
    assert!(P::verify::<LeafNode, _, _, HEADER_SIZE>(application, &carried, rng).expect("verify"));

    let wrong_data = proof.carry::<LeafNode>(data + Fp::ONE);
    assert!(
        !P::verify::<LeafNode, _, _, HEADER_SIZE>(application, &wrong_data, rng)
            .expect("verify wrong header")
    );
}

#[test]
fn both_proof_forms_roundtrip_and_verify() {
    let application = app();
    let mut rng = StdRng::seed_from_u64(953);
    let pcd = leaf(&application, &mut rng, 7);
    let expected = pcd.commitments();
    let (compressed, compressed_data) = application
        .compress(&pcd, &mut rng)
        .expect("compress")
        .into_parts();
    let (proof, data) = pcd.into_parts();
    assert_eq!(data, compressed_data);
    assert_roundtrip_and_verification(&application, proof, data, expected, &mut rng);
    assert_roundtrip_and_verification(&application, compressed, data, expected, &mut rng);
}
