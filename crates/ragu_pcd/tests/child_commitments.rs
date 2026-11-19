//! Debug consistency failures in the nested commitment walk must return an
//! invalid-witness error when fusion consumes a stale child cache.

#![cfg(debug_assertions)]

use alloc::{string::ToString, vec};

use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{WalletRank, sparse};
use ragu_core::{Cycle, Error, Result, pasta::Pasta};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::Proof;
use crate::{ApplicationBuilder, step::internal::rerandomize::Rerandomize};

type TestProof = Proof<Pasta, WalletRank>;

fn check(mutate: impl FnOnce(&mut TestProof)) -> Result<()> {
    let params = crate::pasta::baked();
    let app = ApplicationBuilder::<Pasta, WalletRank, 4>::new().finalize(params)?;
    let mut rng = StdRng::seed_from_u64(0x57a1e);
    let honest = app.rerandomize(app.bootstrap_pcd(), &mut rng)?;
    assert!(app.verify_uncompressed(&honest, &mut rng)?);
    let (parent, ()) = app.fuse(
        &mut rng,
        Rerandomize::<()>::new(),
        (),
        honest.clone(),
        honest.clone(),
    )?;
    assert!(app.verify_uncompressed(&parent, &mut rng)?);

    let mut proof = honest.proof().clone();
    mutate(&mut proof);
    assert!(proof.well_formed());
    assert_ne!(
        ReferenceBackend::sparse_commit_to_affine(
            proof.nested_p_poly(),
            Pasta::nested_generators(params),
        ),
        proof.nested_p_commitment(),
        "the mutation must leave a stale commitment"
    );
    let malformed = proof.carry::<()>(());
    for (side, left, right) in [
        ("left", malformed.clone(), honest.clone()),
        ("right", honest.clone(), malformed.clone()),
    ] {
        assert!(
            matches!(
                app.fuse(&mut rng, Rerandomize::<()>::new(), (), left, right),
                Err(Error::InvalidWitness(message))
                    if message.to_string() == "nested P does not match its accumulated polynomial"
            ),
            "fusion must return the nested consistency error for the {side} child"
        );
    }
    assert!(matches!(
        app.rerandomize(malformed, &mut rng),
        Err(Error::InvalidWitness(message))
            if message.to_string() == "nested P does not match its accumulated polynomial"
    ));
    Ok(())
}

#[test]
fn stale_nested_p_polynomial_returns_invalid_witness() -> Result<()> {
    check(|proof| {
        // A canonical, shape-preserving coefficient edit leaves the cached
        // point intact, reproducing the mismatch at the debug check.
        proof
            .nested_p_poly
            .add_assign(&sparse::Polynomial::from_coeffs(vec![
                <Pasta as Cycle>::ScalarField::ONE,
            ]));
    })
}

#[test]
fn stale_nested_p_commitment_returns_invalid_witness() -> Result<()> {
    check(|proof| {
        // Replace only the cache with another valid, nonidentity curve point.
        proof.nested_p_commitment.0 = proof.nested_a_commitment();
    })
}
