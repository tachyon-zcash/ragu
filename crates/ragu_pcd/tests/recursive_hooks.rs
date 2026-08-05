//! Recursive enforcement of what the hooks produce: poly-queries, the
//! polynomials they open, and derived challenges.
//!
//! Requires the `unstable-fuzzing` feature for the proof-corruption helpers:
//! `cargo test -p ragu_pcd --features unstable-fuzzing --test recursive_hooks`

#![cfg(feature = "unstable-fuzzing")]

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::fuzz_utils::Corruption;
use ragu_testing::pcd::poly_query::{
    CommitAndOpen, CommitAndOpenWitness, OpenAndHash, OpenAndHashWitness, open_app, poly,
};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;

#[test]
fn a_corrupted_poly_query_is_rejected_directly_and_recursively() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1234);

    let polynomial = poly(&[3, 1, 4, 1, 5]);
    let (leaf1, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            polynomial,
            claimed_y: None,
        },
    )?;
    assert!(app.verify(&leaf1, &mut rng)?);

    let mut proof = leaf1.proof().clone();
    proof.corrupt(Corruption::QueryY(0, Fp::from(1u64)));
    let corrupted_leaf = proof.carry(leaf1.data().clone());
    assert!(
        !app.verify(&corrupted_leaf, &mut rng)?,
        "root verify must reject a corrupted poly-query"
    );

    let polynomial = poly(&[2, 7, 1, 8, 2, 8]);
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            polynomial,
            claimed_y: None,
        },
    )?;
    let p1 = poly::<Fp, R>(&[3, 1, 4, 1, 5]);
    let x = Fp::from(9u64);
    let y = p1.eval(x);

    let fused = app.fuse(
        &mut rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness {
            polynomial: p1.clone(),
            x,
            y,
        },
        corrupted_leaf,
        leaf2,
    );
    match fused {
        Err(e) => std::eprintln!("fuse rejected natively: {e:?}"),
        Ok((parent, ())) => {
            std::eprintln!("fuse produced a proof; checking verify...");
            assert!(
                !app.verify(&parent, &mut rng)?,
                "a parent of a corrupted-poly-query child must not verify"
            );
        }
    }

    Ok(())
}

/// A derived challenge that is not the hash of the point it was derived from
/// is rejected — directly at root verify, and recursively when the proof is
/// fused as a child. (Editing a finished proof also breaks the child's revdot
/// poly-query, so this does not isolate the `challenge_binding` circuit.)
#[test]
fn forged_challenge_is_rejected_directly_and_recursively() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(99);

    let polynomial = poly(&[3, 1, 4, 1, 5]);
    let (honest, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            polynomial,
            claimed_y: None,
        },
    )?;
    assert!(app.verify(&honest, &mut rng)?);

    // Keep the point, change the challenge.
    let mut proof = honest.proof().clone();
    proof.corrupt(Corruption::ChallengeValue(0, Fp::from(1u64)));
    let forged = proof.carry(honest.data().clone());
    assert!(
        !app.verify(&forged, &mut rng)?,
        "root verify must reject a challenge that is not its point's hash"
    );

    let polynomial = poly(&[2, 7, 1, 8]);
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            polynomial,
            claimed_y: None,
        },
    )?;
    let p3 = poly::<Fp, R>(&[5, 5, 5]);
    let x = Fp::from(11u64);
    let y = p3.eval(x);

    let fused = app.fuse(
        &mut rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness {
            polynomial: p3.clone(),
            x,
            y,
        },
        forged,
        leaf2,
    );

    match fused {
        Err(e) => std::eprintln!("interior fuse rejected the forged challenge: {e:?}"),
        Ok((parent, ())) => {
            assert!(
                !app.verify(&parent, &mut rng)?,
                "a parent of a forged-challenge child must not verify"
            );
        }
    }

    Ok(())
}

/// S2 — a poly-query whose commitment is no carried polynomial's is rejected:
/// negate the commitment and nothing else, so it is a perfectly valid point
/// that nothing in the instance commits to, at root and through a fuse.
#[test]
fn a_poly_query_against_an_uncarried_commitment_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(4242);

    let polynomial = poly(&[3, 1, 4, 1, 5]);
    let (honest, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            polynomial,
            claimed_y: None,
        },
    )?;
    assert!(
        app.verify(&honest, &mut rng)?,
        "the honest leaf must verify"
    );

    let mut proof = honest.proof().clone();
    proof.corrupt(Corruption::QueryCom(0));
    let tampered = proof.carry(honest.data().clone());

    assert!(
        !app.verify(&tampered, &mut rng)?,
        "root verify must reject a poly-query against a commitment no carried polynomial produced"
    );

    let polynomial = poly(&[2, 7, 1, 8]);
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            polynomial,
            claimed_y: None,
        },
    )?;
    let p3 = poly::<Fp, R>(&[5, 5, 5]);
    let x = Fp::from(11u64);
    let y = p3.eval(x);

    let fused = app.fuse(
        &mut rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness {
            polynomial: p3.clone(),
            x,
            y,
        },
        tampered,
        leaf2,
    );

    match fused {
        Err(e) => std::eprintln!("interior fuse rejected the unresolvable query name: {e:?}"),
        Ok((parent, ())) => {
            assert!(
                !app.verify(&parent, &mut rng)?,
                "a parent of a child whose poly-query opens no carried polynomial must not verify"
            );
        }
    }

    Ok(())
}

// Two tests lived here, both about a commitment that is not its polynomial's:
// one substituting the polynomial behind a query's commitment, one
// substituting the commitment carried beside a polynomial. Neither state can
// be built any more. A step hands over a polynomial and the framework commits
// it, and a proof carries only the polynomial — so there is no second copy to
// disagree with the first, at any boundary. What the tests proved is now a
// property of the types.
