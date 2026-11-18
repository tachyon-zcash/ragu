//! Rerandomization folds its input with a fresh trivial proof whose
//! accumulators are uniformly random. These tests hold the trivial proof and
//! the result to that: both verify, and each accumulator polynomial is dense
//! and differs from one run to the next.

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, pasta::Fp};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::{
    Proof,
    recursive_propagation_tests::support::{self, C, R, Seed},
};
use crate::{
    internal::native::online,
    step::{Index, InternalStepIndex},
};

/// Whether every coefficient of `poly` is nonzero. A uniform polynomial
/// fails this with probability at most its length over the field size.
fn is_dense<F: Field>(poly: &sparse::Polynomial<F, R>) -> bool {
    poly.iter_coeffs().len() == R::num_coeffs() && poly.iter_coeffs().all(|c| c != F::ZERO)
}

/// Holds every accumulator polynomial of `proof` to be dense, and to differ
/// from its counterpart in `other`.
fn assert_masked(proof: &Proof<C, R>, other: &Proof<C, R>, label: &str) {
    for (name, poly, counterpart) in [
        ("a", &proof.native_a_poly, &other.native_a_poly),
        ("b", &proof.native_b_poly, &other.native_b_poly),
        ("p", &proof.native_p_poly, &other.native_p_poly),
    ] {
        assert!(is_dense(poly), "{label}: native {name} must be dense");
        assert!(
            !poly.iter_coeffs().eq(counterpart.iter_coeffs()),
            "{label}: native {name} must differ between runs"
        );
    }
    for (name, poly, counterpart) in [
        ("a", &proof.nested_a_poly, &other.nested_a_poly),
        ("b", &proof.nested_b_poly, &other.nested_b_poly),
        ("p", &proof.nested_p_poly, &other.nested_p_poly),
    ] {
        assert!(is_dense(poly), "{label}: nested {name} must be dense");
        assert!(
            !poly.iter_coeffs().eq(counterpart.iter_coeffs()),
            "{label}: nested {name} must differ between runs"
        );
    }
}

/// The trivial proof is a bootstrap proof: it verifies, and a parent
/// consumes it as a unit child. Its accumulators are the random dummy's,
/// folded.
#[test]
fn a_random_trivial_proof_verifies_with_random_accumulators() -> Result<()> {
    support::with_app(|app| {
        let first = app.random_trivial_pcd(&mut StdRng::seed_from_u64(0x7a11))?;
        let second = app.random_trivial_pcd(&mut StdRng::seed_from_u64(0x7a12))?;

        let bootstrap = Index::internal(InternalStepIndex::Bootstrap)
            .circuit_index::<<C as crate::profile::ProfiledCycle>::Profile>(
            app.num_application_steps,
        )?;
        for proof in [&first, &second] {
            assert_eq!(proof.proof().circuit_id, bootstrap);
            assert!(app.verify_differential(proof, StdRng::seed_from_u64(0x7a13))?);
        }
        assert_masked(first.proof(), second.proof(), "trivial proof");

        // A seed consumes it as it does the application's bootstrap proof.
        let mut rng = StdRng::seed_from_u64(0x7a14);
        let (seeded, ()) = app.fuse(&mut rng, Seed::new(), Fp::from(3), first, second)?;
        assert!(app.verify_differential(&seeded, &mut rng)?);
        Ok(())
    })
}

/// A rerandomized proof keeps the header's data and the output polynomials,
/// and its accumulators are masked: dense, and different for each run on
/// the same input.
#[test]
fn rerandomization_masks_every_accumulator_polynomial() -> Result<()> {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0x7a21);
        let (input, ()) = app.seed(&mut rng, Seed::new(), Fp::from(5))?;

        let first = app.rerandomize(input.clone(), &mut StdRng::seed_from_u64(0x7a22))?;
        let second = app.rerandomize(input.clone(), &mut StdRng::seed_from_u64(0x7a23))?;

        let rerandomize = Index::internal(InternalStepIndex::Rerandomize)
            .circuit_index::<<C as crate::profile::ProfiledCycle>::Profile>(
            app.num_application_steps,
        )?;
        for output in [&first, &second] {
            assert_eq!(output.proof().circuit_id, rerandomize);
            assert_eq!(output.data(), input.data());
            assert_eq!(
                online::coefficients(output.proof().online_polynomials()),
                online::coefficients(input.proof().online_polynomials()),
            );
            assert!(app.verify_differential(output, StdRng::seed_from_u64(0x7a24))?);
        }
        assert_masked(first.proof(), second.proof(), "rerandomized proof");

        // The same randomness gives the same proof: the application keeps
        // no state between rerandomizations.
        let replayed = app.rerandomize(input, &mut StdRng::seed_from_u64(0x7a22))?;
        assert_eq!(first.proof().test_mismatch(replayed.proof()), None);
        Ok(())
    })
}
