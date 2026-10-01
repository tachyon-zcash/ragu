//! Minimization and expansion using the polynomial and wire codecs.

use ragu_circuits::polynomials::{Rank, TestRank, sparse::Polynomial};
use ragu_core::{
    Cycle,
    pasta::{EqAffine, Fp, Pasta},
};
use ragu_primitives::wire::{self, Decode, Encode, Limits, Minimize};
use udon::{
    curve::{Affine, Projective},
    field::Field,
};

type Poly = Polynomial<Fp, TestRank>;

#[derive(Minimize)]
#[ragu(minimal = MinimalToyProof)]
struct ExpandedToyProof {
    #[ragu(provided, codec = wire::Scalar)]
    query: Fp,
    #[ragu(provided, codec = wire::Point)]
    point: EqAffine,
    #[ragu(provided)]
    polynomial: Poly,
    #[ragu(derived)]
    evaluation: verifier::Derived,
}

// Exercise cycle-associated types and ranks independently of PCD verification.
#[derive(Minimize)]
struct GenericToy<C: Cycle, R: Rank> {
    #[ragu(provided, codec = wire::Scalar)]
    query: C::CircuitField,
    #[ragu(provided, codec = wire::Point)]
    point: C::HostCurve,
    #[ragu(provided)]
    polynomial: Polynomial<C::CircuitField, R>,
    #[ragu(derived)]
    cache: verifier::Derived,
}

mod verifier {
    use super::*;

    // Only this module can construct Derived. It deliberately has no Clone,
    // Encode or Decode implementation, nor a constructor accepting a scalar.
    pub struct Derived(Fp);

    fn recompute(proof: &MinimalToyProof) -> Derived {
        Derived(proof.polynomial.eval(proof.query))
    }

    pub fn expand(proof: MinimalToyProof) -> ExpandedToyProof {
        let evaluation = recompute(&proof);
        ExpandedToyProof {
            query: proof.query,
            point: proof.point,
            polynomial: proof.polynomial,
            evaluation,
        }
    }

    // This toy statement binds the point to g * polynomial(query). It is not
    // a polynomial commitment scheme or a substitute for Ragu verification.
    pub fn verify(proof: &MinimalToyProof) -> bool {
        proof.point == (EqAffine::generator() * recompute(proof).0).to_affine()
    }

    pub fn cached_evaluation(proof: &ExpandedToyProof) -> Fp {
        proof.evaluation.0
    }
}

fn example(query: u64) -> ExpandedToyProof {
    let query = Fp::from(query);
    let polynomial = Poly::from_coeffs(vec![Fp::ONE, Fp::from(2)]);
    let point = (EqAffine::generator() * polynomial.eval(query)).to_affine();
    verifier::expand(MinimalToyProof {
        query,
        point,
        polynomial,
    })
}

#[test]
fn minimize_encode_decode_expand_and_verify() {
    let proof = example(3);
    let package = proof.minimize();
    let bytes = package.to_bytes();
    let decoded = MinimalToyProof::from_bytes(&bytes, Limits::default()).unwrap();
    assert!(verifier::verify(&decoded));
    assert_eq!(decoded.to_bytes(), bytes);
    let expanded = verifier::expand(decoded);
    assert_eq!(verifier::cached_evaluation(&expanded), Fp::from(7));
    assert_eq!(expanded.minimize().to_bytes(), bytes);

    // Declaration order: query, point, polynomial, under a single envelope.
    let mut expected = vec![wire::VERSION];
    <Fp as Encode<wire::Scalar>>::encode(&proof.query, &mut expected);
    <EqAffine as Encode<wire::Point>>::encode(&proof.point, &mut expected);
    proof.polynomial.encode(&mut expected);
    assert_eq!(bytes, expected);
}

#[test]
fn derives_for_cycle_associated_types_and_rank() {
    let proof = example(3);
    let expected = proof.minimize().to_bytes();
    let generic = GenericToy::<Pasta, TestRank> {
        query: proof.query,
        point: proof.point,
        polynomial: proof.polynomial,
        cache: proof.evaluation,
    };
    let bytes = generic.minimize().to_bytes();
    assert_eq!(bytes, expected);
    let decoded =
        GenericToyMinimal::<Pasta, TestRank>::from_bytes(&bytes, Limits::default()).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
    // The omitted cache remains available only on the source representation.
    let _cache = generic.cache;
}

#[test]
fn poisoned_prover_cache_is_omitted_and_recomputed() {
    let mut proof = example(3);
    let expected = proof.minimize().to_bytes();
    proof.evaluation = example(20).evaluation;
    assert_eq!(verifier::cached_evaluation(&proof), Fp::from(41));
    assert_eq!(proof.minimize().to_bytes(), expected);
    let decoded = MinimalToyProof::from_bytes(&expected, Limits::default()).unwrap();
    assert!(verifier::verify(&decoded));
    assert_eq!(
        verifier::cached_evaluation(&verifier::expand(decoded)),
        Fp::from(7)
    );
}

#[test]
fn decoder_and_verifier_reject_different_classes_of_tampering() {
    let mut package = example(3).minimize();
    package.point = EqAffine::identity();
    let bytes = package.to_bytes();
    let decoded = MinimalToyProof::from_bytes(&bytes, Limits::default()).unwrap();
    assert!(!verifier::verify(&decoded));

    let bytes = example(3).minimize().to_bytes();
    // The generated struct derives no Debug, so `unwrap_err` is unavailable.
    for length in 0..bytes.len() {
        MinimalToyProof::from_bytes(&bytes[..length], Limits::default())
            .err()
            .expect("truncated proof");
    }
    let mut wrong_version = bytes.clone();
    wrong_version[0] = wire::VERSION.wrapping_add(1);
    MinimalToyProof::from_bytes(&wrong_version, Limits::default())
        .err()
        .expect("wrong version");
    let mut trailing = bytes;
    trailing.push(0);
    MinimalToyProof::from_bytes(&trailing, Limits::default())
        .err()
        .expect("trailing byte");
}

#[test]
fn pre_udon_polynomial_encoding() {
    // Captured at 887e0abc, before the Udon migration.
    let bytes = include_bytes!("fixtures/wire/polynomial.bin");
    let poly = Poly::from_coeffs(vec![Fp::ONE, Fp::ZERO, Fp::from(17), -Fp::ONE]);
    assert_eq!(poly.to_bytes(), bytes);
    let decoded = Poly::from_bytes(bytes, Limits::default()).unwrap();
    assert!(decoded.iter_coeffs().eq(poly.iter_coeffs()));
}
