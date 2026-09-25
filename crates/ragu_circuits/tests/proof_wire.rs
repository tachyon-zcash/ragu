//! Test-only demonstration of #191/#660 using the polynomial and wire codecs.

use ragu_arithmetic::{
    Cycle,
    ff::Field,
    group::{Curve, CurveAffine},
};
use ragu_circuits::polynomials::{Rank, TestRank, sparse::Polynomial};
use ragu_pasta::{EqAffine, Fp, Pasta};
use ragu_primitives::wire::{self, Compress, Decode, Encode, Limits};

type Poly = Polynomial<Fp, TestRank>;

#[derive(Compress)]
#[ragu(compressed = CompressedToyProof)]
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

// Exercise the associated-type/generic shape used by the eventual real proof,
// without changing or serializing that proof.
#[derive(Compress)]
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

    fn recompute(proof: &CompressedToyProof) -> Derived {
        Derived(proof.polynomial.eval(proof.query))
    }

    pub fn expand(proof: CompressedToyProof) -> ExpandedToyProof {
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
    pub fn verify(proof: &CompressedToyProof) -> bool {
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
    verifier::expand(CompressedToyProof {
        query,
        point,
        polynomial,
    })
}

#[test]
fn compress_encode_decode_expand_and_verify() {
    let proof = example(3);
    let package = proof.compress();
    let bytes = package.to_bytes();
    let decoded = CompressedToyProof::from_bytes(&bytes, Limits::default()).unwrap();
    assert!(verifier::verify(&decoded));
    assert_eq!(decoded.to_bytes(), bytes);
    let expanded = verifier::expand(decoded);
    assert_eq!(verifier::cached_evaluation(&expanded), Fp::from(7));
    assert_eq!(expanded.compress().to_bytes(), bytes);

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
    let expected = proof.compress().to_bytes();
    let generic = GenericToy::<Pasta, TestRank> {
        query: proof.query,
        point: proof.point,
        polynomial: proof.polynomial,
        cache: proof.evaluation,
    };
    let bytes = generic.compress().to_bytes();
    assert_eq!(bytes, expected);
    let decoded =
        GenericToyCompressed::<Pasta, TestRank>::from_bytes(&bytes, Limits::default()).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
    // The omitted cache remains available only on the source representation.
    let _cache = generic.cache;
}

#[test]
fn poisoned_prover_cache_is_omitted_and_recomputed() {
    let mut proof = example(3);
    let expected = proof.compress().to_bytes();
    proof.evaluation = example(20).evaluation;
    assert_eq!(verifier::cached_evaluation(&proof), Fp::from(41));
    assert_eq!(proof.compress().to_bytes(), expected);
    let decoded = CompressedToyProof::from_bytes(&expected, Limits::default()).unwrap();
    assert!(verifier::verify(&decoded));
    assert_eq!(
        verifier::cached_evaluation(&verifier::expand(decoded)),
        Fp::from(7)
    );
}

#[test]
fn decoder_and_verifier_reject_different_classes_of_tampering() {
    let mut package = example(3).compress();
    package.point = EqAffine::identity();
    let bytes = package.to_bytes();
    let decoded = CompressedToyProof::from_bytes(&bytes, Limits::default()).unwrap();
    assert!(!verifier::verify(&decoded));

    let bytes = example(3).compress().to_bytes();
    // The generated struct derives no Debug, so `unwrap_err` is unavailable.
    for length in 0..bytes.len() {
        CompressedToyProof::from_bytes(&bytes[..length], Limits::default())
            .err()
            .expect("truncated proof");
    }
    let mut wrong_version = bytes.clone();
    wrong_version[0] = wire::VERSION.wrapping_add(1);
    CompressedToyProof::from_bytes(&wrong_version, Limits::default())
        .err()
        .expect("wrong version");
    let mut trailing = bytes;
    trailing.push(0);
    CompressedToyProof::from_bytes(&trailing, Limits::default())
        .err()
        .expect("trailing byte");
}
