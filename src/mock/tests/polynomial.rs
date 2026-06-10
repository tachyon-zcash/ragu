use core::ops::Neg as _;

use ff::Field as _;
use pasta_curves::Fp;

use crate::polynomial::*;

#[test]
fn from_roots_and_multiply() {
    let a = Fp::from(3u64);
    let b = Fp::from(7u64);

    let pa = Polynomial::from_roots(&[a]);
    assert_eq!(pa.coefficients(), &[a.neg(), Fp::ONE]);

    let pb = Polynomial::from_roots(&[b]);
    assert_eq!(pa.multiply(&pb), Polynomial::from_roots(&[a, b]));

    let identity = Polynomial::default();
    assert_eq!(pa.multiply(&identity), pa);
}

#[test]
fn commitment_deterministic_and_distinct() {
    let c1 = Polynomial::from_roots(&[Fp::from(1u64)]).commit();
    let c2 = Polynomial::from_roots(&[Fp::from(2u64)]).commit();
    let c1_again = Polynomial::from_roots(&[Fp::from(1u64)]).commit();
    assert_eq!(c1, c1_again);
    assert_ne!(c1, c2);
}

#[test]
fn commitment_serialization_roundtrip() {
    let commitment = Polynomial::from_roots(&[Fp::from(99u64)]).commit();
    let bytes: [u8; 32] = commitment.into();
    let recovered = Commitment::try_from(&bytes).expect("valid point");
    assert_eq!(commitment, recovered);
}

#[test]
fn trailing_zeros_preserve_commitment_and_equality() {
    let a = Fp::from(3u64);
    let b = Fp::from(7u64);

    // A coefficient vector and the same vector padded with trailing zeros denote
    // the same fixed-rank polynomial: a zero coefficient contributes the
    // identity point, so the Pedersen commit is unchanged.
    let short = Polynomial::from_coeffs(&[a, b]);
    let padded_tail = Polynomial::from_coeffs(&[a, b, Fp::ZERO]);
    assert_eq!(short, padded_tail, "tail zero preserves commitment");

    // Head position is still binding: a zero in front moves everything to a
    // different generator, so the commitment differs.
    let short = Polynomial::from_coeffs(&[a, b]);
    let head_padded = Polynomial::from_coeffs(&[Fp::ZERO, a, b]);
    assert_ne!(short, head_padded, "head zero changes commitment");

    // Interior position is still binding: a zero in the middle moves `b` onto a
    // different generator, so the commitment differs.
    let interior = Polynomial::from_coeffs(&[a, Fp::ZERO, b]);
    assert_ne!(short, interior, "interior zero changes commitment");
}

#[test]
fn blinding_changes_commitment() {
    // `commit` is unblinded; blinding is a separate homomorphic `+ blind·h`
    // against the blinding generator.
    let unblinded = Polynomial::from_roots(&[Fp::from(42u64)]).commit();
    let blinded = unblinded + generators::h() * Fp::ONE;
    assert_ne!(unblinded, blinded);
}

#[test]
fn short_commit_blind_changes_commitment() {
    // `short_commit` mirrors ragu's `FixedGenerators::short_commit`
    // (`g(0)·value + h·blind`); varying the blind changes the commitment.
    let value = Fp::from(7u64);
    assert_ne!(
        generators::short_commit(value, Fp::ZERO),
        generators::short_commit(value, Fp::ONE),
    );
}
