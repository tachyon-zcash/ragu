use alloc::{boxed::Box, string::ToString as _, vec::Vec};

use ragu_circuits::polynomials::{Rank, TestRank};
use ragu_core::{
    Error,
    pasta::{Ep, Eq, Fp, Fq, PallasGenerators, PastaParams, VestaGenerators},
};
use udon::curve::{AffineAdapter, Projective as _};

mod application;
mod ctx;
mod proof;

/// Deterministic test parameters with distinct generators at every test-rank
/// coefficient. Production callers supply ragu's canonical baked parameters.
pub(crate) fn test_params() -> &'static PastaParams {
    let pallas_generators = (1..=TestRank::num_coeffs())
        .map(|index| {
            let adapted = (Ep::generator() * Fq::from(index as u64)).to_affine();
            AffineAdapter::as_slice(&[adapted])[0]
        })
        .collect::<Vec<_>>();
    let vesta_generators = (1..=TestRank::num_coeffs())
        .map(|index| {
            let adapted = (Eq::generator() * Fp::from(index as u64)).to_affine();
            AffineAdapter::as_slice(&[adapted])[0]
        })
        .collect::<Vec<_>>();

    let pallas_blinding =
        (Ep::generator() * Fq::from(TestRank::num_coeffs() as u64 + 1)).to_affine();
    let vesta_blinding =
        (Eq::generator() * Fp::from(TestRank::num_coeffs() as u64 + 1)).to_affine();
    let pallas = PallasGenerators::new(
        pallas_generators.leak(),
        AffineAdapter::as_slice(&[pallas_blinding])[0],
    );
    let vesta = VestaGenerators::new(
        vesta_generators.leak(),
        AffineAdapter::as_slice(&[vesta_blinding])[0],
    );
    Box::leak(Box::new(PastaParams::new(pallas, vesta)))
}

pub(crate) fn assert_invalid_witness(error: Error, expected: &str) {
    match error {
        Error::InvalidWitness(source) => assert_eq!(source.to_string(), expected),
        other => panic!("expected InvalidWitness, got {other:?}"),
    }
}
