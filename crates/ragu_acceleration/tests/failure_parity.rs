//! Both backends must behave identically on inputs the `Backend` contract
//! excludes, so no caller can observe which backend is selected through a
//! panic or a silently different result.

use ragu_acceleration::AcceleratedBackend;
use ragu_arithmetic::{
    Cycle, FixedGenerators,
    group::{Curve, Group},
    pasta_curves::pallas,
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{Rank, TestRank, sparse::Polynomial};
use ragu_pasta::Pasta;

#[test]
fn unequal_lengths_truncate_identically() {
    let generator = pallas::Point::generator();
    let scalars: Vec<pallas::Scalar> = (1..=5).map(pallas::Scalar::from).collect();
    let bases: Vec<pallas::Affine> = (1..=3)
        .map(|i| (generator * pallas::Scalar::from(i)).to_affine())
        .collect();

    let canonical = ragu_arithmetic::msm(scalars.iter(), bases.iter());
    assert_eq!(
        ReferenceBackend::msm(scalars.iter(), bases.iter()),
        canonical
    );
    assert_eq!(
        AcceleratedBackend::msm(scalars.iter(), bases.iter()),
        canonical
    );

    // The symmetric case: more bases than scalars.
    let canonical = ragu_arithmetic::msm(scalars[..2].iter(), bases.iter());
    assert_eq!(
        ReferenceBackend::msm(scalars[..2].iter(), bases.iter()),
        canonical
    );
    assert_eq!(
        AcceleratedBackend::msm(scalars[..2].iter(), bases.iter()),
        canonical
    );
}

/// A generator table shorter than the rank requires.
struct ShortGenerators {
    g: Vec<pallas::Affine>,
    h: pallas::Affine,
    u: pallas::Affine,
}

impl ShortGenerators {
    fn new() -> Self {
        let full = Pasta::nested_generators(Pasta::baked());
        Self {
            g: full.g()[..TestRank::num_coeffs() / 2].to_vec(),
            h: *full.h(),
            u: *full.u(),
        }
    }
}

impl FixedGenerators<pallas::Affine> for ShortGenerators {
    fn g(&self) -> &[pallas::Affine] {
        &self.g
    }

    fn h(&self) -> &pallas::Affine {
        &self.h
    }

    fn u(&self) -> &pallas::Affine {
        &self.u
    }
}

fn dense_poly() -> Polynomial<pallas::Scalar, TestRank> {
    Polynomial::from_coeffs(
        (0..TestRank::num_coeffs())
            .map(|i| pallas::Scalar::from(i as u64 + 1))
            .collect(),
    )
}

#[test]
#[should_panic(expected = "generators.g().len() >= R::num_coeffs()")]
fn reference_commit_rejects_short_generators() {
    let _ = ReferenceBackend::sparse_commit(&dense_poly(), &ShortGenerators::new());
}

#[test]
#[should_panic(expected = "generators.g().len() >= R::num_coeffs()")]
fn accelerated_commit_rejects_short_generators() {
    let _ = AcceleratedBackend::sparse_commit(&dense_poly(), &ShortGenerators::new());
}
