//! Review A03: each diagonal and off-diagonal residual has an independently
//! specified coefficient. These are local algebra tests, with all challenges
//! fixed; they do not permit an error committed earlier to adapt to a challenge.
//! The error producer is checked separately from the scalar consumer, so a
//! shared permutation cannot make the two mistakes cancel.
//! Mutation controls transpose the producer's i/j coordinates, reverse the
//! consumer's diagonal traversal, or replace the outer inverse challenge.

use alloc::{vec, vec::Vec};

use ragu_arithmetic::DeferredField;
use ragu_circuits::polynomials::{Rank, TestRank, sparse};
use ragu_core::{
    Result,
    drivers::emulator::Emulator,
    maybe::{Always, Maybe},
};
use ragu_pasta::{Fp, Fq};
use ragu_primitives::{Element, allocator::Standard, vec::FixedVec};

use super::*;
use crate::internal::{native, nested};

/// The coefficient of matrix entry (i,j) in a size-s reduction is
/// mu^(i-j) nu^(s-1-j). This expression uses neither Horner nor the production
/// off-diagonal iterator. In particular, swapping i and j changes the weight.
fn weight<F: Field>(mu: F, nu: F, size: usize, i: usize, j: usize) -> F {
    let power = mu.pow_vartime([i.abs_diff(j) as u64]);
    let signed = if i < j {
        power.invert().unwrap()
    } else {
        power
    };
    signed * nu.pow_vartime([(size - 1 - j) as u64])
}

fn scalar_fold<F: Field, P: Parameters>(
    ky: &[F],
    inner: &[Vec<F>],
    outer: &[F],
    challenges: [F; 4],
) -> Result<F> {
    let dr = &mut Emulator::execute();
    let allocator = &mut Standard::new();
    let [mu, nu, mu_prime, nu_prime] =
        challenges.map(|v| Element::alloc(dr, allocator, Always::<()>::just(|| v)).unwrap());
    let first = ClaimFolder::new(dr, &mu, &nu)?;
    let second = ClaimFolder::new(dr, &mu_prime, &nu_prime)?;
    let collapsed = FixedVec::try_from_fn(|g| {
        let errors = FixedVec::try_from_fn(|k| {
            Element::alloc(dr, allocator, Always::<()>::just(|| inner[g][k]))
        })?;
        let values = FixedVec::try_from_fn(|i| {
            Element::alloc(
                dr,
                allocator,
                Always::<()>::just(|| ky[g * P::GroupSize::len() + i]),
            )
        })?;
        first.fold_inner::<P>(dr, &errors, &values)
    })?;
    let errors =
        FixedVec::try_from_fn(|k| Element::alloc(dr, allocator, Always::<()>::just(|| outer[k])))?;
    Ok(*second
        .fold_outer::<P>(dr, &errors, &collapsed)?
        .value()
        .take())
}

fn every_residual<F: Field + From<u64>, P: Parameters>() -> Result<()> {
    let (n, m) = (P::NumGroups::len(), P::GroupSize::len());
    let mut ky = vec![F::ZERO; n * m];
    let mut inner = vec![vec![F::ZERO; m * (m - 1)]; n];
    let mut outer = vec![F::ZERO; n * (n - 1)];
    // Distinct nonzero, nonunit challenges distinguish the two layers and
    // the complementary powers. Repeat with a second assignment.
    for challenges in [[2, 3, 5, 7], [11, 13, 17, 19]].map(|a| a.map(F::from)) {
        let [mu, nu, mu_prime, nu_prime] = challenges;
        assert_eq!(
            scalar_fold::<F, P>(&ky, &inner, &outer, challenges)?,
            F::ZERO
        );
        for g in 0..n {
            let group_weight = nu_prime.pow_vartime([(n - 1 - g) as u64]);
            for i in 0..m {
                ky[g * m + i] = F::ONE;
                let expected = group_weight * nu.pow_vartime([(m - 1 - i) as u64]);
                assert_ne!(expected, F::ZERO);
                assert_eq!(
                    scalar_fold::<F, P>(&ky, &inner, &outer, challenges)?,
                    expected,
                    "diagonal residual at group {g}, claim {i}"
                );
                ky[g * m + i] = F::ZERO;
            }
            for i in 0..m {
                for j in 0..m {
                    if i == j {
                        continue;
                    }
                    let slot = i * (m - 1) + j - usize::from(j > i);
                    inner[g][slot] = F::ONE;
                    let expected = group_weight * weight(mu, nu, m, i, j);
                    assert_ne!(expected, F::ZERO);
                    assert_eq!(
                        scalar_fold::<F, P>(&ky, &inner, &outer, challenges)?,
                        expected,
                        "inner residual at group {g}, ({i},{j}), slot {slot}"
                    );
                    inner[g][slot] = F::ZERO;
                }
            }
        }
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let slot = i * (n - 1) + j - usize::from(j > i);
                outer[slot] = F::ONE;
                let expected = weight(mu_prime, nu_prime, n, i, j);
                assert_ne!(expected, F::ZERO);
                assert_eq!(
                    scalar_fold::<F, P>(&ky, &inner, &outer, challenges)?,
                    expected,
                    "outer residual ({i},{j}), slot {slot}"
                );
                outer[slot] = F::ZERO;
            }
        }
    }
    Ok(())
}

#[test]
fn native_every_fold_residual_has_the_prescribed_weight() -> Result<()> {
    every_residual::<Fp, native::RevdotParameters>()
}

#[test]
fn nested_every_fold_residual_has_the_prescribed_weight() -> Result<()> {
    every_residual::<Fq, nested::RevdotParameters>()
}

/// Coefficient-array specification of revdot, including reversal at the
/// rank boundary. Inputs deliberately have asymmetric coefficients.
fn direct_revdot<F: Field>(a: &[F], b: &[F]) -> F {
    (0..a.len()).map(|d| a[d] * b[a.len() - 1 - d]).sum()
}

fn every_error<F: DeferredField + From<u64>, P: Parameters>() {
    let (n, m) = (P::NumGroups::len(), P::GroupSize::len());
    let width = TestRank::num_coeffs();
    // Include an incomplete last group and an entirely absent last group.
    for count in [0, 1, m - 1, m, m + 1, (n - 1) * m, n * m - 1, n * m] {
        let coefficients = |side: usize| -> Vec<Vec<F>> {
            (0..n * m)
                .map(|k| {
                    (0..width)
                        .map(|d| {
                            if k < count {
                                F::from(((k + 2) * (d + 3 + side) + side * d * d + 1) as u64)
                            } else {
                                F::ZERO
                            }
                        })
                        .collect()
                })
                .collect()
        };
        let a = coefficients(0);
        let b = coefficients(1);
        let polys = |source: &[Vec<F>]| -> Vec<_> {
            source[..count]
                .iter()
                .cloned()
                .map(sparse::Polynomial::<F, TestRank>::from_coeffs)
                .collect()
        };
        let inner = inner_error_terms::<F, TestRank, P>(&polys(&a), &polys(&b));
        for g in 0..n {
            for i in 0..m {
                for j in 0..m {
                    if i == j {
                        continue;
                    }
                    let slot = i * (m - 1) + j - usize::from(j > i);
                    assert_eq!(
                        inner[g][slot],
                        direct_revdot(&a[g * m + i], &b[g * m + j]),
                        "inner producer: count={count}, group={g}, ({i},{j})"
                    );
                }
            }
        }
        // Form each intermediate polynomial without calling fold_inner.
        let direct_groups = |source: &[Vec<F>], scale: F| -> Vec<Vec<F>> {
            (0..n)
                .map(|g| {
                    (0..width)
                        .map(|d| {
                            (0..m)
                                .map(|i| {
                                    source[g * m + i][d] * scale.pow_vartime([(m - 1 - i) as u64])
                                })
                                .sum()
                        })
                        .collect()
                })
                .collect()
        };
        let a_groups = direct_groups(&a, F::from(2).invert().unwrap());
        let b_groups = direct_groups(&b, F::from(6));
        let to_polys = |groups: &[Vec<F>]| -> Vec<_> {
            groups
                .iter()
                .cloned()
                .map(sparse::Polynomial::<F, TestRank>::from_coeffs)
                .collect()
        };
        let outer = outer_error_terms::<F, TestRank, P>(&to_polys(&a_groups), &to_polys(&b_groups));
        for (i, a_group) in a_groups.iter().enumerate() {
            for (j, b_group) in b_groups.iter().enumerate() {
                if i == j {
                    continue;
                }
                let slot = i * (n - 1) + j - usize::from(j > i);
                assert_eq!(
                    outer[slot],
                    direct_revdot(a_group, b_group),
                    "outer producer: count={count}, ({i},{j})"
                );
            }
        }
    }
}

#[test]
fn native_error_coordinates_match_independent_coefficient_arrays() {
    every_error::<Fp, native::RevdotParameters>();
}

#[test]
fn nested_error_coordinates_match_independent_coefficient_arrays() {
    every_error::<Fq, nested::RevdotParameters>();
}
