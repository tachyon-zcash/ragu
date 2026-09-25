//! Reduction 2: from many openings to one.
//!
//! Given opening claims $p_i(x_i) = y_i$ over committed polynomials, the
//! prover commits to the quotient polynomial $f = \sum_i \alpha^{n-1-i}
//! (p_i - y_i) / (X - x_i)$, the verifier squeezes $u$, the prover sends
//! every polynomial's value at $u$, the verifier squeezes $\beta$, and both
//! fold $f$ and the polynomials under $\beta$, $f$ weighted highest, into
//! one polynomial $p$ opened at $u$: the verifier derives its commitment
//! from the commitments and its value $v$ from the quotient relation and the
//! sent values, and the IPA proves $p(u) = v$.
//!
//! This is the fuse's batch, run natively over an arbitrary claim list, with
//! the same weights the fuse's `compute_f` and `compute_p` phases use.

use alloc::{borrow::Cow, boxed::Box, vec::Vec};

use ragu_arithmetic::{CurveAffine, FixedGenerators, factor_iter, ff::Field, msm};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Error, Result};

use super::revdot::OpeningClaim;
use crate::ipa::IpaTranscript;

/// The prover's messages of the batch on one curve.
#[derive(Clone, Debug)]
pub(crate) struct Batch<C: CurveAffine> {
    /// The commitment to the quotient polynomial $f$.
    pub f: C,
    /// Each polynomial's value at $u$, in the polynomials' order.
    pub evaluations: Vec<C::Scalar>,
}

/// The one opening claim the batch leaves for the IPA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Batched<C: CurveAffine> {
    /// The commitment to $p$.
    pub commitment: C,
    /// The point $u$.
    pub point: C::Scalar,
    /// The value $v = p(u)$.
    pub value: C::Scalar,
}

/// What the prover keeps to open the batched claim.
pub(crate) struct Witness<F> {
    /// $p$, the polynomial the IPA opens, with $n$ coefficients.
    pub p: Vec<F>,
    /// The point $u$ it opens it at.
    pub u: F,
}

/// The prover's batch: `polys` are the committed polynomials the `claims`
/// refer to, in the order their commitments are listed.
pub(crate) fn batch<C: CurveAffine, R: Rank, T: IpaTranscript<C>>(
    polys: &[Cow<'_, sparse::Polynomial<C::Scalar, R>>],
    claims: &[OpeningClaim<C::Scalar>],
    generators: &impl FixedGenerators<C>,
    transcript: &mut T,
) -> Result<(Batch<C>, Witness<C::Scalar>)> {
    let alpha = transcript.squeeze_challenge()?;

    // f: the quotients of every claim, batched under alpha.
    let quotients = claims
        .iter()
        .map(|claim| factor_iter(polys[claim.poly].iter_coeffs(), claim.point))
        .collect();
    let f = batched_quotients::<_, R>(quotients, alpha);
    let f_commitment = f.commit_to_affine(generators);
    transcript.write_point(f_commitment)?;

    let u = transcript.squeeze_challenge()?;
    let mut evaluations = Vec::with_capacity(polys.len());
    for poly in polys {
        let value = poly.eval(u);
        transcript.write_scalar(value)?;
        evaluations.push(value);
    }

    // p: f and every polynomial, folded under beta with f weighted highest.
    let beta = transcript.squeeze_challenge()?;
    let mut p = f;
    for poly in polys {
        p.scale(beta);
        p.add_assign(poly);
    }

    Ok((
        Batch {
            f: f_commitment,
            evaluations,
        },
        Witness {
            p: p.iter_coeffs().collect(),
            u,
        },
    ))
}

/// Horner-batches quotient coefficient streams, highest degree first as
/// [`factor_iter`] yields them, under $\alpha$: the first stream receives the
/// highest power.
fn batched_quotients<F: Field, R: Rank>(
    mut streams: Vec<Box<dyn Iterator<Item = F> + '_>>,
    alpha: F,
) -> sparse::Polynomial<F, R> {
    let mut coeffs = Vec::with_capacity(R::num_coeffs());
    let (first, rest) = streams.split_first_mut().expect("at least one claim");
    for coeff in first.by_ref() {
        let batched = rest.iter_mut().fold(coeff, |acc, stream| {
            alpha * acc + stream.next().expect("streams have equal length")
        });
        coeffs.push(batched);
    }
    coeffs.reverse();
    sparse::Polynomial::from_coeffs(coeffs)
}

/// The verifier's batch: `commitments` are the polynomials the `claims`
/// refer to. Returns the claim the IPA must prove.
///
/// # Errors
///
/// Fails if the batch does not carry one value per polynomial, or if $u$
/// lands on a query point, which happens with negligible probability.
pub(crate) fn verify<C: CurveAffine, T: IpaTranscript<C>>(
    commitments: &[C],
    claims: &[OpeningClaim<C::Scalar>],
    batch: &Batch<C>,
    transcript: &mut T,
) -> Result<Batched<C>> {
    if batch.evaluations.len() != commitments.len() {
        return Err(Error::InvalidWitness(
            "one value per batched polynomial".into(),
        ));
    }

    let alpha = transcript.squeeze_challenge()?;
    transcript.write_point(batch.f)?;
    let u = transcript.squeeze_challenge()?;
    for &value in &batch.evaluations {
        transcript.write_scalar(value)?;
    }
    let beta = transcript.squeeze_challenge()?;

    // f(u) from the quotient relation, the first claim weighted highest.
    let mut f_at_u = C::Scalar::ZERO;
    for claim in claims {
        let denominator = Option::<C::Scalar>::from((u - claim.point).invert())
            .ok_or_else(|| Error::InvalidWitness("u lands on a query point".into()))?;
        f_at_u = f_at_u * alpha + (batch.evaluations[claim.poly] - claim.value) * denominator;
    }

    // v and the commitment to p: f and every polynomial under beta, f
    // weighted highest.
    let mut value = f_at_u;
    for &evaluation in &batch.evaluations {
        value = value * beta + evaluation;
    }
    let mut weights = Vec::with_capacity(commitments.len() + 1);
    let mut weight = C::Scalar::ONE;
    for _ in 0..=commitments.len() {
        weights.push(weight);
        weight *= beta;
    }
    weights.reverse();
    let points: Vec<C> = core::iter::once(batch.f)
        .chain(commitments.iter().copied())
        .collect();
    let commitment = msm(&weights, &points).into();

    Ok(Batched {
        commitment,
        point: u,
        value,
    })
}

#[cfg(test)]
#[path = "../../tests/compress_batch.rs"]
mod tests;
