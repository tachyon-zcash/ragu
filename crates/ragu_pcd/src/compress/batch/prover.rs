//! The prover's side of the batch.

use alloc::{borrow::Cow, vec::Vec};

use ragu_backend::Backend;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{FixedGenerators, Result};
use udon::{curve::Affine, field::Field, polynomial::divide_linear_rev};

use super::{Batch, check_claims};
use crate::{compress::revdot::OpeningClaim, ipa::IpaTranscript};

/// What the prover keeps to open the batched claim.
pub(crate) struct Witness<F> {
    /// $p$, the polynomial the IPA opens, with $n$ coefficients.
    pub p: Vec<F>,
    /// The point $u$ it opens it at.
    pub u: F,
}

/// The prover's batch: `polys` are the committed polynomials the `claims`
/// refer to, in the order their commitments are listed.
///
/// # Errors
///
/// Fails if claims assign different values to the same polynomial at the
/// same point, or if a transcript operation fails.
pub(crate) fn batch<C: Affine, R: Rank, B: Backend, T: IpaTranscript<C>>(
    polys: &[Cow<'_, sparse::Polynomial<C::Scalar, R>>],
    claims: &[OpeningClaim<C::Scalar>],
    generators: &impl FixedGenerators<C>,
    transcript: &mut T,
) -> Result<(Batch<C>, Witness<C::Scalar>)> {
    check_claims(claims)?;
    let alpha = transcript.squeeze_challenge()?;

    // f: the quotients of every claim, batched under alpha.
    let quotients = claims
        .iter()
        .map(|claim| divide_linear_rev(polys[claim.poly].iter_coeffs(), claim.point))
        .collect::<Vec<_>>();
    let f = batched_quotients::<_, R>(quotients, alpha);
    let f_commitment = B::sparse_commit_to_affine(&f, generators);
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
/// [`divide_linear_rev`] yields them, under $\alpha$: the first stream
/// receives the highest power.
fn batched_quotients<F: Field, R: Rank>(
    mut streams: Vec<impl Iterator<Item = F>>,
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
