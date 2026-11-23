//! The prover's side of the batch.

use alloc::{borrow::Cow, vec::Vec};

use ragu_backend::Backend;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{FixedGenerators, Result};
use udon::curve::Affine;

use super::{Batch, check_claims};
use crate::{
    backend::committer::Committer, compress::revdot::OpeningClaim, ipa::IpaTranscript,
    profile::online::prover::alpha_batched_quotients,
};

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
pub(crate) fn batch<C: Affine, R: Rank, B: Backend>(
    polys: &[Cow<'_, sparse::Polynomial<C::Scalar, R>>],
    claims: &[OpeningClaim<C::Scalar>],
    committer: &Committer<'_, C, impl FixedGenerators<C>, B>,
    transcript: &mut impl IpaTranscript<C>,
) -> Result<(Batch<C>, Witness<C::Scalar>)> {
    check_claims(claims)?;
    let alpha = transcript.squeeze_challenge()?;

    // f: the quotients of every claim, batched under alpha.
    assert!(!claims.is_empty(), "at least one claim");
    let f = alpha_batched_quotients::<_, R, B>(
        claims
            .iter()
            .map(|claim| (polys[claim.poly].as_ref(), claim.point))
            .collect(),
        alpha,
    );
    let f_commitment = committer.commit(&f);
    transcript.write_point(f_commitment)?;

    let u = transcript.squeeze_challenge()?;
    let evaluations: Vec<_> = B::map(polys.iter(), |poly| poly.eval(u)).collect();
    for value in &evaluations {
        transcript.write_scalar(*value)?;
    }

    // p: f and every polynomial, folded under beta with f weighted highest.
    let beta = transcript.squeeze_challenge()?;
    let p = B::sparse_linear_combination(&sparse::Polynomial::fold_terms(
        core::iter::once(&f).chain(polys.iter().map(AsRef::as_ref)),
        beta,
    ));

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
