//! The prover's side of the batch.

use alloc::{borrow::Cow, vec::Vec};

use ragu_backend::Backend;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{FixedGenerators, Result};
use udon::{curve::Affine, field::Field};

use super::{Batch, check_claims};
use crate::{
    compress::revdot::OpeningClaim, ipa::IpaTranscript,
    profile::online::batch::alpha_batched_quotients,
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
    generators: &impl FixedGenerators<C>,
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
    let f_commitment = B::sparse_commit_to_affine(&f, generators);
    transcript.write_point(f_commitment)?;

    let u = transcript.squeeze_challenge()?;
    let evaluations: Vec<_> = B::map(polys.iter(), |poly| poly.eval(u)).collect();
    for value in &evaluations {
        transcript.write_scalar(*value)?;
    }

    // p: f and every polynomial, folded under beta with f weighted highest.
    let beta = transcript.squeeze_challenge()?;
    let mut terms = Vec::with_capacity(polys.len() + 1);
    let mut power = C::Scalar::ONE;
    for poly in polys.iter().rev() {
        terms.push((poly.as_ref(), power));
        power *= beta;
    }
    terms.push((&f, power));
    let p = B::sparse_linear_combination(&terms);

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
