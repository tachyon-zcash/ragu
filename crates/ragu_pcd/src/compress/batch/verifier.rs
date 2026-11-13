//! The verifier's side of the batch.

use alloc::vec::Vec;

use ragu_backend::Backend;
use ragu_core::{Error, MsmWorkspace, Result};
use udon::{curve::Affine, field::Field};

use super::{Batch, Batched, check_claims};
use crate::{
    SelectableBackend,
    compress::revdot::{OpeningClaim, Openings},
    ipa::{self, IpaProof, IpaTranscript, MSM, Params},
};

/// Derives the batched commitment, point, and value from `openings` and
/// `batch`, then checks `opening` against that claim through the IPA.
pub(crate) fn verify_openings<P: Affine, B: SelectableBackend>(
    openings: &Openings<P>,
    batch: &Batch<P>,
    opening: &IpaProof<P>,
    params: &Params<P>,
    workspace: &mut MsmWorkspace,
    transcript: &mut impl IpaTranscript<P>,
) -> Result<bool> {
    let claim = verify::<_, B, _>(&openings.commitments, &openings.claims, batch, transcript)?;
    let mut msm = MSM::new(params);
    msm.append_term(P::Scalar::ONE, claim.commitment);
    Ok(
        ipa::verify_proof(params, msm, transcript, opening, claim.point, claim.value)?
            .use_challenges()
            .eval_with_workspace::<B>(workspace),
    )
}

/// The verifier's batch: `commitments` are the polynomials the `claims`
/// refer to. Returns the claim the IPA must prove.
///
/// # Errors
///
/// Fails if claims assign different values to the same polynomial at the
/// same point, if the batch does not carry one value per polynomial, or if
/// $u$ lands on a query point, which happens with negligible probability.
pub(crate) fn verify<C: Affine, B: Backend, T: IpaTranscript<C>>(
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

    check_claims(claims)?;
    let alpha = transcript.squeeze_challenge()?;
    transcript.write_point(batch.f)?;
    let u = transcript.squeeze_challenge()?;
    for &value in &batch.evaluations {
        transcript.write_scalar(value)?;
    }
    let beta = transcript.squeeze_challenge()?;

    // f(u) from the quotient relation, the first claim weighted highest.
    // Repeated query points share one inverse. Keep the original claim
    // order and alpha weights; only the denominator computation is batched.
    let mut points = Vec::new();
    let positions: Vec<_> = claims
        .iter()
        .map(|claim| {
            if let Some(index) = points.iter().position(|point| *point == claim.point) {
                index
            } else {
                points.push(claim.point);
                points.len() - 1
            }
        })
        .collect();
    let mut inverses: Vec<_> = points.iter().map(|point| u - point).collect();
    // Batch inversion leaves zero entries unchanged, but this relation
    // requires every denominator to be invertible.
    if inverses.contains(&C::Scalar::ZERO) {
        return Err(Error::InvalidWitness("u lands on a query point".into()));
    }
    let mut scratch = alloc::vec![C::Scalar::ZERO; inverses.len()];
    C::Scalar::batch_invert(&mut inverses, &mut scratch);
    let mut f_at_u = C::Scalar::ZERO;
    for (claim, position) in claims.iter().zip(positions) {
        f_at_u =
            f_at_u * alpha + (batch.evaluations[claim.poly] - claim.value) * inverses[position];
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
    let commitment = B::msm(&weights, &points).into();

    Ok(Batched {
        commitment,
        point: u,
        value,
    })
}
