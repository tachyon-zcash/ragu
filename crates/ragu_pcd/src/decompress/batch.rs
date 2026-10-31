//! The batch's verifier as a gadget: $f(u)$ from the quotient relation,
//! the batched value $v$ and the weights of the batched commitment, over
//! circuit elements.
//!
//! This is the [`compress::batch`](crate::compress::batch) verifier over
//! [`Element`]s, given the opening claims the reduction left and the
//! instance's, the prover's values at $u$ and the challenges. The claims'
//! points and values are elements, their polynomial indices constants: the
//! batched commitment is the weighted sum of $\[f\]$ and the polynomials'
//! commitments under the returned weights, which a circuit over the other
//! field forms. The native verifier rejects two claims on one polynomial
//! and point with different values; the protocol's claim lists never
//! repeat a pair, so the gadget takes the lists as they are.

use alloc::vec::Vec;
use core::iter::once;

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;

use super::consecutive_powers;
use crate::compress::revdot::OpeningClaim;

/// The prover's scalar messages of the batch on one curve: each
/// polynomial's value at $u$, in the polynomials' order.
pub(crate) struct Messages<'dr, D: Driver<'dr>> {
    pub evaluations: Vec<Element<'dr, D>>,
}

/// The verifier's challenges of the batch: $\alpha$ weighting the
/// quotients, $u$ the point, $\beta$ weighting the polynomials.
pub(crate) struct Challenges<'dr, D: Driver<'dr>> {
    pub alpha: Element<'dr, D>,
    pub u: Element<'dr, D>,
    pub beta: Element<'dr, D>,
}

/// The one opening claim the batch leaves for the IPA, less its
/// commitment: the point $u$, the value $v$, and the weights of $\[f\]$ and
/// the polynomials' commitments in the batched commitment, $\[f\]$'s first
/// and highest.
pub(crate) struct Batched<'dr, D: Driver<'dr>> {
    pub point: Element<'dr, D>,
    pub value: Element<'dr, D>,
    pub weights: Vec<Element<'dr, D>>,
}

/// The batch on one curve over `claims`, whose polynomial indices lie
/// below `polys`, the number of committed polynomials. Witness generation
/// fails if $u$ lands on a claim's point, which the native verifier
/// rejects too.
///
/// # Panics
///
/// Panics unless `messages` holds one value per polynomial, which is
/// checked before allocation, or if a claim names a polynomial beyond
/// `polys`.
pub(crate) fn verify<'dr, D: Driver<'dr>>(
    dr: &mut D,
    claims: &[OpeningClaim<Element<'dr, D>>],
    polys: usize,
    challenges: &Challenges<'dr, D>,
    messages: &Messages<'dr, D>,
) -> Result<Batched<'dr, D>> {
    assert_eq!(
        messages.evaluations.len(),
        polys,
        "one value per batched polynomial"
    );
    let u = &challenges.u;

    // f(u) from the quotient relation, the first claim weighted highest.
    let mut quotients = Vec::with_capacity(claims.len());
    for claim in claims {
        let evaluation = &messages.evaluations[claim.poly];
        let numerator = evaluation.sub(dr, &claim.value);
        let denominator = u.sub(dr, &claim.point).invert(dr)?;
        quotients.push(numerator.mul(dr, &denominator)?);
    }
    let f_at_u = Element::fold(dr, &quotients, &challenges.alpha)?;

    // v: f and every polynomial under beta, f weighted highest; and the
    // same weights for the commitments.
    let value = Element::fold(
        dr,
        once(&f_at_u).chain(&messages.evaluations),
        &challenges.beta,
    )?;
    let mut weights = consecutive_powers(dr, &challenges.beta, polys + 1)?;
    weights.reverse();

    Ok(Batched {
        point: u.clone(),
        value,
        weights,
    })
}

#[cfg(test)]
#[path = "../../tests/decompress_batch.rs"]
mod tests;
