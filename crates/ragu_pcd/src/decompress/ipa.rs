//! The IPA verifier's scalar side as a gadget: the round challenges'
//! inverses, $b = s(x)$ and the scalar each point of the final check
//! carries, over circuit elements.
//!
//! This is the scalar part of [`verify_proof`](crate::ipa::verify_proof).
//! The batched claim's point $x$ and value $v$, the prover's $c$ and the
//! challenges $\xi$, $z$ and $u_j$ arrive as elements, and the gadget
//! returns the scalars of the final check's multi-scalar multiplication.
//! Its points, the prover's $\[S\]$, $L_j$ and $R_j$, the generators and
//! $G' = \langle s, G \rangle$, live on the other curve, so the circuit
//! over their base field forms the multi-scalar multiplication and checks
//! that it is the identity.
//!
//! With $k$ rounds, $s(X) = \prod_{i < k} (1 + u_{k-1-i} X^{2^i})$: $G'$
//! is the commitment to $s$ over the same generators and $b = s(x)$.
//! [`s_at`] evaluates $s$ wherever a circuit needs it, in $2k - 1$ gates,
//! which is how the stage polynomial standing for $s$ will be checked
//! against the round challenges.

use alloc::vec::Vec;

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;

use super::Powers;

/// The prover's scalar message of the IPA: $c$, the final folded
/// coefficient.
pub(crate) struct Messages<'dr, D: Driver<'dr>> {
    pub c: Element<'dr, D>,
}

/// The verifier's challenges of the IPA: $\xi$ folding $\[S\]$ in, $z$
/// weighting $U$, and the round challenges $u_j$ in order.
pub(crate) struct Challenges<'dr, D: Driver<'dr>> {
    pub xi: Element<'dr, D>,
    pub z: Element<'dr, D>,
    pub rounds: Vec<Element<'dr, D>>,
}

/// The scalars of the final check: with the batched commitment weighted
/// by one, the sum of every point under its scalar must be the identity.
pub(crate) struct Scalars<'dr, D: Driver<'dr>> {
    /// The scalar of $G_0$: $-v$.
    pub g_0: Element<'dr, D>,
    /// The scalar of $\[S\]$: $\xi$.
    pub s_commitment: Element<'dr, D>,
    /// Each round's scalars of $L_j$ and $R_j$: $u_j^{-1}$ and $u_j$.
    pub rounds: Vec<(Element<'dr, D>, Element<'dr, D>)>,
    /// The scalar of $U$: $-c b z$.
    pub u: Element<'dr, D>,
    /// The scalar of $G'$: $-c$.
    pub g_prime: Element<'dr, D>,
}

/// $s(\text{point}) = \prod_{i < k} (1 + u_{k-1-i} \cdot \text{point}^{2^i})$
/// over the `rounds`' challenges $u_j$.
pub(crate) fn s_at<'dr, D: Driver<'dr>>(
    dr: &mut D,
    rounds: &[Element<'dr, D>],
    point: &Element<'dr, D>,
) -> Result<Element<'dr, D>> {
    let powers = Powers::new(dr, point, rounds.len() as u32)?;
    let mut product: Option<Element<'dr, D>> = None;
    for (u_j, power) in rounds.iter().rev().zip(powers.squares()) {
        let factor = u_j.mul(dr, power)?.add(dr, &Element::one());
        product = Some(match product {
            None => factor,
            Some(acc) => acc.mul(dr, &factor)?,
        });
    }
    Ok(product.unwrap_or_else(Element::one))
}

/// The scalars of the final check for the claim that the batched
/// polynomial takes `value` at `point`. Witness generation fails on a zero
/// round challenge, which the native verifier rejects too.
pub(crate) fn verify<'dr, D: Driver<'dr>>(
    dr: &mut D,
    point: &Element<'dr, D>,
    value: &Element<'dr, D>,
    challenges: &Challenges<'dr, D>,
    messages: &Messages<'dr, D>,
) -> Result<Scalars<'dr, D>> {
    let mut rounds = Vec::with_capacity(challenges.rounds.len());
    for u_j in &challenges.rounds {
        rounds.push((u_j.invert(dr)?, u_j.clone()));
    }
    let b = s_at(dr, &challenges.rounds, point)?;
    let neg_c = messages.c.negate(dr);
    let u = neg_c.mul(dr, &b)?.mul(dr, &challenges.z)?;
    Ok(Scalars {
        g_0: value.negate(dr),
        s_commitment: challenges.xi.clone(),
        rounds,
        u,
        g_prime: neg_c,
    })
}

#[cfg(test)]
#[path = "../../tests/decompress_ipa.rs"]
mod tests;
