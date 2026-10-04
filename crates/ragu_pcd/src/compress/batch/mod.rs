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

use alloc::vec::Vec;

use ragu_core::{Error, Result};
use udon::{curve::Affine, field::Field};

use super::revdot::OpeningClaim;

mod prover;
mod verifier;

pub(crate) use prover::batch;
#[cfg(test)]
pub(crate) use verifier::verify;
pub(crate) use verifier::verify_openings;

/// The prover's messages of the batch on one curve.
#[derive(Clone, Debug)]
pub(crate) struct Batch<C: Affine> {
    /// The commitment to the quotient polynomial $f$.
    pub f: C,
    /// Each polynomial's value at $u$, in the polynomials' order.
    pub evaluations: Vec<C::Scalar>,
}

/// The one opening claim the batch leaves for the IPA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Batched<C: Affine> {
    /// The commitment to $p$.
    pub commitment: C,
    /// The point $u$.
    pub point: C::Scalar,
    /// The value $v = p(u)$.
    pub value: C::Scalar,
}

/// Rejects conflicting values for the same polynomial index and point.
/// Identical claims remain in the batch, and distinct polynomial indices
/// remain distinct even if their commitments happen to be equal.
fn check_claims<F: Field>(claims: &[OpeningClaim<F>]) -> Result<()> {
    for (i, claim) in claims.iter().enumerate() {
        if claims[..i].iter().any(|previous| {
            previous.poly == claim.poly
                && previous.point == claim.point
                && previous.value != claim.value
        }) {
            return Err(Error::InvalidWitness(
                "conflicting opening values for the same polynomial and point".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/compress_batch.rs"]
mod tests;
