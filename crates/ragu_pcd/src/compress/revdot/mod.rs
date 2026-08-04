//! Reduction 1: from revdot claims to polynomial openings.
//!
//! The [`fold`] first collapses the claims on one curve to three, $(A, B)$
//! and one $(E, W)$ per layer, committing each layer's error terms before
//! its challenges. The split then takes those three as $t(X) = \sum_i
//! \rho^i a_i(X) b_i(X)$, splits it as $t(X) = X^{n-1} p(1/X) + X^n q(X)$,
//! so that $p(0) = \sum_i \rho^i \operatorname{revdot}(a_i, b_i)$, and
//! commits to $p$ and $q$. The verifier squeezes $r$ and checks $\sum_i
//! \rho^i a_i(r) b_i(r) = r^{n-1} p(1/r) + r^n q(r)$ from the claimed
//! openings, then hands every opening it relied on to the batch: each
//! [`Derived`] polynomial at its point, $p$ at $1/r$ and at $0$, where it
//! must equal $\sum_i \rho^i k_i$, and $q$ at $r$.
//!
//! Both sides take the claims in the decider's order, the prover through
//! [`claims::Builder`](crate::internal::claims::Builder) and the verifier
//! through the [`claims`]' shapes.
//!
//! The transcript is assumed to have seen the commitments the claims are
//! over, and $y$ and $z$ to have been squeezed from it.

use alloc::vec::Vec;

use ragu_core::{Error, Result};
use udon::{curve::Affine, field::Field};

use self::fold::{Derived, Fold};
use super::POLYS;
use crate::internal::{native, nested};

pub(crate) mod claims;
pub(crate) mod fold;
mod prover;
mod verifier;

pub(crate) use prover::{reduce_native, reduce_nested};
pub(crate) use verifier::{verify_native, verify_nested};

/// An opening claim: the polynomial at `poly` in an [`Openings`]' list takes
/// `value` at `point`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpeningClaim<F> {
    pub poly: usize,
    pub point: F,
    pub value: F,
}

/// The opening claims a reduction leaves for the batch, over the committed
/// polynomials they refer to: the [`Derived`] polynomials in order, then
/// $p$, then $q$.
#[derive(Clone, Debug)]
pub(crate) struct Openings<C: Affine> {
    pub commitments: Vec<C>,
    pub claims: Vec<OpeningClaim<C::Scalar>>,
}

/// The prover's messages of the reduction on one curve.
#[derive(Clone, Debug)]
pub(crate) struct Reduction<C: Affine> {
    /// The fold's.
    pub fold: Fold<C>,
    /// The commitment to $p$.
    pub p: C,
    /// The commitment to $q$.
    pub q: C,
    /// Each [`Derived`] polynomial's claimed opening at its point, in
    /// order.
    pub openings: Vec<C::Scalar>,
    /// The claimed $p(1/r)$.
    pub p_at_inverse_r: C::Scalar,
    /// The claimed $q(r)$.
    pub q_at_r: C::Scalar,
}

/// The native components in the order the instance lists their
/// commitments.
pub(crate) fn native_components() -> impl Iterator<Item = native::RxComponent> {
    [native::RxComponent::AbA, native::RxComponent::AbB]
        .into_iter()
        .chain(native::RxIndex::all(POLYS).map(native::RxComponent::Rx))
}

/// The position of a native component in [`native_components`].
pub(crate) fn native_position(component: native::RxComponent) -> usize {
    match component {
        native::RxComponent::AbA => 0,
        native::RxComponent::AbB => 1,
        native::RxComponent::Rx(index) => 2 + index.position(POLYS),
    }
}

/// The nested components in the order the instance lists their
/// commitments.
pub(crate) fn nested_components() -> impl Iterator<Item = nested::RxComponent> {
    [nested::RxComponent::AbA, nested::RxComponent::AbB]
        .into_iter()
        .chain(nested::RxIndex::all(POLYS).map(nested::RxComponent::Rx))
}

/// The position of a nested component in [`nested_components`].
pub(crate) fn nested_position(component: nested::RxComponent) -> usize {
    match component {
        nested::RxComponent::AbA => 0,
        nested::RxComponent::AbB => 1,
        nested::RxComponent::Rx(index) => 2 + index.position(POLYS),
    }
}

/// The opening claims a reduction leaves over `commitments`, the
/// [`Derived`] polynomials' in order: each at its point, $p$ at $1/r$, $q$
/// at $r$, and $p$ at $0$, where it must equal `target`.
fn openings<C: Affine>(
    mut commitments: Vec<C>,
    reduction: &Reduction<C>,
    r: C::Scalar,
    z: C::Scalar,
    inverse_r: C::Scalar,
    target: C::Scalar,
) -> Openings<C> {
    let (p, q) = (commitments.len(), commitments.len() + 1);
    let mut claims = Vec::with_capacity(commitments.len() + 3);
    for (poly, (derived, &value)) in Derived::ALL.iter().zip(&reduction.openings).enumerate() {
        claims.push(OpeningClaim {
            poly,
            point: derived.point(r, z),
            value,
        });
    }
    claims.push(OpeningClaim {
        poly: p,
        point: inverse_r,
        value: reduction.p_at_inverse_r,
    });
    claims.push(OpeningClaim {
        poly: q,
        point: r,
        value: reduction.q_at_r,
    });
    claims.push(OpeningClaim {
        poly: p,
        point: C::Scalar::ZERO,
        value: target,
    });
    commitments.push(reduction.p);
    commitments.push(reduction.q);
    Openings {
        commitments,
        claims,
    }
}

/// The inverse of a challenge, which is zero with negligible probability.
fn invert<F: Field>(value: F) -> Result<F> {
    value
        .invert()
        .ok_or_else(|| Error::InvalidWitness("a zero challenge cannot be inverted".into()))
}

#[cfg(test)]
#[path = "../../../tests/compress_revdot.rs"]
mod tests;
