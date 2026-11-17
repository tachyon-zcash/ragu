//! Common abstraction for orchestrating revdot claims.
//!
//! # Revdot claims
//!
//! A **revdot claim** asserts that two polynomials $a(X)$ and $b(X)$ satisfy
//! a reversed inner product on their coefficient vectors (see
//! [`sparse::Polynomial::revdot`]). In the proof system, each circuit stage
//! produces a claim of the form
//!
//! $$\operatorname{revdot}(a(X), b(X)) = k(Y),$$
//!
//! where $k(Y)$ is the public-input polynomial restricted at a verifier
//! challenge. Verifiers check these claims, and the folding machinery reduces
//! many such claims into a single claim plus a bounded set of error terms.
//!
//! This module provides helpers to build the $(a, b)$ pairs for each claim
//! and to aggregate them across proof components.

use alloc::borrow::Cow;

use ragu_circuits::polynomials::{Rank, sparse};
use udon::field::Field;

/// Sum an iterator of polynomials, borrowing if only one element.
///
/// Returns `Cow::Borrowed` for a single polynomial, `Cow::Owned` for multiple.
/// Panics if the iterator is empty.
pub fn sum_polynomials<'rx, F: Field, R: Rank>(
    mut rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
) -> Cow<'rx, sparse::Polynomial<F, R>> {
    let first = rxs.next().expect("must provide at least one rx polynomial");
    match rxs.next() {
        None => Cow::Borrowed(first),
        Some(second) => {
            let mut sum = first.clone();
            sum.add_assign(second);
            for rx in rxs {
                sum.add_assign(rx);
            }
            Cow::Owned(sum)
        }
    }
}

/// Trait for providing claim component values from sources.
///
/// This trait abstracts over what a "source" provides. For polynomial contexts
/// (verify, fuse), it provides polynomial references. For evaluation contexts
/// (`compute_v`), it provides single element evaluations (at $xz$).
///
/// Implementors provide access to rx values for all proofs they manage. The
/// `RxComponent` associated type defines which components can be requested.
pub trait Source {
    /// The type identifying which rx component to retrieve.
    type RxComponent: Copy;

    /// Opaque type for rx values.
    type Rx;

    /// Type for application circuit identifiers.
    type AppCircuitId;

    /// Get an iterator over rx values for all proofs for the given component.
    fn rx(&self, component: Self::RxComponent) -> impl Iterator<Item = Self::Rx>;

    /// Get an iterator over application circuit info for all proofs.
    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId>;
}
