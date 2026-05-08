//! Polynomial-query opening claims raised by [`Step`](crate::step::Step) impls.
//!
//! A `Step::witness` impl returns a `Vec<PolyQueryClaim<...>>` alongside its
//! other outputs. Each claim asserts that the polynomial committed to by `com`
//! evaluates to `y` at the point `x`. The framework collects these claims for
//! later fuse-time processing. Steps that don't need polynomial-query
//! verification return an empty `Vec`.

use ragu_arithmetic::CurveAffine;
use ragu_core::drivers::Driver;
use ragu_primitives::{Element, Point};

/// A polynomial-commitment opening claim: the polynomial committed to by `com`
/// evaluates to `y` at the point `x`.
pub struct PolyQueryClaim<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Commitment to the polynomial.
    pub com: Point<'dr, D, C>,
    /// Evaluation point.
    pub x: Element<'dr, D>,
    /// Claimed value of the polynomial at `x`.
    pub y: Element<'dr, D>,
}
