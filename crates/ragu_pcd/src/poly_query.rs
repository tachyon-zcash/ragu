//! Polynomial-query claim collection for [`Step`](crate::step::Step) impls.
//!
//! A `Step::witness` impl receives a `pq: &mut PolyQueryClaims<...>` parameter
//! alongside its driver. Steps that need to verify a polynomial-commitment
//! opening — i.e. that the polynomial committed to by `com` evaluates to `y` at
//! point `x` — call `pq.enforce_polynomial_query(dr, com, x, y)`. The framework
//! collects the resulting claims; later, fuse-time code processes them.
//!
//! Steps that don't need polynomial-query verification simply ignore the
//! parameter.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, Point};

/// Records polynomial-commitment opening claims raised by a [`Step::witness`]
/// invocation so that later code (e.g. in `fuse(...)`) can process them.
pub struct PolyQueryClaims<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    claims: Vec<(Point<'dr, D, C>, Element<'dr, D>, Element<'dr, D>)>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> PolyQueryClaims<'dr, D, C> {
    /// Creates a new, empty claim collector.
    pub fn new() -> Self {
        Self { claims: Vec::new() }
    }

    /// Records a claim that the polynomial committed to by `com` evaluates to
    /// `y` at the point `x`.
    pub fn enforce_polynomial_query(
        &mut self,
        _dr: &mut D,
        com: Point<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.claims.push((com, x, y));
        Ok(())
    }

    /// Consumes the collector and returns the recorded claims.
    pub fn into_inner(self) -> Vec<(Point<'dr, D, C>, Element<'dr, D>, Element<'dr, D>)> {
        self.claims
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Default for PolyQueryClaims<'dr, D, C> {
    fn default() -> Self {
        Self::new()
    }
}
