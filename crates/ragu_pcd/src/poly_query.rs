//! Polynomial-query claim collection for [`Step`](crate::step::Step) impls.
//!
//! A `Step::witness` impl receives a `pq: &mut PolyQueryClaims<...>`
//! parameter alongside its driver. Steps that need to verify a
//! polynomial-commitment opening — i.e. that the polynomial committed to by
//! `com` evaluates to `y` at point `x` — call
//! `pq.enforce_polynomial_query(dr, com, x, y)`. The framework collects the
//! resulting claims through the adapter's `Aux` for later fuse-time
//! processing. Steps that don't need polynomial-query verification simply
//! ignore the parameter.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, Point};

/// Sink for polynomial-commitment opening claims raised by a
/// [`Step::witness`](crate::step::Step::witness) invocation.
///
/// Wires aren't carried out of `witness()`, so each recorded claim's
/// `(com, x, y)` values are extracted up-front and accumulated into a single
/// `DriverValue`. The framework's adapter constructs this sink, passes it to
/// the step, then surfaces [`into_inner`](Self::into_inner) through its
/// `Aux` for later fuse-time processing.
pub struct PolyQueryClaims<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    claims: DriverValue<D, Vec<(C, D::F, D::F)>>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> PolyQueryClaims<'dr, D, C> {
    /// Creates a new, empty claim collector.
    pub fn new() -> Self {
        Self {
            claims: D::just(Vec::new),
        }
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
        let triple =
            D::try_just(|| Ok((com.value().take(), *x.value().take(), *y.value().take())))?;
        let current = core::mem::replace(&mut self.claims, D::just(Vec::new));
        self.claims = current.and_then(|mut v| {
            triple.map(|t| {
                v.push(t);
                v
            })
        });
        Ok(())
    }

    /// Consumes the sink and returns the accumulated claim values.
    pub fn into_inner(self) -> DriverValue<D, Vec<(C, D::F, D::F)>> {
        self.claims
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Default for PolyQueryClaims<'dr, D, C> {
    fn default() -> Self {
        Self::new()
    }
}
