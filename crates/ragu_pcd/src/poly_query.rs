//! Polynomial-query claim collection for [`Step`](crate::step::Step) impls.
//!
//! A step that needs to verify a polynomial-commitment opening — i.e. that
//! the polynomial committed to by `com` evaluates to `y` at point `x` —
//! constructs a [`PolyQueryClaims`] inside its `witness()` implementation,
//! records each opening via [`PolyQueryClaims::enforce_polynomial_query`],
//! and surfaces the recorded claims through its [`Step::Aux`] by returning
//! [`PolyQueryClaims::into_inner`]. Later fuse-time code consumes the claims
//! through the same `Aux` channel.
//!
//! [`Step::Aux`]: crate::step::Step::Aux

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, Point};

/// Builder that records polynomial-commitment opening claims as plain
/// `(com, x, y)` value triples for inclusion in a step's [`Aux`].
///
/// Wires aren't carried out of `witness()`, so the recorded claim values are
/// extracted up-front and accumulated into a single `DriverValue` that the
/// step returns via [`into_inner`](Self::into_inner).
///
/// [`Aux`]: crate::step::Step::Aux
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
        let triple = D::try_just(|| {
            Ok((
                com.value().take(),
                *x.value().take(),
                *y.value().take(),
            ))
        })?;
        let current = core::mem::replace(&mut self.claims, D::just(Vec::new));
        self.claims = current.and_then(|mut v| {
            triple.map(|t| {
                v.push(t);
                v
            })
        });
        Ok(())
    }

    /// Consumes the builder and returns the accumulated claim values, suitable
    /// for inclusion in a step's `Aux`.
    pub fn into_inner(self) -> DriverValue<D, Vec<(C, D::F, D::F)>> {
        self.claims
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Default for PolyQueryClaims<'dr, D, C> {
    fn default() -> Self {
        Self::new()
    }
}
