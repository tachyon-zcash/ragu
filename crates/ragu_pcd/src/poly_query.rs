//! Polynomial-query verification interface for [`Step`](crate::step::Step)
//! implementations.
//!
//! A `Step::witness` impl receives a `pq: &mut Q` parameter alongside its
//! driver. Steps that need to verify a polynomial-commitment opening — i.e.
//! that the polynomial committed to by `com` evaluates to `y` at point `x` —
//! call `pq.enforce_polynomial_query(...)`. Steps that don't need this
//! capability simply ignore the parameter.
//!
//! The framework path through `step::internal::adapter::Adapter` passes
//! [`NoPolyQuery`], whose impl returns an error; callers that need to drive
//! `OpenAndHash`-style steps must invoke `Step::witness` with their own
//! `PolyQuery` implementation.

use ragu_arithmetic::CurveAffine;
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, Point};

/// Verifies polynomial-commitment query claims inside a circuit.
pub trait PolyQuery<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Enforces that the polynomial committed to by `com` evaluates to `y` at
    /// the point `x`.
    fn enforce_polynomial_query(
        &mut self,
        dr: &mut D,
        com: Point<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()>;
}

/// No-op [`PolyQuery`] implementation. Used by callers that don't drive any
/// `Step` requiring polynomial queries; if such a step does invoke
/// `enforce_polynomial_query`, the call returns an error rather than silently
/// skipping the constraint.
pub struct NoPolyQuery;

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> PolyQuery<'dr, D, C> for NoPolyQuery {
    fn enforce_polynomial_query(
        &mut self,
        _dr: &mut D,
        _com: Point<'dr, D, C>,
        _x: Element<'dr, D>,
        _y: Element<'dr, D>,
    ) -> Result<()> {
        Err(ragu_core::Error::Initialization(
            "step invoked enforce_polynomial_query but caller passed NoPolyQuery".into(),
        ))
    }
}
