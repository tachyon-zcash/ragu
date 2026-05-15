//! Step execution context, abstracting the driver and optional capability
//! sinks like [`PolyQueryClaims`].
//!
//! Every step receives a single `cx: &mut Self::Context<...>` argument.
//! The base [`Cx`] trait always exposes the driver via
//! [`Cx::driver`]. Steps that record polynomial-commitment opening claims
//! pick a context implementing [`HasPolyQuery`] and call
//! [`HasPolyQuery::split_pq`] to get simultaneous mutable borrows of the
//! driver and the claim sink.
//!
//! Two concrete contexts are provided:
//!
//! - [`BasicCx`]: driver only.
//! - [`PolyCx`]: driver plus a [`PolyQueryClaims`] sink.
//!
//! Each [`Step`](super::Step) implementation picks its required context
//! via the `Step::Context` associated type. Whether `PolyQueryClaims` is
//! reachable is a compile-time property of the chosen context type —
//! `BasicCx` doesn't implement `HasPolyQuery`, so a step that opted out
//! of the capability cannot call `split_pq`.
//!
//! Custom context types are supported by implementing [`Cx`] (and
//! optionally [`HasPolyQuery`]) plus [`MakeCx`], which tells the
//! framework how to build the context from the driver and claim sink it
//! supplies at each step invocation.

use ragu_arithmetic::CurveAffine;
use ragu_core::drivers::Driver;

use crate::poly_query::PolyQueryClaims;

/// Base step execution context: always exposes the driver.
pub trait Cx<'dr> {
    /// The driver type carried by this context.
    type D: Driver<'dr>;

    /// Returns a mutable borrow of the driver.
    fn driver(&mut self) -> &mut Self::D;
}

/// Context capability for recording polynomial-commitment opening claims.
///
/// Step impls that need to record claims bound their context as
/// `Cx: HasPolyQuery<'dr, C::NestedCurve>` and call
/// [`split_pq`](Self::split_pq) to get the driver and claim sink as
/// disjoint mutable borrows. Pass them to
/// [`PolyQueryClaims::enforce_polynomial_query`] to record a claim.
pub trait HasPolyQuery<'dr, C>: Cx<'dr>
where
    C: CurveAffine<Base = <Self::D as Driver<'dr>>::F>,
{
    /// Returns simultaneous mutable borrows of the driver and the
    /// poly-query claim sink.
    fn split_pq(&mut self) -> (&mut Self::D, &mut PolyQueryClaims<'dr, Self::D, C>);
}

/// Construct a context from the framework-supplied driver and
/// poly-query sink.
///
/// The default [`Step::make_cx`](super::Step::make_cx) implementation
/// delegates here. Contexts that don't need the claim sink ignore the
/// second argument; contexts that do retain it.
pub trait MakeCx<'a, 'dr, D, C>: Sized
where
    'dr: 'a,
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
{
    /// Build the context.
    fn make(dr: &'a mut D, pq: &'a mut PolyQueryClaims<'dr, D, C>) -> Self;
}

/// Context carrying only the driver. Use when a step does not record
/// polynomial-commitment claims.
pub struct BasicCx<'a, D> {
    dr: &'a mut D,
}

impl<'a, D> BasicCx<'a, D> {
    /// Wrap a driver borrow into a [`BasicCx`].
    pub fn new(dr: &'a mut D) -> Self {
        Self { dr }
    }
}

impl<'a, 'dr, D: Driver<'dr>> Cx<'dr> for BasicCx<'a, D> {
    type D = D;
    fn driver(&mut self) -> &mut D {
        &mut *self.dr
    }
}

impl<'a, 'dr, D, C> MakeCx<'a, 'dr, D, C> for BasicCx<'a, D>
where
    'dr: 'a,
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
{
    fn make(dr: &'a mut D, _pq: &'a mut PolyQueryClaims<'dr, D, C>) -> Self {
        BasicCx::new(dr)
    }
}

/// Context carrying both the driver and a [`PolyQueryClaims`] sink.
/// Use when a step records polynomial-commitment opening claims.
pub struct PolyCx<'a, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    dr: &'a mut D,
    pq: &'a mut PolyQueryClaims<'dr, D, C>,
}

impl<'a, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> PolyCx<'a, 'dr, D, C> {
    /// Wrap driver and claim-sink borrows into a [`PolyCx`].
    pub fn new(dr: &'a mut D, pq: &'a mut PolyQueryClaims<'dr, D, C>) -> Self {
        Self { dr, pq }
    }
}

impl<'a, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Cx<'dr> for PolyCx<'a, 'dr, D, C> {
    type D = D;
    fn driver(&mut self) -> &mut D {
        &mut *self.dr
    }
}

impl<'a, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> HasPolyQuery<'dr, C>
    for PolyCx<'a, 'dr, D, C>
{
    fn split_pq(&mut self) -> (&mut D, &mut PolyQueryClaims<'dr, D, C>) {
        (&mut *self.dr, &mut *self.pq)
    }
}

impl<'a, 'dr, D, C> MakeCx<'a, 'dr, D, C> for PolyCx<'a, 'dr, D, C>
where
    'dr: 'a,
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
{
    fn make(dr: &'a mut D, pq: &'a mut PolyQueryClaims<'dr, D, C>) -> Self {
        PolyCx::new(dr, pq)
    }
}
