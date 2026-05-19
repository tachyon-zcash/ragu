//! Context object threaded through [`Step::witness`](super::Step::witness).
//!
//! Bundles the framework-side state — the [`Driver`] and the
//! [`PolyQueryClaims`] sink — so that reusable sub-components called from a
//! step body can take a single `&mut StepCtx` rather than juggling individual
//! arguments. New framework hooks added in the future (e.g. transcript
//! threading) belong on this type as well.

use ragu_arithmetic::{CurveAffine, PoseidonPermutation};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, Point, poseidon::Sponge};

use crate::poly_query::PolyQueryClaims;

/// Framework-side state threaded through [`Step::witness`](super::Step::witness).
///
/// `dr` is exposed directly because callers routinely need it for allocator
/// calls and gadget construction. The poly-query claim sink is exposed via
/// [`enforce_poly_query`](Self::enforce_poly_query) so the framework can keep
/// the underlying claim representation flexible.
pub struct StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
{
    /// The underlying driver. Components called from a step body use this for
    /// allocation and constraint emission.
    pub dr: &'a mut D,
    pq: &'a mut PolyQueryClaims<'dr, D, C>,
}

impl<'a, 'dr, D, C> StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
{
    pub(crate) fn new(dr: &'a mut D, pq: &'a mut PolyQueryClaims<'dr, D, C>) -> Self {
        Self { dr, pq }
    }

    /// Records a poly-query claim: the polynomial committed to by `com`
    /// evaluates to `y` at the point `x`. The framework collects these via the
    /// adapter's `Aux` for later fuse-time verification.
    pub fn enforce_poly_query(
        &mut self,
        com: Point<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.pq.enforce_polynomial_query(self.dr, com, x, y)
    }

    /// Squeezes a challenge field element from `sponge` using this context's
    /// driver. Callers are responsible for having absorbed every value the
    /// challenge needs to be bound to before calling this.
    ///
    /// The sponge is passed in explicitly rather than carried on `StepCtx`:
    /// transcript threading at the adapter level is intentional follow-up work,
    /// not part of this slice.
    pub fn derive_challenge<P: PoseidonPermutation<D::F>>(
        &mut self,
        sponge: &mut Sponge<'dr, D, P>,
    ) -> Result<Element<'dr, D>> {
        sponge.squeeze(self.dr)
    }
}
