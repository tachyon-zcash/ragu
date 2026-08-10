//! Context object threaded through [`Step::witness`](super::Step::witness).
//!
//! Bundles the framework-side state — the [`Driver`] and the
//! [`FrameworkHooks`] container — so that reusable sub-components called from
//! a step body can take a single `&mut StepCtx` rather than juggling
//! individual arguments. The poly-query claim sink is exposed via
//! [`enforce_poly_query`](StepCtx::enforce_poly_query) and the challenge hook
//! via [`derive_challenge`](StepCtx::derive_challenge). New framework hooks
//! added in the future (e.g. transcript threading) belong on [`FrameworkHooks`]
//! as well.

use ragu_arithmetic::CurveAffine;
use ragu_core::{Result, drivers::Driver, gadgets::Gadget};
use ragu_primitives::{Element, Point};

use crate::framework_hooks::FrameworkHooks;

/// Framework-side state threaded through [`Step::witness`](super::Step::witness).
/// The poly-query claim sink is exposed via
/// [`enforce_poly_query`](Self::enforce_poly_query)
pub struct StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
{
    /// The underlying driver. Components called from a step body use this for
    /// allocation and constraint emission.
    pub dr: &'a mut D,
    hooks: &'a mut FrameworkHooks<'dr, D, C>,
}

impl<'a, 'dr, D, C> StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
{
    pub(crate) fn new(dr: &'a mut D, hooks: &'a mut FrameworkHooks<'dr, D, C>) -> Self {
        Self { dr, hooks }
    }

    /// Records a poly-query claim: the polynomial committed to by `com` (a nested curve point)
    /// evaluates to `y` at the point `x`. The framework collects these via the
    /// adapter's `Aux` for later fuse-time verification.
    pub fn enforce_poly_query(
        &mut self,
        com: Point<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.hooks.enforce_polynomial_query(self.dr, com, x, y)
    }

    /// Derives a challenge from `gadget`. Returns a nested-curve `point` (a
    /// Pedersen commitment to the gadget's wires) and the derived challenge as
    /// an `Element` (the Poseidon hash of that point). The framework performs
    /// the real derivation outside the circuit — the caller never instantiates
    /// or reasons about a sponge.
    pub fn derive_challenge<G: Gadget<'dr, D>>(
        &mut self,
        gadget: G,
    ) -> Result<(Point<'dr, D, C>, Element<'dr, D>)> {
        self.hooks.derive_challenge(self.dr, gadget)
    }
}
