//! The context object threaded through [`Step::witness`](super::Step::witness).

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};

use crate::{framework_hooks::FrameworkHooks, poly_commitment::PolyHandle};

/// Framework-side state threaded through
/// [`Step::witness`](super::Step::witness): the [`Driver`] and the hooks
/// bundled together, so a sub-component called from a step body takes a single
/// `&mut StepCtx`.
pub struct StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    /// The underlying driver, for allocation and constraint emission.
    pub dr: &'a mut D,
    hooks: &'a mut FrameworkHooks<'dr, D, C>,
}

impl<'a, 'dr, D, C> StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    pub(crate) fn new(dr: &'a mut D, hooks: &'a mut FrameworkHooks<'dr, D, C>) -> Self {
        Self { dr, hooks }
    }

    /// Witnesses one polynomial and returns its [`PolyHandle`] — the instance
    /// wires the step can open, absorb, or carry in a header.
    ///
    /// The framework commits it; the commitment is a host-curve point the
    /// native circuit cannot hold, so a step never handles one.
    ///
    /// The polynomial's own rank may be smaller than the application's: the
    /// coefficients are re-wrapped at the application's rank, and the commitment
    /// survives because both place coefficient $i$ against generator $i$. A
    /// larger rank panics during proving.
    ///
    /// No commitment is refused for its value; a step that witnesses more
    /// polynomials than its layout allows is refused when the instance is
    /// assembled, not here.
    pub fn witness_polynomial<R: Rank>(
        &mut self,
        polynomial: DriverValue<D, sparse::Polynomial<C::CircuitField, R>>,
    ) -> Result<PolyHandle<'dr, D, C>> {
        self.hooks.witness_polynomial(self.dr, polynomial)
    }

    /// Evaluates the polynomial behind `handle` at `x`, as a prover-only
    /// value. It synthesizes nothing and proves nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`](ragu_core::Error::InvalidWitness) if
    /// `handle` is not one this step witnessed.
    pub fn evaluate(
        &mut self,
        handle: &PolyHandle<'dr, D, C>,
        x: DriverValue<D, C::CircuitField>,
    ) -> Result<DriverValue<D, C::CircuitField>> {
        self.hooks.evaluate(handle, x)
    }
}
