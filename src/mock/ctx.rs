//! The driver and framework hooks available to a step.

use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    pasta::{Fp, Pasta},
};
use ragu_primitives::{Element, GadgetExt as _, io::Write};

use super::{hooks::FrameworkHooks, poly_commitment::PolyHandle};

/// Framework-side state threaded through [`Step::witness`](crate::Step::witness).
///
/// The public driver supports ordinary gadget allocation and constraint
/// emission. The remaining methods mock the polynomial and challenge hooks that
/// real ragu exposes alongside it.
pub struct StepCtx<'a, 'dr, D>
where
    D: Driver<'dr, F = Fp>,
{
    /// The underlying driver used by real ragu gadgets.
    pub dr: &'a mut D,
    hooks: &'a mut FrameworkHooks<'dr, D>,
}

impl<'a, 'dr, D> StepCtx<'a, 'dr, D>
where
    D: Driver<'dr, F = Fp>,
{
    pub(crate) fn new(dr: &'a mut D, hooks: &'a mut FrameworkHooks<'dr, D>) -> Self {
        Self { dr, hooks }
    }

    /// Witnesses a polynomial, commits to it with the caller-supplied canonical
    /// generators, and returns the gadget handle naming that commitment.
    ///
    /// The parameters supplied to [`ApplicationBuilder::new`](crate::ApplicationBuilder::new)
    /// must provide at least `R::num_coeffs()` canonical generators. The real
    /// sparse commitment routine assumes this and panics if the sequence is too
    /// short.
    ///
    /// Identity polynomial commitments are valid and are represented by their
    /// compressed encoding in the handle.
    ///
    /// # Errors
    ///
    /// Propagates witness-generation errors from the underlying driver.
    pub fn witness_polynomial<R: Rank>(
        &mut self,
        polynomial: DriverValue<D, sparse::Polynomial<Fp, R>>,
    ) -> Result<PolyHandle<'dr, D, Pasta>> {
        self.hooks.witness_polynomial(self.dr, polynomial)
    }

    /// Evaluates the polynomial named by `handle` at `x`, as a prover-only
    /// value. Use [`enforce_poly_query`](Self::enforce_poly_query) to record
    /// and check the corresponding opening.
    ///
    /// # Errors
    ///
    /// Returns an error if `handle` does not name a polynomial witnessed by
    /// this step.
    pub fn evaluate(
        &mut self,
        handle: &PolyHandle<'dr, D, Pasta>,
        x: DriverValue<D, Fp>,
    ) -> Result<DriverValue<D, Fp>> {
        self.hooks.evaluate(handle, x)
    }

    /// Records a poly-query asserting that the polynomial named by `handle`
    /// evaluates to `y` at `x`.
    ///
    /// The mock checks the opening natively against the committed polynomial;
    /// real ragu enforces it in the parent fuse or final verification.
    ///
    /// # Errors
    ///
    /// Returns an error if `handle` is foreign to this step or if the opening
    /// value is incorrect.
    pub fn enforce_poly_query(
        &mut self,
        handle: &PolyHandle<'dr, D, Pasta>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.hooks.enforce_poly_query(handle, x, y)
    }

    /// Derives a domain-separated Fiat–Shamir challenge from the field elements
    /// emitted by `input`'s ordinary [`Write`] implementation.
    ///
    /// This is a mock extension: the ea0bf839 reference's `StepCtx` has no
    /// challenge hook. Migration must use the reference's eventual challenge API.
    ///
    /// This accepts any writable gadget, including field elements, points,
    /// polynomial commitment handles, and compositions of those gadgets.
    ///
    /// Callers must pin the complete input sequence. Unlike real ragu's
    /// fixed-width recursive transcript, the mock absorbs only the supplied
    /// elements; exact outputs agree only when the complete absorbed sequences
    /// (including any reference padding) and parameters are identical. Local
    /// sponge gate cost is not a guarantee about real recursive-step cost.
    pub fn derive_challenge<G>(&mut self, input: &G) -> Result<Element<'dr, D>>
    where
        G: Gadget<'dr, D>,
        G::Kind: Write<Fp>,
    {
        let mut inputs = Vec::new();
        input.write(self.dr, &mut inputs)?;
        self.hooks.derive_challenge(self.dr, &inputs)
    }
}
