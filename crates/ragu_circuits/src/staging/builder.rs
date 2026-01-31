//! Multi-stage circuit witness computation with staged wire allocation.
//!
//! The staging system separates witness computation into explicit **stage
//! polynomials** ($a(X)$, $b(X)$, ...) that can be committed independently,
//! and an implicit **final witness** ($r'(X)$) that consumes their outputs.
//! Together these form the full witness polynomial:
//!
//! $$
//! r(X) = r'(X) + a(X) + b(X) + \cdots
//! $$
//!
//!
//! Staged polynomials enable the prover to commit to portions of the witness
//! before computing the full circuit.
//!
//! ## Two-Phase Builder Pattern
//!
//! The [`StageBuilder`] uses a two-phase protocol:
//!
//! 1. **Wire reservation** — Call [`add_stage`](StageBuilder::add_stage) for
//!    each stage polynomial. This reserves non-overlapping wire positions
//!    without computing values yet, ensuring all provers agree on wire layout.
//!
//! 2. **Witness computation** — Call [`finish`](StageBuilder::finish) to get
//!    the driver, then populate each stage via [`StageGuard::enforced`] or
//!    [`StageGuard::unenforced`]. The remaining code computes $r'(X)$.
//!
//! After phase 1, the witness polynomial has a fixed structure:
//!
//! $$
//! r(X) = \underbrace{a(X)}\_{\text{wires 0--99}} + \underbrace{b(X)}\_{\text{wires 100--101}} + \underbrace{r'(X)}\_{\text{wires 102+}}
//! $$
//!
//! ## Example
//!
//! See the `compute_v` module in `ragu_pcd` crate for a real-world multi-stage
//! circuit, or the [staging chapter] in the book.
//!
//! [staging chapter]: https://tachyon.z.cash/ragu/protocol/extensions/staging

use arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue, FromDriver,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Consistent, Gadget, GadgetKind},
    maybe::Empty,
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{Stage, StageExt};
use crate::polynomials::Rank;

/// Builder object for synthesizing a multi-stage circuit witness.
pub struct StageBuilder<
    'a,
    'dr,
    D: Driver<'dr>,
    R: Rank,
    Current: Stage<D::F, R>,
    Target: Stage<D::F, R>,
> {
    driver: &'a mut D,
    _marker: PhantomData<(&'dr (), R, Current, Target)>,
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Target: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, (), Target>
{
    /// Creates a new [`StageBuilder`] with the given [`Driver`].
    pub fn new(driver: &'a mut D) -> Self {
        StageBuilder {
            driver,
            _marker: PhantomData,
        }
    }
}

/// Injects pre-allocated stage wires into a gadget, without enforcing constraints.
struct StageWireInjector<'a, 'dr, D: Driver<'dr>> {
    stage_wires: core::slice::Iter<'a, D::Wire>,
    _marker: PhantomData<&'dr ()>,
}

impl<'dr, D: Driver<'dr>> FromDriver<'_, 'dr, Emulator<Wireless<D::MaybeKind, D::F>>>
    for StageWireInjector<'_, 'dr, D>
{
    type NewDriver = D;

    fn convert_wire(&mut self, _: &()) -> Result<D::Wire> {
        self.stage_wires
            .next()
            .cloned()
            .ok_or_else(|| ragu_core::Error::InvalidWitness("not enough stage wires".into()))
    }
}

/// A guard type returned by [`add_stage`](StageBuilder::add_stage) that holds
/// pre-allocated stage wires.
///
/// The stage wires are allocated at the correct positions, but the actual
/// witness computation is deferred until one of the consuming methods is called:
///
/// - [`enforced`](Self::enforced) - run witness and enforce constraints
/// - [`unenforced`](Self::unenforced) - run witness without constraints
///
/// To skip a stage without producing a gadget, use [`StageBuilder::skip_stage`]
/// instead of [`add_stage`](StageBuilder::add_stage).
#[must_use = "StageGuard must be consumed via `enforced` or `unenforced`"]
pub struct StageGuard<'dr, D: Driver<'dr>, R: Rank, S: Stage<D::F, R>> {
    stage: S,
    stage_wires: Vec<D::Wire>,
    _marker: PhantomData<(&'dr (), R, S)>,
}

impl<'dr, D: Driver<'dr>, R: Rank, S: Stage<D::F, R> + 'dr> StageGuard<'dr, D, R, S> {
    /// Inject stage wires and enforce internal consistency constraints.
    ///
    /// Runs the stage's witness method on a wireless emulator, substitutes
    /// the pre-allocated stage wires, then calls `enforce_consistent()` on
    /// the result to enforce internal constraints (e.g., curve equations
    /// for Points).
    pub fn enforced<'source: 'dr>(
        self,
        dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<<S::OutputKind as GadgetKind<D::F>>::Rebind<'dr, D>>
    where
        <S::OutputKind as GadgetKind<D::F>>::Rebind<'dr, D>: Consistent<'dr, D>,
    {
        let output = self.unenforced_inner(witness)?;
        output.enforce_consistent(dr)?;
        Ok(output)
    }

    /// Internal helper that injects stage wires without enforcing constraints.
    fn unenforced_inner<'source: 'dr>(
        self,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<<S::OutputKind as GadgetKind<D::F>>::Rebind<'dr, D>> {
        let mut emulator: Emulator<Wireless<D::MaybeKind, D::F>> = Emulator::wireless();
        let computed_gadget = self.stage.witness(&mut emulator, witness)?;

        let mut injector = StageWireInjector::<D> {
            stage_wires: self.stage_wires.iter(),
            _marker: PhantomData,
        };

        computed_gadget.map(&mut injector)
    }

    /// Injects stage wires without enforcing constraints.
    ///
    /// Runs the stage's witness method on a wireless emulator (not on the
    /// underlying driver), then substitutes the pre-allocated stage wires
    /// into the resulting gadget.
    pub fn unenforced<'source: 'dr>(
        self,
        _dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<<S::OutputKind as GadgetKind<D::F>>::Rebind<'dr, D>> {
        self.unenforced_inner(witness)
    }
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Current: Stage<D::F, R>, Target: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, Current, Target>
{
    /// Add the next stage to the builder, allocating stage wire positions.
    ///
    /// This method allocates the stage wires at the correct positions but does
    /// not compute the witness. Call [`StageGuard::unenforced`] or
    /// [`StageGuard::enforced`] on the returned guard to provide the witness
    /// and obtain the output gadget.
    pub fn configure_stage<Next: Stage<D::F, R, Parent = Current> + 'dr>(
        self,
        stage: Next,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )> {
        // Invoke wireless emulator with dummy witness to get gadget structure.
        // The emulator never actually reads the witness values.
        let mut emulator = Emulator::counter();
        let mut num_wires = stage.witness(&mut emulator, Empty)?.num_wires();

        // Check bounds
        if num_wires > Next::values() {
            return Err(ragu_core::Error::MultiplicationBoundExceeded(
                Next::num_multiplications(),
            ));
        }

        // Collect stage wires
        let mut wires = Vec::with_capacity(num_wires);
        for _ in 0..num_wires {
            wires.push(self.driver.alloc(|| Ok(Coeff::Zero))?);
        }

        // Padding
        while (num_wires / 2) < Next::num_multiplications() {
            self.driver.alloc(|| Ok(Coeff::Zero))?;
            num_wires += 1;
        }

        Ok((
            StageGuard {
                stage,
                stage_wires: wires,
                _marker: PhantomData,
            },
            StageBuilder {
                driver: self.driver,
                _marker: PhantomData,
            },
        ))
    }

    /// Adds the next stage to the builder using [`Self::configure_stage`],
    /// assuming the stage implements [`Default`].
    pub fn add_stage<Next>(
        self,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )>
    where
        Next: Stage<D::F, R, Parent = Current> + Default + 'dr,
    {
        self.configure_stage(Next::default())
    }

    /// Skips the next stage without producing a gadget.
    ///
    /// This allocates the stage wire positions but does not return a guard,
    /// so it's used when you need to reserve the wire positions for a stage
    /// but don't need to compute its witness or produce its output gadget.
    pub fn skip_stage<Next: Stage<D::F, R, Parent = Current> + Default + 'dr>(
        self,
    ) -> Result<StageBuilder<'a, 'dr, D, R, Next, Target>> {
        let (_, builder) = self.add_stage::<Next>()?;
        Ok(builder)
    }
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Finished: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, Finished, Finished>
{
    /// Obtains the underlying driver after finishing the last stage.
    pub fn finish(self) -> &'a mut D {
        self.driver
    }
}
