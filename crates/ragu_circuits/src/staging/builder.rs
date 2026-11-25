//! Multi-stage circuit witness generation with staged wire allocation.
//!
//! The staging system separates witness generation into explicit **stage
//! polynomials** ($a(X)$, $b(X)$, ...) that can be committed independently,
//! and an implicit **final trace** ($r'(X)$) that consumes their outputs.
//! Together these form the full trace polynomial:
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
//! 1. **Wire reservation** — Call [`configure_stage`](StageBuilder::configure_stage)
//!    (or [`add_stage`](StageBuilder::add_stage) for stages implementing
//!    [`Default`]) for each stage polynomial. This reserves non-overlapping
//!    wire positions without computing values yet, ensuring all provers agree
//!    on wire layout.
//!
//! 2. **Witness generation** — Call [`finish`](StageBuilder::finish) to get the
//!    driver, then populate each stage via [`StageGuard::enforced`] or
//!    [`StageGuard::unenforced`]. The remaining code computes $r'(X)$.
//!
//! After phase 1, the trace polynomial has a fixed structure:
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
//! See the parent module's [stage output contracts] section for what
//! [`Stage::witness`] does and does not guarantee about the wires inside the
//! gadget it returns, and how [`StageGuard::enforced`]/[`unenforced`] differ in
//! how they treat those wires.
//!
//! [staging chapter]: https://tachyon.z.cash/ragu/implementation/staging
//! [stage output contracts]: super#stage-output-contracts
//! [`unenforced`]: StageGuard::unenforced

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_core::{
    Coeff, Result,
    convert::WireMap,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Gadget},
    maybe::Empty,
};
use ragu_primitives::{
    allocator::{Allocator, Standard},
    consistent::Consistent,
};

use super::{Stage, StageExt};
use crate::polynomials::Rank;

/// Builder object for executing a multi-stage circuit witness.
pub struct StageBuilder<
    'a,
    'dr,
    D: Driver<'dr>,
    R: Rank,
    Current: Stage<D::F, R>,
    Target: Stage<D::F, R>,
> {
    driver: &'a mut D,
    on_finish: fn(&mut D),
    _marker: PhantomData<(&'dr (), R, Current, Target)>,
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Target: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, (), Target>
{
    /// Creates a new [`StageBuilder`] with the given [`Driver`].
    pub(crate) fn new(driver: &'a mut D, on_finish: fn(&mut D)) -> Self {
        StageBuilder {
            driver,
            on_finish,
            _marker: PhantomData,
        }
    }
}

/// Injects pre-allocated stage wires into a gadget, without enforcing
/// constraints.
struct StageWireInjector<'a, 'dr, D: Driver<'dr>> {
    stage_wires: core::slice::Iter<'a, D::Wire>,
    _marker: PhantomData<&'dr ()>,
}

impl<'dr, D: Driver<'dr>> WireMap<D::F> for StageWireInjector<'_, 'dr, D> {
    type Src = Emulator<Wireless<D::MaybeKind, D::F>>;
    type Dst = D;

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
/// witness generation is deferred until one of the consuming methods is called:
///
/// - [`enforced`](Self::enforced) - run the stage witness body and re-emit
///   covered wire contracts
/// - [`unenforced`](Self::unenforced) - run the stage witness body without
///   re-emitting wire contracts
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
    /// Injects pre-allocated stage wires into the gadget produced by
    /// [`Stage::witness`], then enforces the wire contracts covered by
    /// [`Consistent`] in the consuming circuit.
    ///
    /// See the parent module's [stage output contracts](super#stage-output-contracts)
    /// section for what this guarantee does and does not cover.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if the stage witness body cannot
    /// produce its output, a structural error if the output gadget contains more
    /// wires than were reserved, or a local-check error if `Consistent`
    /// enforcement fails under a checking driver.
    pub fn enforced<'source: 'dr>(
        self,
        dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<Bound<'dr, D, S::OutputKind>>
    where
        Bound<'dr, D, S::OutputKind>: Consistent<'dr, D>,
    {
        let output = self.unenforced_inner(witness)?;
        output.enforce_consistent(dr)?;
        Ok(output)
    }

    /// Internal helper that injects stage wires without re-emitting wire
    /// contracts.
    fn unenforced_inner<'source: 'dr>(
        self,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<Bound<'dr, D, S::OutputKind>> {
        let mut emulator: Emulator<Wireless<D::MaybeKind, D::F>> = Emulator::wireless();
        let computed_gadget = self.stage.witness(&mut emulator, witness)?;

        let mut injector = StageWireInjector::<D> {
            stage_wires: self.stage_wires.iter(),
            _marker: PhantomData,
        };

        computed_gadget.map(&mut injector)
    }

    /// Injects pre-allocated stage wires into the gadget produced by
    /// [`Stage::witness`] without re-emitting output wire contracts in this
    /// circuit.
    ///
    /// # Preconditions
    ///
    /// Callers must use this only when the output wire contracts are enforced
    /// elsewhere or are not needed by later circuit code. See the parent
    /// module's [stage output contracts](super#stage-output-contracts) section.
    ///
    /// # Errors
    ///
    /// Returns a witness-generation error if the stage witness body cannot
    /// produce its output, or a structural error if the output gadget contains
    /// more wires than were reserved.
    pub fn unenforced<'source: 'dr>(
        self,
        _dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<Bound<'dr, D, S::OutputKind>> {
        self.unenforced_inner(witness)
    }
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Current: Stage<D::F, R>, Target: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, Current, Target>
{
    /// Adds the next stage to the builder, allocating stage wire positions.
    ///
    /// This method allocates the stage wires at the correct positions but does
    /// not run the stage witness body. Call [`StageGuard::unenforced`] or
    /// [`StageGuard::enforced`] on the returned guard to provide the witness
    /// and obtain the output gadget.
    ///
    /// # Errors
    ///
    /// Returns a capacity error if the stage output uses more wires than its
    /// configured value count, or an initialization error if the stage is
    /// not laid at the gates that follow the current stage.
    pub fn configure_stage<Next: Stage<D::F, R, Parent = Current> + 'dr>(
        self,
        stage: Next,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )> {
        self.place(stage)
    }

    /// Adds a stage that is not a child of the current stage but is laid at
    /// the gates that follow it.
    ///
    /// Two stages can be laid at the same gates when no circuit loads both:
    /// each circuit's trace is summed with the polynomials of the stages it
    /// loads alone. A stage's parent fixes one chain of stages before it.
    /// A stage that overrides [`Stage::skip_gates`] to follow another stage
    /// in some layouts is added after that stage with this method, which
    /// checks the positions where [`configure_stage`](Self::configure_stage)
    /// has them from the types.
    ///
    /// The stages a circuit adds are still one run of gates from gate one
    /// to the end of its last stage, which is what the last stage's final
    /// mask covers.
    ///
    /// # Errors
    ///
    /// Returns an initialization error if the stage is not laid at the
    /// gates that follow the current stage, or a capacity error if the
    /// stage output uses more wires than its configured value count.
    pub fn configure_stage_beside<Next: Stage<D::F, R> + 'dr>(
        self,
        stage: Next,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )> {
        self.place(stage)
    }

    /// Allocates the wires of `stage` after the current stage's.
    fn place<Next: Stage<D::F, R> + 'dr>(
        self,
        stage: Next,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )> {
        // The builder allocates in order, so the stage's wires land at the
        // gates after the current stage's. They must be the gates the
        // stage's polynomial and mask are at.
        if Next::skip_gates() != Current::skip_gates() + Current::num_gates() {
            return Err(ragu_core::Error::Initialization(
                "a stage is added at the gates that follow the stage before it".into(),
            ));
        }

        // Invoke wireless emulator with dummy witness to get gadget structure.
        // The emulator never actually reads witness input.
        let mut emulator = Emulator::counter();
        let mut num_wires = stage.witness(&mut emulator, Empty)?.num_wires()?;

        // Check bounds
        if num_wires > Next::values() {
            return Err(ragu_core::Error::GateBoundExceeded {
                limit: Next::num_gates(),
            });
        }

        // Collect stage wires
        let allocator = &mut Standard::new();
        let mut wires = Vec::with_capacity(num_wires);
        for _ in 0..num_wires {
            wires.push(allocator.alloc(self.driver, || Ok(Coeff::Zero))?);
        }

        // Padding
        while (num_wires / 2) < Next::num_gates() {
            allocator.alloc(self.driver, || Ok(Coeff::Zero))?;
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
                on_finish: self.on_finish,
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

    /// Adds a stage laid after the current one that is not its child, using
    /// [`Self::configure_stage_beside`], assuming the stage implements
    /// [`Default`].
    pub fn add_stage_beside<Next>(
        self,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )>
    where
        Next: Stage<D::F, R> + Default + 'dr,
    {
        self.configure_stage_beside(Next::default())
    }

    /// Reserves the gates of a stage laid after the current one that is not
    /// its child, without producing a gadget: [`Self::skip_stage`] for
    /// [`Self::add_stage_beside`].
    pub fn skip_stage_beside<Next: Stage<D::F, R> + Default + 'dr>(
        self,
    ) -> Result<StageBuilder<'a, 'dr, D, R, Next, Target>> {
        let (_, builder) = self.add_stage_beside::<Next>()?;
        Ok(builder)
    }

    /// Skips the next stage without producing a gadget.
    ///
    /// This allocates the stage wire positions but does not return a guard,
    /// so it's used when you need to reserve the wire positions for a stage
    /// but don't need to run its witness body or produce its output gadget.
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
    ///
    /// If the builder was constructed with an `on_finish` hook, the hook
    /// is called on the driver before it is returned.
    pub fn finish(self) -> &'a mut D {
        (self.on_finish)(self.driver);
        self.driver
    }
}
