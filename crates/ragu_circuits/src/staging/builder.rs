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

    /// Reserves the gates of `Through` and of every stage before it, as
    /// [`skip_stage`](Self::skip_stage) does for each in turn, and returns
    /// the wires of those gates: the $a$ wire then the $d$ wire of each,
    /// from the first gate after the SYSTEM gate.
    ///
    /// This is for a circuit that reads the stages of a chain by gate
    /// rather than as each stage's gadget, as a [page](crate::paging) of a
    /// circuit over that chain does. No stage is loaded, so no stage's
    /// output contract is emitted.
    ///
    /// # Errors
    ///
    /// Propagates any error from allocating the gates.
    pub fn reserve_through<Through: Stage<D::F, R>>(
        self,
    ) -> Result<(Vec<D::Wire>, StageBuilder<'a, 'dr, D, R, Through, Target>)> {
        // Every stage takes whole gates, two wires each, so one allocator
        // over the chain's gates allocates what one per stage does.
        let gates = Through::skip_gates() + Through::num_gates() - 1;
        let allocator = &mut Standard::new();
        let mut wires = Vec::with_capacity(2 * gates);
        for _ in 0..2 * gates {
            wires.push(allocator.alloc(self.driver, || Ok(Coeff::Zero))?);
        }
        Ok((
            wires,
            StageBuilder {
                driver: self.driver,
                on_finish: self.on_finish,
                _marker: PhantomData,
            },
        ))
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
    /// configured value count.
    pub fn configure_stage<Next: Stage<D::F, R, Parent = Current> + 'dr>(
        self,
        stage: Next,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )> {
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

#[cfg(test)]
mod tests {
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Kind},
        maybe::Maybe,
        pasta::Fp,
    };
    use ragu_primitives::{
        Element,
        allocator::Standard,
        vec::{ConstLen, FixedVec},
    };

    use super::StageBuilder;
    use crate::{
        WithAux, floor_planner, into_wiring_object,
        polynomials::TestRank,
        staging::{MultiStage, MultiStageCircuit, Stage},
    };

    type R = TestRank;

    /// Four values: two whole gates.
    #[derive(Default)]
    struct First;

    impl Stage<Fp, R> for First {
        type Parent = ();
        type Witness<'source> = [Fp; 4];
        type OutputKind = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<4>>];

        fn values() -> usize {
            4
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, [Fp; 4]>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|values| values[i]))
            })
        }
    }

    /// Three values after [`First`]: two gates, the second half filled.
    #[derive(Default)]
    struct Second;

    impl Stage<Fp, R> for Second {
        type Parent = First;
        type Witness<'source> = [Fp; 3];
        type OutputKind = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<3>>];

        fn values() -> usize {
            3
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, [Fp; 3]>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|values| values[i]))
            })
        }
    }

    /// The product of a value of each stage, with the stages loaded as
    /// gadgets or their gates reserved and read by wire.
    struct Product {
        reserved: bool,
    }

    impl MultiStageCircuit<Fp, R> for Product {
        type Last = Second;
        type Instance<'source> = Fp;
        type Witness<'source> = ([Fp; 4], [Fp; 3]);
        type Output = Kind![Fp; Element<'_, _>];
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Fp>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, &mut Standard::new(), instance)
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
            witness: DriverValue<D, ([Fp; 4], [Fp; 3])>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
        where
            Self: 'dr,
        {
            let first = witness.as_ref().map(|witness| witness.0);
            let second = witness.as_ref().map(|witness| witness.1);
            let (dr, left, right) = if self.reserved {
                let (wires, builder) = builder.reserve_through::<Second>()?;
                let dr = builder.finish();
                // The second value of the first stage is the $d$ wire of
                // gate 1, and the third of the second the $a$ wire of
                // gate 4.
                (
                    dr,
                    Element::promote(wires[1].clone(), first.map(|values| values[1])),
                    Element::promote(wires[6].clone(), second.map(|values| values[2])),
                )
            } else {
                let (first_stage, builder) = builder.add_stage::<First>()?;
                let (second_stage, builder) = builder.add_stage::<Second>()?;
                let dr = builder.finish();
                let first = first_stage.unenforced(dr, first)?;
                let second = second_stage.unenforced(dr, second)?;
                (dr, first[1].clone(), second[2].clone())
            };
            let product = left.mul(dr, &right)?;
            Ok(WithAux::new(product, D::unit()))
        }
    }

    #[test]
    fn reserving_a_chain_is_loading_each_of_its_stages() -> Result<()> {
        let registered = |reserved: bool| -> Result<_> {
            let object = into_wiring_object::<Fp, _, R>(MultiStage::new(Product { reserved }))?;
            let plan = floor_planner::floor_plan(object.segment_records());
            Ok(object.monomials(&plan))
        };
        assert_eq!(registered(true)?, registered(false)?);
        Ok(())
    }
}
